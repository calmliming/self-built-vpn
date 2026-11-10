from datetime import datetime, timezone
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.parse import unquote

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import team_auth
import traffic_stats as traffic

USER = 'a' * 32
OTHER = 'b' * 32
TOKEN = 'test-only-token-' + 'c' * 34


class TrafficTests(unittest.TestCase):
    def test_idempotent_samples_and_process_restart_preserve_cumulative_totals(self):
        state = {'users': {}, 'sources': {}}
        def sample(state, epoch, upload, download):
            return traffic.accumulate(state, 'xray', epoch, {USER: {'upload': upload, 'download': download}}, 'now', '2026-11')
        state = sample(state, 'first', 1000, 2000)
        self.assertEqual(state['users'][USER]['download'], 0, 'No fabricated historical usage')
        state = sample(state, 'first', 1100, 2500)
        duplicate = sample(state, 'first', 1100, 2500)
        self.assertEqual(state, duplicate)
        state = sample(duplicate, 'restarted', 20, 70)
        self.assertEqual(state['users'][USER]['upload'], 120)
        self.assertEqual(state['users'][USER]['download'], 570)
        self.assertEqual(state['users'][USER]['months']['2026-11']['download'], 570)

    def test_all_xray_protocols_map_to_member_not_another_member(self):
        aliases = {'personal': 'legacy-owner', 'team-' + USER: USER, 'http-user': USER, 'socks-user': USER, 'team-' + OTHER: OTHER}
        records = [{'name': f'user>>>{name}>>>traffic>>>downlink', 'value': str(size)}
                   for name, size in [('personal', 11), ('team-' + USER, 30), ('http-user', 40), ('socks-user', 50), ('team-' + OTHER, 9000), ('unknown', 123)]]
        result = traffic.parse_xray({'stat': records}, aliases)
        self.assertEqual(result[USER], {'upload': 0, 'download': 120})
        self.assertEqual(result[OTHER]['download'], 9000)
        self.assertEqual(result['legacy-owner']['download'], 11)
        self.assertEqual(traffic.parse_hysteria({USER: {'tx': 12, 'rx': 150}})[USER], {'upload': 12, 'download': 150})

    def test_month_rollover_uses_beijing_timezone_and_keeps_lifetime_history(self):
        before = datetime(2026, 11, 30, 15, 59, tzinfo=timezone.utc)
        after = datetime(2026, 11, 30, 16, 0, tzinfo=timezone.utc)
        self.assertEqual(traffic.month_key(before), '2026-11')
        self.assertEqual(traffic.month_key(after), '2026-12')
        policy = {'user_id': USER, 'period': 'month', 'include_legacy': False, 'total_bytes': 1_000_000_000_000}
        snapshots = [{'users': {USER: {'upload': 8, 'download': 100, 'months': {'2026-11': {'upload': 8, 'download': 100}}}, OTHER: {'download': 999}}}]
        self.assertIn('download=100;', traffic.subscription_info(policy, snapshots, before))
        self.assertIn('download=0;', traffic.subscription_info(policy, snapshots, after))
        policy['period'] = 'lifetime'
        self.assertIn('download=100;', traffic.subscription_info(policy, snapshots, after))

    def test_shared_owner_usage_is_included_only_for_assigned_admin(self):
        policy = {'user_id': USER, 'period': 'lifetime', 'total_bytes': None, 'include_legacy': False}
        data = [{'users': {USER: {'upload': 10, 'download': 20}, 'legacy-owner': {'upload': 40, 'download': 60}}}]
        self.assertEqual(traffic.subscription_info(policy, data), 'upload=10; download=20; total=0; expire=0')
        policy['include_legacy'] = True
        self.assertEqual(traffic.subscription_info(policy, data), 'upload=50; download=80; total=0; expire=0')

    def test_invalid_counters_cannot_be_silently_coerced(self):
        for value in [-1, True, 1.5, 'nan', 2**63]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                traffic.byte_count(value)

    def test_public_subscription_has_real_header_and_unchanged_body_and_revokes_old_token(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policies = root / 'subscriptions.json'
            store = root / 'usage.json'
            team = root / 'team'
            legacy = root / 'legacy'
            legacy.mkdir()
            target = team / TOKEN
            target.mkdir(parents=True)
            config = b'{"proxies":[{"name":"test-only"}]}'
            (target / 'config.yaml').write_bytes(config)
            for filename in ('config.yaml', 'fleet.yaml'):
                (legacy / filename).write_bytes(config)
            policy = {'user_id': USER, 'token': TOKEN, 'period': 'lifetime', 'total_bytes': 10**12, 'include_legacy': False}
            metadata = {'members': {USER: policy}, 'server_id': 'us', 'legacy_token': TOKEN,
                        'snapshots': {'us': {'users': {USER: {'download': 999999}}},
                                      'hk': {'users': {USER: {'upload': 7, 'download': 200}}}}}
            policies.write_text(json.dumps(metadata))
            store.write_text(json.dumps({'users': {USER: {'upload': 10, 'download': 100}, OTHER: {'download': 99999}}}))
            with (patch.object(traffic, 'POLICIES', policies), patch.object(traffic, 'STORE', store),
                  patch.object(team_auth, 'TEAM_SUB', team), patch.object(team_auth, 'LEGACY_SUB', legacy)):
                server = ThreadingHTTPServer(('127.0.0.1', 0), team_auth.Handler)
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    connection = HTTPConnection(*server.server_address, timeout=3)
                    path = '/team-sub/' + TOKEN + '/config.yaml'
                    connection.request('GET', path)
                    response = connection.getresponse()
                    self.assertEqual(response.status, 200)
                    self.assertEqual(response.read(), config)
                    self.assertEqual(response.getheader('Subscription-Userinfo'), 'upload=17; download=300; total=1000000000000; expire=0')
                    self.assertIn('filename="self-built-vpn"', response.getheader('Content-Disposition'))
                    metadata['subscription_name'] = '团队专用 VPN'
                    policies.write_text(json.dumps(metadata))
                    connection.request('HEAD', path)
                    response = connection.getresponse()
                    self.assertEqual(response.read(), b'')
                    self.assertEqual(response.getheader('Content-Length'), str(len(config)))
                    encoded = response.getheader('Content-Disposition').split("filename*=UTF-8''")[1]
                    self.assertEqual(unquote(encoded), metadata['subscription_name'])
                    for filename in ('config.yaml', 'fleet.yaml'):
                        connection.request('GET', '/sub/' + TOKEN + '/' + filename)
                        response = connection.getresponse()
                        self.assertEqual(response.status, 200)
                        self.assertEqual(response.read(), config)
                        self.assertTrue(response.getheader('Content-Disposition').endswith(encoded))
                    (target / 'config.yaml').unlink()
                    connection.request('GET', path)
                    self.assertEqual(connection.getresponse().status, 404)
                    connection.close()
                finally:
                    server.shutdown()
                    server.server_close()
                    thread.join()


if __name__ == '__main__':
    unittest.main()
