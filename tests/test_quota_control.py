from datetime import datetime, timedelta, timezone
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
import threading
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import quota_control as quota
from team_auth import authenticate
import team_auth

USER, OTHER = 'a' * 32, 'b' * 32
NOW = datetime(2026, 11, 30, 15, 59, 59, tzinfo=timezone.utc)

def policy(user=USER, **changes):
    return dict(user_id=user, token='test-only-token', total_bytes=500, period='month',
                include_legacy=False, enforce=True, enabled=True, regions=['us'], **changes)

def sample(at=NOW, counts=None):
    return {'version': 1, 'checked_at': at.isoformat(), 'started_at': at.isoformat(), 'errors': {},
            'sampled_at': {key: at.isoformat() for key in quota.SOURCES},
            'users': counts or {USER: {'upload': 10, 'download': 20, 'months': {'2026-11': {'upload': 10, 'download': 20}}}}}

def usage(value, month='2026-11'):
    return {'upload': 0, 'download': value, 'months': {month: {'upload': 0, 'download': value}}}


class QuotaTests(unittest.TestCase):
    def test_three_regions_protocols_devices_and_shared_owner_use_one_pool(self):
        first = policy()
        first.update(regions=['hk','sg','us'], include_legacy=True)
        peers = {code: sample(counts={USER: usage(80), 'legacy-owner': usage(70), OTHER: usage(9000)}) for code in quota.REGIONS}
        allowed = quota.decisions({USER: first}, peers, NOW)['decisions'][USER]
        self.assertFalse(allowed['blocked'])
        self.assertEqual(allowed['used_bytes'], 450)
        peers['hk']['users'][USER] = usage(130)
        denied = quota.decisions({USER: first, OTHER: policy(OTHER)}, peers, NOW)['decisions']
        self.assertEqual(denied[USER]['used_bytes'], 500)
        self.assertEqual(denied[USER]['reason'], 'quota-exhausted')

    def test_month_rollover_restores_quota_but_never_reenables_disabled_members(self):
        policies = {USER: policy(), OTHER: policy(OTHER)}
        policies[OTHER]['enabled'] = False
        peers = {'us': sample(counts={USER: usage(500), OTHER: usage(700)})}
        self.assertTrue(quota.decisions(policies, peers, NOW)['decisions'][USER]['blocked'])
        next_month = NOW + timedelta(seconds=1)
        peers['us']['checked_at'] = next_month.isoformat()
        restored = quota.decisions(policies, peers, next_month)
        self.assertEqual(restored['month'], '2026-12')
        self.assertEqual(restored['decisions'][USER]['used_bytes'], 0)
        self.assertFalse(restored['decisions'][USER]['blocked'])
        self.assertEqual(restored['decisions'][OTHER]['reason'], 'member-disabled')
        policies[USER]['period'] = 'lifetime'
        self.assertTrue(quota.decisions(policies, peers, next_month)['decisions'][USER]['blocked'])

    def test_missing_stale_and_expired_decisions_fail_closed(self):
        first = policy()
        value = quota.decisions({USER: first}, {'us': sample()}, NOW)
        args = ({'enabled': True}, value, {USER: first})
        self.assertEqual(quota.reason_for(USER, *args, NOW), '')
        self.assertEqual(quota.reason_for(USER, *args, NOW + timedelta(seconds=31)), 'quota-service-unavailable')
        self.assertEqual(quota.reason_for(OTHER, *args, NOW), 'quota-policy-pending')
        stale = quota.decisions({USER: first}, {'us': sample()}, NOW + timedelta(seconds=61))
        self.assertEqual(stale['decisions'][USER]['reason'], 'quota-service-unavailable')
        self.assertEqual(quota.reason_for(USER, {'enabled': False}, {}, {}, NOW), '')

    def test_link_rotation_preserves_pool_and_policy_changes_require_fresh_decision(self):
        first = policy()
        value = quota.decisions({USER: first}, {'us': sample()}, NOW)
        original = quota.policy_hash(first)
        first['token'] = 'another-test-only-token'
        self.assertEqual(quota.policy_hash(first), original)
        self.assertEqual(quota.reason_for(USER, {'enabled':True}, value, {USER:first}, NOW), '')
        first['total_bytes'] = 1000
        self.assertEqual(quota.reason_for(USER, {'enabled':True}, value, {USER:first}, NOW), 'quota-service-unavailable')

    def test_resumed_hysteria_session_has_fresh_id_but_same_member_pool(self):
        first=policy()
        state={'generations':{USER:0}}
        files={quota.CONTROL:{'enabled':True},quota.STATE:state,quota.POLICIES:{'members':{USER:first}}}
        with patch.object(quota,'load',side_effect=lambda path,*args:files[path]), patch.object(quota,'clock',return_value=NOW):
            old=quota.session_identity(USER)
            self.assertEqual(old.partition(':')[0],USER)
            first['token']='rotated-link'
            self.assertEqual(quota.session_identity(USER),old)
            state['generations'][USER]=1
            restored=quota.session_identity(USER)
            self.assertNotEqual(restored,old)
            # Hysteria's pending kick for the old ID cannot hit the new one.
            self.assertNotIn(restored,{old})
            from traffic_stats import parse_hysteria
            self.assertEqual(parse_hysteria({old:{'tx':10,'rx':200},restored:{'tx':20,'rx':300}}),{USER:{'upload':30,'download':500}})

    def test_only_online_blocked_sessions_are_kicked(self):
        import io
        from unittest.mock import MagicMock
        opener=MagicMock()
        online={USER+':old':1,OTHER+':allowed':1}
        # A real context-manager-shaped empty successful POST response.
        response=MagicMock();response.__enter__.return_value.status=200
        opener.open.side_effect=[io.BytesIO(json.dumps(online).encode()),response,io.BytesIO(b'{}')]
        with patch.object(quota,'load',return_value={'stats_secret':'test-only'}),patch.object(quota.urllib.request,'build_opener',return_value=opener):
            quota.kick_online({USER,'c'*32})
        request=opener.open.call_args_list[1].args[0]
        self.assertEqual(json.loads(request.data),[USER+':old'])
        self.assertEqual(opener.open.call_count,3)

    def test_blocking_keeps_authentication_and_unblocking_restores_exact_configuration(self):
        original = {'inbounds': [{'protocol':'http', 'settings': {'accounts': [{'user':'http-a','pass':'test-only-password'}]}}],
                    'outbounds': [{'tag':'internet','protocol':'freedom'},{'tag':'blocked','protocol':'blackhole'}],
                    'routing': {'rules':[{'ip':['127.0.0.0/8'],'outboundTag':'blocked'}]}}
        aliases = {'team-'+USER:USER,'http-a':USER,'socks-a':USER,'personal':'legacy-owner','team-'+OTHER:OTHER}
        guarded = quota.guarded(original, {USER}, aliases)
        self.assertEqual(guarded['inbounds'], original['inbounds'])
        self.assertEqual(set(guarded['routing']['rules'][0]['user']), {'team-'+USER,'http-a','socks-a'})
        self.assertEqual(quota.guarded(guarded, set(), aliases), original)
        # Reopening a quota guard never creates an authentication entry.
        self.assertEqual(authenticate('removed-member-password', {}), '')

    def test_stale_or_restored_counter_files_cannot_reduce_authoritative_usage(self):
        old = sample(counts={USER:usage(500), OTHER:usage(20)})
        restored = sample(counts={USER:usage(50)})
        merged = quota.merge_snapshot(old, restored)
        self.assertEqual(merged['users'][USER]['download'], 500)
        self.assertEqual(merged['users'][OTHER]['download'], 20)

    def test_coordinator_requires_peer_secret_and_rejects_invalid_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root/'config.json'; policies = root/'policies.json'
            config.write_text(json.dumps({'enabled':True,'keys':{'us':hashlib.sha256(b'test-only-secret').hexdigest()}}))
            policies.write_text(json.dumps({'members':{USER:policy()}}))
            payload = {'server_id':'us','sample':sample()}
            with patch.object(quota,'COORDINATOR',config), patch.object(quota,'COORD_DATA',root), patch.object(quota,'POLICIES',policies):
                with self.assertRaises(PermissionError):
                    quota.coordinate(payload,'wrong',NOW)
                self.assertFalse((root/'usage.json').exists())
                self.assertFalse(quota.coordinate(payload,'test-only-secret',NOW)['decisions'][USER]['blocked'])
                payload['sample']['users'][USER]['download'] = -1
                with self.assertRaises(ValueError):
                    quota.coordinate(payload,'test-only-secret',NOW)
                payload['sample'] = sample(NOW - timedelta(seconds=61))
                with self.assertRaises(ValueError):
                    quota.coordinate(payload,'test-only-secret',NOW)

    def test_public_report_endpoint_requires_node_key_before_accepting_a_body(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);config=root/'config.json';policies=root/'policies.json'
            config.write_text(json.dumps({'enabled':True,'keys':{'us':hashlib.sha256(b'test-only-secret').hexdigest()}}))
            policies.write_text(json.dumps({'members':{USER:policy()}}))
            with patch.object(quota,'COORDINATOR',config), patch.object(quota,'COORD_DATA',root), patch.object(quota,'POLICIES',policies), patch.object(quota,'clock',return_value=NOW):
                server=ThreadingHTTPServer(('127.0.0.1',0),team_auth.Handler)
                thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
                try:
                    connection=HTTPConnection(*server.server_address,timeout=3)
                    connection.request('POST','/quota/report',body='invalid-json',headers={'Authorization':'member-subscription-token'})
                    response=connection.getresponse();self.assertEqual(response.status,403);response.read()
                    self.assertFalse((root/'usage.json').exists())
                    connection.request('POST','/quota/report',body=json.dumps({'server_id':'us','sample':sample()}),headers={'Authorization':'test-only-secret'})
                    response=connection.getresponse();self.assertEqual(response.status,200)
                    self.assertFalse(json.loads(response.read())['decisions'][USER]['blocked'])
                    connection.close()
                finally:
                    server.shutdown();server.server_close();thread.join()

    def test_idle_checks_do_not_restart_other_members_tcp_connections(self):
        from contextlib import nullcontext
        from types import SimpleNamespace
        original = {'inbounds': [], 'outbounds':[{'tag':'blocked','protocol':'blackhole'}], 'routing':{'rules':[]}}
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for name in ['xray.json','extra-xray.json']:
                (root/name).write_text(json.dumps(original))
            (root/'team-auth-state.json').write_text(json.dumps({'stats_secret':'test-only'}))
            def write(path, content, *args):path.write_text(content);return True
            transaction = SimpleNamespace(commit=lambda:None)
            response = SimpleNamespace(status=200,__enter__=lambda s:s,__exit__=lambda *a:None)
            from unittest.mock import MagicMock
            opened=MagicMock();opened.__enter__.return_value.status=200
            with patch.object(quota,'BASE',root), patch.object(quota,'Transaction',return_value=nullcontext(transaction)), patch.object(quota,'validate_xray'), patch.object(quota,'write',side_effect=write), patch.object(quota,'apply_service') as restart, patch.object(quota,'kick_online'), patch.object(quota.urllib.request,'build_opener') as opener:
                opener.return_value.open.return_value=opened
                for _ in range(2):quota.apply_blocks({USER:'quota-exhausted'}, {'team-'+USER:USER})
                self.assertEqual(restart.call_count,2)
                for _ in range(2):quota.apply_blocks({USER:''}, {'team-'+USER:USER})
                self.assertEqual(restart.call_count,4)

if __name__ == '__main__':unittest.main()
