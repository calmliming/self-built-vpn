import base64
from contextlib import nullcontext, redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))

from deploy_server import client_config, client_metadata
from manage import managed_action
from settings import Settings, dump_yaml
from verification import preflight, validate_packet, verify_published, verify_proxy_authentication
from server_agent import export_profile
from test_configuration import SECRET


FAKE_SERVER = '''import json, pathlib, sys
payload = json.loads(sys.stdin.readline())
proof = payload['proof']
journal = pathlib.Path(payload['journal'])
actions = []
def event(kind):
    print('SELF_VPN_EVENT ' + json.dumps({'event':kind, **proof}), flush=True)
def receive():
    line = sys.stdin.readline()
    value = json.loads(line) if line else {'action':'eof'}
    actions.append(value['action'])
    journal.write_text(json.dumps(actions))
    if value['action'] in ['abort', 'eof']:
        event('rolled-back')
        raise SystemExit(1)
    return value['action']
event('ready')
action = receive()
if action != 'prepare':
    event('published')
    receive()
event('done')
'''


def packet(settings):
    client = client_config(SECRET, settings)
    content = dump_yaml(client).encode()
    return {'configuration': client, 'metadata': client_metadata(SECRET, settings, client),
            'yaml': base64.b64encode(content).decode(), 'digest': hashlib.sha256(content).hexdigest()}


class VerificationTests(unittest.TestCase):
    def setUp(self):
        self.settings = Settings(server_ip='203.0.113.20')
        self.packet = packet(self.settings)

    def test_http_and_socks_authentication_rejects_open_or_wrong_password_access(self):
        class Connection:
            def __init__(self, data):
                self.data = io.BytesIO(data)
            def recv(self, count):
                return self.data.read(count)
            def sendall(self, data):
                pass
        for kind, replies in [
            ('http', [b'HTTP/1.1 407 Proxy Authentication Required\r\n'] * 2),
            ('socks5', [b'\x05\xff', b'\x05\x02\x01\x01']),
        ]:
            node = {'type': kind, 'username': 'test-user'}
            with patch('verification._proxy_tls', side_effect=[nullcontext(Connection(data)) for data in replies]):
                self.assertTrue(verify_proxy_authentication(node, 'example')['wrong_password_rejected'])
        for kind, replies in [
            ('http', [b'HTTP/1.1 200 Connection Established\r\n']),
            ('socks5', [b'\x05\x00']),
            ('socks5', [b'\x05\xff', b'\x05\x02\x01\x00']),
        ]:
            with patch('verification._proxy_tls', side_effect=[nullcontext(Connection(data)) for data in replies]):
                with self.assertRaises(RuntimeError):
                    verify_proxy_authentication({'type': kind, 'username': 'test-user'}, 'example')

    def test_tampered_candidate_or_different_host_is_rejected(self):
        self.assertEqual(validate_packet(self.packet, self.settings), self.packet['configuration'])
        with self.assertRaises(ValueError):
            validate_packet(self.packet, self.settings, digest='wrong-digest')
        changed = dict(self.packet, yaml=base64.b64encode(b'changed').decode())
        with self.assertRaises(ValueError):
            validate_packet(changed, self.settings)
        with self.assertRaises(ValueError):
            validate_packet(self.packet, Settings(server_ip='198.51.100.20'))

    def test_published_content_and_tls_must_match(self):
        content = base64.b64decode(self.packet['yaml'])
        with patch('verification.https_request', return_value=({'http': 200}, content)):
            self.assertEqual(verify_published(self.packet, self.settings, 'example')['http'], 200)
        for status, body in [(404, content), (200, b'old-subscription')]:
            with patch('verification.https_request', return_value=({'http': status}, body)):
                with self.assertRaises(RuntimeError):
                    verify_published(self.packet, self.settings, 'example')
        with patch('verification.https_request', side_effect=RuntimeError('TLS failed')):
            with self.assertRaises(RuntimeError):
                verify_published(self.packet, self.settings, 'example')

    def test_missing_physical_interface_fails_before_opening_ssh(self):
        with self.assertRaises(ValueError):
            preflight(self.settings)

    def test_current_export_reads_published_rules_instead_of_regenerating_them(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder) / 'private'
            public = Path(folder) / 'public'
            base.mkdir()
            public.mkdir()
            (base / 'secrets.json').write_text(json.dumps(SECRET))
            (base / 'client.json').write_text(json.dumps(self.packet['metadata']))
            published = self.packet['configuration'].copy()
            published['rules'] = ['MATCH,REJECT']
            raw = json.dumps(published).encode()
            (public / 'config.yaml').write_bytes(raw)
            with patch('server_agent.BASE', base), patch('server_agent.SUB', public):
                exported = export_profile(self.settings)
            self.assertEqual(exported['configuration']['rules'], ['MATCH,REJECT'])
            self.assertEqual(exported['digest'], hashlib.sha256(raw).hexdigest())

    def run_protocol(self, failure=None, action='deploy'):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            server = root / 'server.py'
            server.write_text(FAKE_SERVER)
            journal = root / 'actions.json'
            proof = {'nonce': 'test-nonce', 'digest': self.packet['digest']}
            payload = json.dumps({'proof': proof, 'journal': str(journal)}) + '\n'
            with patch('manage.ROOT', root), patch('manage.remote_command', return_value=[sys.executable, '-u', str(server)]), patch('manage.remote_payload', return_value=payload), patch('manage.read_remote', return_value=(self.packet, 0)), patch('manage.verify_profile', side_effect=RuntimeError('node unreachable') if failure == 'before' else None), patch('manage.verify_published', side_effect=RuntimeError('subscription mismatch') if failure == 'after' else None), redirect_stdout(io.StringIO()):
                if failure:
                    with self.assertRaisesRegex(RuntimeError, 'server rollback completed'):
                        managed_action(self.settings, action, Path('/unused-mihomo'), 'example')
                else:
                    managed_action(self.settings, action, Path('/unused-mihomo'), 'example')
            return json.loads(journal.read_text())

    def test_success_requires_publish_then_commit(self):
        self.assertEqual(self.run_protocol(), ['publish', 'commit'])

    def test_failed_public_node_check_aborts_before_publication(self):
        self.assertEqual(self.run_protocol(failure='before'), ['abort'])

    def test_failed_download_after_publication_requests_rollback(self):
        self.assertEqual(self.run_protocol(failure='after'), ['publish', 'abort'])

    def test_prepare_only_does_not_publish(self):
        self.assertEqual(self.run_protocol(action='add-nodes'), ['prepare'])

    def test_rule_update_requires_external_verification_without_republishing(self):
        self.assertEqual(self.run_protocol(action='update-rules'), ['prepare'])
        self.assertEqual(self.run_protocol(action='update-rules', failure='before'), ['abort'])


if __name__ == '__main__':
    unittest.main()
