import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))

import operations
from operations import Transaction, apply_service, write
import server_agent
from settings import Settings


class Systemd:
    def __init__(self):
        self.active = {'self-vpn': True, 'nginx': True}
        self.enabled = {'self-vpn': True, 'nginx': True}
        self.calls = []
        self.fail_next_restart = False
        self.fail_next_timer_start = False

    def state(self, service, verb='is-active'):
        mapping = self.enabled if verb == 'is-enabled' else self.active
        return ('enabled' if mapping.get(service) else 'disabled') if verb == 'is-enabled' else ('active' if mapping.get(service) else 'inactive')

    def run(self, command, **kwargs):
        self.calls.append(command)
        if command[0] != 'systemctl' or len(command) < 3:
            return ''
        verb, service = command[1:3]
        if verb == 'start' and service == operations.RENEW_TIMER and self.fail_next_timer_start:
            self.fail_next_timer_start = False
            raise RuntimeError('Injected timer resume failure')
        if verb == 'restart' and self.fail_next_restart:
            self.fail_next_restart = False
            raise RuntimeError('Injected restart failure')
        if verb in ['restart', 'start', 'stop']:
            self.active[service] = verb != 'stop'
        if verb in ['enable', 'disable']:
            self.enabled[service] = verb == 'enable'
        return ''


class DeploymentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.base = self.root / 'state'
        self.active = self.root / 'active.json'
        self.subscription = self.root / 'config.yaml'
        write(self.active, 'old-config', 0o640)
        write(self.subscription, 'old-subscription', 0o640)
        self.systemd = Systemd()
        self.patches = [patch('operations.state', self.systemd.state), patch('operations.run', self.systemd.run)]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)

    def transaction(self, **kwargs):
        return Transaction(paths=[self.active, self.subscription], base=self.base, services=['self-vpn', 'nginx'], pause_renewal=False, **kwargs)

    def assert_original(self):
        self.assertEqual(self.active.read_text(), 'old-config')
        self.assertEqual(self.subscription.read_text(), 'old-subscription')
        self.assertEqual(self.active.stat().st_mode & 0o777, 0o640)

    def test_failure_restores_files_modes_and_service_state(self):
        with self.assertRaises(RuntimeError):
            with self.transaction() as transaction:
                write(self.active, 'new-config', 0o600)
                write(self.subscription, 'new-subscription', 0o600)
                transaction.touch_service('self-vpn')
                self.systemd.active['self-vpn'] = False
                raise RuntimeError('Injected failure')
        self.assert_original()
        self.assertTrue(self.systemd.active['self-vpn'])
        self.assertEqual(json.loads((transaction.folder / 'manifest.json').read_text())['status'], 'rolled-back')

    def test_new_files_are_removed_and_symlinks_are_restored(self):
        created = self.root / 'new.service'
        link = self.root / 'enabled'
        link.symlink_to('old-target')
        with self.assertRaises(RuntimeError):
            with Transaction(paths=[created, link], base=self.base, services=[], pause_renewal=False):
                write(created, 'new-service')
                link.unlink()
                link.symlink_to('new-target')
                raise RuntimeError('Injected failure')
        self.assertFalse(created.exists())
        self.assertEqual(str(link.readlink()), 'old-target')

    def test_certificate_tree_and_private_key_modes_are_restored(self):
        archive = self.root / 'archive'
        live = self.root / 'live'
        archive.mkdir()
        live.mkdir()
        write(archive / 'privkey.pem', 'old-private-key', 0o600)
        (live / 'privkey.pem').symlink_to('../archive/privkey.pem')
        with self.assertRaises(RuntimeError):
            with Transaction(paths=[archive, live], base=self.base, services=[], pause_renewal=False):
                write(archive / 'privkey.pem', 'new-private-key', 0o644)
                write(archive / 'new.pem', 'new-certificate')
                raise RuntimeError('Injected certificate failure')
        self.assertEqual((live / 'privkey.pem').read_text(), 'old-private-key')
        self.assertEqual((archive / 'privkey.pem').stat().st_mode & 0o777, 0o600)
        self.assertFalse((archive / 'new.pem').exists())

    def test_renewal_timer_resumes_after_failed_deployment(self):
        self.systemd.active[operations.RENEW_TIMER] = True
        with self.assertRaises(RuntimeError):
            with Transaction(paths=[self.active], base=self.base, services=['self-vpn'], pause_renewal=True):
                self.assertFalse(self.systemd.active[operations.RENEW_TIMER])
                raise RuntimeError('Injected failure')
        self.assertTrue(self.systemd.active[operations.RENEW_TIMER])

    def test_timer_resume_failure_prevents_commit_and_restores_files(self):
        self.systemd.active[operations.RENEW_TIMER] = True
        self.systemd.fail_next_timer_start = True
        with self.assertRaises(RuntimeError):
            with Transaction(paths=[self.active], base=self.base, services=['self-vpn'], pause_renewal=True) as transaction:
                write(self.active, 'new-config')
                transaction.commit()
        self.assertFalse(transaction.committed)
        self.assert_original()
        self.assertTrue(self.systemd.active[operations.RENEW_TIMER])

    def test_incomplete_rollback_is_reported_and_can_be_recovered(self):
        def failed_restart(command, **kwargs):
            if command[1:3] == ['restart', 'self-vpn']:
                raise RuntimeError('Injected recovery failure')
            return self.systemd.run(command, **kwargs)
        with patch('operations.run', failed_restart):
            with self.assertRaisesRegex(RuntimeError, 'Rollback incomplete'):
                with self.transaction() as transaction:
                    transaction.touch_service('self-vpn')
                    write(self.active, 'new-config')
                    raise RuntimeError('Injected failure')
        self.assert_original()
        manifest = transaction.folder / 'manifest.json'
        self.assertEqual(json.loads(manifest.read_text())['status'], 'rollback-incomplete')
        with self.transaction() as recovered:
            recovered.commit()
        self.assertEqual(json.loads(manifest.read_text())['status'], 'rolled-back')

    def test_committed_changes_survive_context_exit(self):
        with self.transaction() as transaction:
            write(self.active, 'new-config')
            transaction.commit()
        self.assertEqual(self.active.read_text(), 'new-config')
        self.assertEqual(json.loads((transaction.folder / 'manifest.json').read_text())['status'], 'committed')

    def test_concurrent_deployment_is_rejected(self):
        with self.transaction() as first:
            with self.assertRaises(BlockingIOError):
                with self.transaction():
                    self.fail('Second deployment acquired the lock')
            first.commit()

    def test_interrupted_journal_is_recovered_before_next_change(self):
        interrupted = self.transaction()
        interrupted.__enter__()
        interrupted.touch_service('self-vpn')
        write(self.active, 'interrupted-config')
        interrupted._release()  # Simulate a process disappearing without __exit__.
        with self.transaction() as recovered:
            self.assert_original()
            recovered.commit()
        self.assertEqual(json.loads((interrupted.folder / 'manifest.json').read_text())['status'], 'rolled-back')

    def test_unchanged_active_service_is_not_restarted(self):
        with self.transaction() as transaction:
            self.assertFalse(write(self.active, 'old-config', 0o640))
            apply_service('self-vpn', False, transaction)
            transaction.commit()
        self.assertEqual(self.systemd.calls, [])

    def test_restart_failure_rolls_back_and_restarts_previous_config(self):
        self.systemd.fail_next_restart = True
        with self.assertRaises(RuntimeError):
            with self.transaction() as transaction:
                write(self.active, 'new-config')
                apply_service('self-vpn', True, transaction)
        self.assert_original()
        self.assertEqual(sum(c[1:3] == ['restart', 'self-vpn'] for c in self.systemd.calls), 2)

    def test_newly_started_service_is_stopped_on_rollback(self):
        self.systemd.active['self-vpn'] = False
        self.systemd.enabled['self-vpn'] = False
        with self.assertRaises(RuntimeError):
            with self.transaction() as transaction:
                apply_service('self-vpn', True, transaction)
                raise RuntimeError('Injected verification failure')
        self.assertFalse(self.systemd.active['self-vpn'])
        self.assertFalse(self.systemd.enabled['self-vpn'])

    def test_generated_credentials_survive_failed_first_installation(self):
        credential = self.base / 'secrets.json'
        with self.assertRaises(RuntimeError):
            with self.transaction():
                write(credential, 'new-private-credential')
                raise RuntimeError('Injected download failure')
        self.assertEqual(credential.read_text(), 'new-private-credential')
        self.assertEqual(credential.stat().st_mode & 0o777, 0o600)

    def test_external_failure_before_and_after_publication_restores_old_subscription(self):
        settings = Settings(server_ip='203.0.113.20')
        for failed_phase in ['publish', 'commit']:
            events = []

            def prepare(config, transaction):
                write(self.active, 'new-config')
                transaction.touch_service('self-vpn')

            def publish(config, digest):
                write(self.subscription, 'new-subscription')

            def receive(expected, nonce, digest):
                if expected == failed_phase:
                    raise RuntimeError('Injected external verification failure')

            with self.subTest(phase=failed_phase), patch('server_agent.Transaction', self.transaction), patch('deploy_server.prepare', prepare), patch('add_protocol_nodes.read_candidate', return_value=({}, {}, 'candidate-digest')), patch('add_protocol_nodes.publish', publish), patch('server_agent.event', side_effect=lambda kind, **values: events.append(kind)):
                with self.assertRaises(RuntimeError):
                    server_agent.run_action('deploy', settings, receive=receive)
            self.assert_original()
            self.assertIn('rolled-back', events)
            self.assertNotIn('done', events)

    def test_certificate_or_download_failure_does_not_publish_or_restart(self):
        for failure in ['certificate failure', 'routing download failure']:
            def fail(config, transaction):
                write(self.active, 'new-config')
                raise RuntimeError(failure)
            with self.subTest(failure=failure), patch('server_agent.Transaction', self.transaction), patch('deploy_server.prepare', fail), patch('add_protocol_nodes.publish') as publish, patch('server_agent.event'):
                with self.assertRaises(RuntimeError):
                    server_agent.run_action('deploy', Settings(server_ip='203.0.113.20'))
                publish.assert_not_called()
            self.assert_original()
        self.assertEqual(self.systemd.calls, [])

    def test_missing_or_wrong_external_proof_never_commits(self):
        with patch('server_agent.select.select', return_value=([], [], [])):
            with self.assertRaises(RuntimeError):
                server_agent.wait_message('commit', 'nonce', 'digest', timeout=0)
        for text in ['', json.dumps({'action': 'commit', 'nonce': 'wrong', 'digest': 'digest'}) + '\n']:
            with patch('server_agent.select.select', return_value=([True], [], [])), patch('sys.stdin', io.StringIO(text)):
                with self.assertRaises(RuntimeError):
                    server_agent.wait_message('commit', 'nonce', 'digest')


if __name__ == '__main__':
    unittest.main()
