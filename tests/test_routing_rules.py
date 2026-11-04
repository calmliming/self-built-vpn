from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))

from operations import write
from routing_rules import update_rules, validate_mrs


def compressed(behavior, count=3):
    raw = b'MRS\x01' + bytes([behavior]) + count.to_bytes(8, 'big') + bytes(40)
    try:
        from compression import zstd
    except ImportError:
        if not shutil.which('zstd'):
            raise unittest.SkipTest('Install zstd or use Python with compression.zstd for codec tests')
        return subprocess.check_output(['zstd', '-q', '-c'], input=raw)
    return zstd.compress(raw)


class RoutingRulesTests(unittest.TestCase):
    def test_checks_compression_header_behavior_and_rule_count(self):
        self.assertEqual(validate_mrs(compressed(0), 'domain'), 3)
        self.assertEqual(validate_mrs(compressed(1, 9), 'ipcidr'), 9)
        for value, behavior in [(b'<html>error</html>', 'domain'), (compressed(0), 'ipcidr'), (compressed(0, 0), 'domain'), (compressed(0)[:-4], 'domain')]:
            with self.assertRaises(Exception):
                validate_mrs(value, behavior)

    def test_second_download_failure_preserves_both_old_files(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'cn-domain.mrs').write_bytes(b'old-domain')
            (root / 'cn-ip.mrs').write_bytes(b'old-ip')
            def fetch(url, **kwargs):
                if 'geoip' in url:
                    raise RuntimeError('Injected network failure')
                return compressed(0)
            with patch('routing_rules.write') as publish:
                with self.assertRaises(RuntimeError):
                    update_rules(root, fetch=fetch)
                publish.assert_not_called()
            self.assertEqual((root / 'cn-domain.mrs').read_bytes(), b'old-domain')
            self.assertEqual((root / 'cn-ip.mrs').read_bytes(), b'old-ip')

    def test_bad_second_file_preserves_both_old_files(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'cn-domain.mrs').write_bytes(b'old-domain')
            (root / 'cn-ip.mrs').write_bytes(b'old-ip')
            with patch('routing_rules.write') as publish:
                with self.assertRaises(ValueError):
                    update_rules(root, fetch=lambda url, **kw: b'<html>error</html>' if 'geoip' in url else compressed(0))
                publish.assert_not_called()

    def test_unchanged_rules_do_not_restart_services_or_rewrite_files(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            def publish(path, content, mode, group):
                return write(path, content, mode)
            with patch('routing_rules.write', publish), patch('operations.run', side_effect=AssertionError('No service operation expected')):
                first = update_rules(root, fetch=lambda url, **kw: compressed(1 if 'geoip' in url else 0))
                timestamps = {p.name: p.stat().st_mtime_ns for p in root.iterdir()}
                second = update_rules(root, force=False, fetch=lambda *a, **k: self.fail('Cached valid rules should not be downloaded again'))
            self.assertTrue(first['changed'])
            self.assertFalse(second['changed'])
            self.assertEqual(timestamps, {p.name: p.stat().st_mtime_ns for p in root.iterdir()})


if __name__ == '__main__':
    unittest.main()
