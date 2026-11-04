import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from settings import ROOT


class HookTests(unittest.TestCase):
    def repository(self, root):
        (root / 'scripts').mkdir()
        (root / 'tests').mkdir()
        (root / '.githooks').mkdir()
        for name in ['settings.py', 'check_public_files.py', 'pre_commit.py']:
            shutil.copyfile(ROOT / 'scripts' / name, root / 'scripts' / name)
        shutil.copyfile(ROOT / '.gitignore', root / '.gitignore')
        shutil.copyfile(ROOT / '.githooks/pre-commit', root / '.githooks/pre-commit')
        (root / '.githooks/pre-commit').chmod(0o755)
        subprocess.run(['git', 'init', '-q', '-b', 'main'], cwd=root, check=True)
        subprocess.run(['git', 'config', '--local', 'core.hooksPath', '.githooks'], cwd=root, check=True)

    def commit(self, root):
        environment = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
        return subprocess.run(['git', '-c', 'user.name=Example', '-c', 'user.email=example@example.invalid', 'commit', '-qm', 'test'], cwd=root, capture_output=True, text=True, env=environment)

    def test_hook_blocks_forced_private_file_before_commit(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.repository(root)
            (root / '.env').write_text('EXAMPLE=private\n')
            subprocess.run(['git', 'add', '.gitignore', '.githooks', 'scripts'], cwd=root, check=True)
            subprocess.run(['git', 'add', '-f', '.env'], cwd=root, check=True)
            result = self.commit(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('.env:', result.stderr)
            self.assertNotEqual(subprocess.run(['git', 'rev-parse', '--verify', 'HEAD'], cwd=root, capture_output=True).returncode, 0)

    def test_hook_tests_staged_source_even_when_worktree_has_a_fix(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.repository(root)
            test = root / 'tests/test_sample.py'
            test.write_text('import unittest\nclass Sample(unittest.TestCase):\n def test_sample(self): self.fail("staged failure")\n')
            subprocess.run(['git', 'add', '.gitignore', '.githooks', 'scripts', 'tests'], cwd=root, check=True)
            test.write_text('import unittest\nclass Sample(unittest.TestCase):\n def test_sample(self): pass\n')
            result = self.commit(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('staged failure', result.stderr)
            self.assertNotEqual(subprocess.run(['git', 'rev-parse', '--verify', 'HEAD'], cwd=root, capture_output=True).returncode, 0)


if __name__ == '__main__':
    unittest.main()
