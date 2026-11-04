from pathlib import Path
import json
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from check_public_files import check_repository, known_private_values, scan_text
from settings import ROOT


class PublicFilesTests(unittest.TestCase):
    def test_allows_example_addresses_and_public_resolvers(self):
        self.assertEqual(scan_text("203.0.113.20 198.51.100.20 127.0.0.1 10.0.0.0/8 224.0.0.0/4 1.1.1.1 8.8.8.8"), [])

    def test_detects_private_material_without_echoing_the_value(self):
        material = [
            "-----BEGIN " + "PRIVATE KEY-----",
            "-----BEGIN " + "ENCRYPTED PRIVATE KEY-----",
            "AKIA" + "A" * 16,
            "sg-" + "a" * 17,
            "123456" + "789012",
            "/sub/" + "x" * 32 + "/config.yaml",
            "/" + "Users/example/project/",
            ".".join(["8", "8", "4", "5"]),
        ]
        for text in material:
            self.assertTrue(scan_text(text))
        value = "private-test-value"
        reasons = scan_text(value, [value])
        self.assertTrue(reasons)
        self.assertNotIn(value, " ".join(reasons))
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / '.secrets').mkdir()
            (root / '.secrets/client.json').write_text(json.dumps({'nodes': [{'obfs-password': value}]}))
            self.assertTrue(scan_text(value, known_private_values(root)))

    def test_checks_actual_index_and_rejects_forced_private_file(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            shutil.copyfile(ROOT / ".gitignore", root / ".gitignore")
            subprocess.run(["git", "init", "-q", "-b", "main"], cwd=root, check=True)
            readme = root / "README.md"
            readme.write_text("Example project using 203.0.113.20\n")
            subprocess.run(["git", "add", ".gitignore", "README.md"], cwd=root, check=True)
            count, errors = check_repository(root)
            self.assertEqual(count, 2)
            self.assertEqual(errors, [])
            readme.write_text("Public address: " + ".".join(["8", "8", "4", "5"]))
            self.assertEqual(check_repository(root)[1], [], "Unstaged edits are not part of the commit")
            subprocess.run(["git", "add", "README.md"], cwd=root, check=True)
            self.assertTrue(check_repository(root)[1])
            (root / ".env").write_text("EXAMPLE=ignored\n")
            subprocess.run(["git", "add", "-f", ".env"], cwd=root, check=True)
            self.assertTrue(any(".env:" in error for error in check_repository(root)[1]))
            (root / "unexpected.pem").write_text("Private export\n")
            subprocess.run(["git", "add", "-f", "unexpected.pem"], cwd=root, check=True)
            self.assertTrue(any("unexpected.pem:" in error for error in check_repository(root)[1]))


if __name__ == "__main__":
    unittest.main()
