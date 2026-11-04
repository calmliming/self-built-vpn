#!/usr/bin/env python3
"""Check secrets and test the staged snapshot, independent of unstaged edits."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from check_public_files import check_repository
from settings import ROOT


def main():
    count, errors = check_repository(ROOT)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print(f'Public file check passed for {count} staged files.', flush=True)
    with tempfile.TemporaryDirectory(prefix='self-vpn-staged-') as folder:
        subprocess.run(['git', 'checkout-index', '--all', '--prefix=' + str(Path(folder)) + os.sep], cwd=ROOT, check=True)
        environment = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
        result = subprocess.run([sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-v'], cwd=folder, env=environment)
    return result.returncode


if __name__ == '__main__':
    raise SystemExit(main())
