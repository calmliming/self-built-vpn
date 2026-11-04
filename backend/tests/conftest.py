"""All API tests use an isolated database and never start the live executor."""
import os
from pathlib import Path
import tempfile

_sandbox = tempfile.TemporaryDirectory(prefix='self-vpn-panel-tests-')
os.environ['SELF_VPN_PANEL_STATE'] = str(Path(_sandbox.name) / 'private')
os.environ['SELF_VPN_PANEL_RUNTIME'] = str(Path(_sandbox.name) / 'runtime')
