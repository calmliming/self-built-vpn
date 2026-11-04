"""Private state lives outside source and the static web root."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT.parent
STATE = Path(os.environ.get('SELF_VPN_PANEL_STATE', PROJECT / '.secrets' / 'panel')).resolve()
RUNTIME = Path(os.environ.get('SELF_VPN_PANEL_RUNTIME', PROJECT / '.runtime' / 'panel')).resolve()
INVENTORY = PROJECT / '.secrets' / 'aws-vps-20261103'
FRONTEND = PROJECT / 'frontend' / 'dist'
COOKIE = 'self_vpn_session'

def prepare_directories():
    for path in [STATE, RUNTIME]:
        path.mkdir(parents=True, mode=0o700, exist_ok=True)
        path.chmod(0o700)
