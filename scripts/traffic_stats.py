"""Read-only protocol counters, durably accumulated on each VPS.

Counters are payload bytes (client upload + download), not provider billing.
Never reset a core's counters: sampling/SSH retries must be idempotent.
"""
import copy
from datetime import datetime, timezone
import fcntl
import json
from pathlib import Path
import re
import subprocess
import urllib.request
from zoneinfo import ZoneInfo

from operations import BASE, write

DATA = Path('/var/lib/self-vpn/traffic')
STORE = DATA / 'usage.json'
POLICIES = DATA / 'subscriptions.json'
SOURCES = {'xray': ('self-vpn', 24593), 'xray-extra': ('self-vpn-extra', 24594),
           'hysteria2': ('self-vpn-hysteria2', 24592)}


def stamp():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def month_key(value=None):
    value = value or datetime.now(timezone.utc)
    return value.astimezone(ZoneInfo('Asia/Shanghai')).strftime('%Y-%m')


def byte_count(value):
    if isinstance(value, str) and re.fullmatch(r'\d{1,19}', value):
        value = int(value)
    if type(value) is not int or not 0 <= value <= 2**63 - 1:
        raise ValueError('Invalid traffic counter')
    return value


def identities(members, extra):
    result = {'personal': 'legacy-owner', 'personal-trojan': 'legacy-owner'}
    for kind in ['http', 'socks5']:
        if extra.get(kind + '_username'):
            result[extra[kind + '_username']] = 'legacy-owner'
    for member in members:
        result['team-' + member['id']] = member['id']
        for kind in ['http', 'socks5']:
            result[member['credential'][kind + '_username']] = member['id']
    return result


def parse_xray(value, aliases):
    if not isinstance(value, dict) or not isinstance(value.get('stat', []), list):
        raise ValueError('Invalid Xray statistics')
    result = {}
    for item in value.get('stat', []):
        match = re.fullmatch(r'user>>>(.+)>>>traffic>>>(uplink|downlink)', item['name'])
        if not match or match[1] not in aliases:
            continue
        pair = result.setdefault(aliases[match[1]], {'upload': 0, 'download': 0})
        pair['upload' if match[2] == 'uplink' else 'download'] += byte_count(item.get('value', 0))
    return result


def parse_hysteria(value):
    if not isinstance(value, dict):
        raise ValueError('Invalid Hysteria statistics')
    result = {}
    for session_id, pair in value.items():
        user_id = session_id.partition(':')[0]
        if user_id == 'legacy-owner' or re.fullmatch(r'[a-f0-9]{32}', user_id):
            # Hysteria uses the server-to-target perspective: tx = user upload.
            target = result.setdefault(user_id, {'upload': 0, 'download': 0})
            target['upload'] += byte_count(pair['tx'])
            target['download'] += byte_count(pair['rx'])
    return result


def accumulate(state, name, epoch, counters, at, month):
    """A new installation starts at zero; a core restart keeps the totals."""
    result = copy.deepcopy(state)
    previous = result.setdefault('sources', {}).get(name)
    previous_raw = previous.get('raw', {}) if previous and previous['epoch'] == epoch else {}
    totals = result.setdefault('users', {})
    for user_id, pair in counters.items():
        target = totals.setdefault(user_id, {'upload': 0, 'download': 0, 'months': {}})
        monthly = target['months'].setdefault(month, {'upload': 0, 'download': 0})
        for direction in ['upload', 'download']:
            current = byte_count(pair[direction])
            old = previous_raw.get(user_id, {}).get(direction, 0)
            # First read establishes the starting point, excluding old usage.
            delta = 0 if previous is None else current - old if current >= old else current
            target[direction] += delta
            monthly[direction] += delta
    raw = {**previous_raw, **counters}
    result['sources'][name] = {'epoch': epoch, 'raw': raw, 'sampled_at': at, 'error': None}
    return result


def read_source(name, aliases):
    service, port = SOURCES[name]
    before = subprocess.check_output(['systemctl', 'show', service, '--property=InvocationID', '--value'],
                                     text=True, timeout=5).strip()
    if not re.fullmatch('[a-f0-9]{32}', before):
        raise RuntimeError('Core is not running')
    if name == 'hysteria2':
        secret = json.loads((BASE / 'team-auth-state.json').read_text())['stats_secret']
        request = urllib.request.Request(f'http://127.0.0.1:{port}/traffic', headers={'Authorization': secret})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(request, timeout=5) as response:
            counters = parse_hysteria(json.loads(response.read(4_000_000)))
    else:
        value = subprocess.check_output(['/usr/local/bin/xray', 'api', 'statsquery',
                    f'--server=127.0.0.1:{port}', '-pattern', 'user>>>'], text=True, timeout=10)
        counters = parse_xray(json.loads(value), aliases)
    after = subprocess.check_output(['systemctl', 'show', service, '--property=InvocationID', '--value'],
                                    text=True, timeout=5).strip()
    if before != after:
        raise RuntimeError('Core restarted during sampling')
    return before, counters


def collect():
    DATA.mkdir(mode=0o750, parents=True, exist_ok=True)
    with (DATA / '.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        state = json.loads(STORE.read_text()) if STORE.exists() else {'version': 1, 'started_at': stamp(), 'users': {}, 'sources': {}}
        extra = json.loads((BASE / 'extra-secrets.json').read_text())
        members = json.loads((BASE / 'team-members.json').read_text())
        # Keep aliases until old process counters disappear after credential rotation.
        aliases = {**state.get('aliases', {}), **identities(members, extra)}
        at = stamp()
        errors = {}
        for name in SOURCES:
            try:
                epoch, counters = read_source(name, aliases)
                state = accumulate(state, name, epoch, counters, at, month_key())
            except Exception:
                errors[name] = '流量接口暂时不可用'
        state.update(aliases=aliases, checked_at=at, errors=errors)
        write(STORE, json.dumps(state, ensure_ascii=False), 0o640, 'self-vpn')
    return public_snapshot(state)


def public_snapshot(state):
    result = {key: state.get(key, {}) for key in ['version', 'started_at', 'checked_at', 'users', 'errors']} | {
        'sampled_at': {name: item['sampled_at'] for name, item in state.get('sources', {}).items()}}
    from quota_control import public_state
    result['quota'] = public_state()
    return result


def instrument(configuration, port):
    result = copy.deepcopy(configuration)
    result['api'] = {'tag': 'traffic-api', 'listen': f'127.0.0.1:{port}', 'services': ['StatsService']}
    result['stats'] = {}
    result.setdefault('policy', {}).setdefault('levels', {}).setdefault('0', {}).update(
        statsUserUplink=True, statsUserDownlink=True)
    return result


def subscription_info(policy, snapshots, at=None):
    month = month_key(at)
    upload = download = 0
    for snapshot in snapshots:
        for identity in [policy['user_id'], *(['legacy-owner'] if policy.get('include_legacy') else [])]:
            pair = snapshot.get('users', {}).get(identity, {})
            if policy.get('period') == 'month':
                pair = pair.get('months', {}).get(month, {})
            upload += byte_count(pair.get('upload', 0))
            download += byte_count(pair.get('download', 0))
    total = byte_count(policy.get('total_bytes') or 0)
    return f'upload={upload}; download={download}; total={total}; expire=0'


if __name__ == '__main__':
    try:
        sample = collect()
    except Exception:
        sample = None
    from quota_control import enforce
    enforce(sample)
