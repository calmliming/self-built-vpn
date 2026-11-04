"""Shared member quotas: an authenticated US coordinator and VPS-side guards."""
import copy
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import tempfile
import time
import urllib.request

from operations import BASE, Transaction, apply_service, validate_xray, write
from traffic_stats import DATA, POLICIES, SOURCES, byte_count, identities, month_key, stamp

CONTROL = BASE / 'quota-control.json'
CLIENT = BASE / 'quota-client.json'
COORDINATOR = BASE / 'quota-coordinator.json'
COORD_DATA = Path('/var/lib/self-vpn/quota-coordinator')
STATE = DATA / 'quota-state.json'
RULE = 'self-vpn-quota'
REGIONS = ['hk', 'sg', 'us']
LEASE_SECONDS = 30
FRESH_SECONDS = 60


def clock():
    return datetime.now(timezone.utc)


def load(path, default=None):
    return json.loads(path.read_text()) if path.exists() else ({} if default is None else default)


def atomic_json(path, value):
    """Also works inside the unprivileged authentication service."""
    fd, name = tempfile.mkstemp(prefix='.quota-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as file:
            os.fchmod(file.fileno(), 0o600)
            json.dump(value, file)
            file.flush()
            os.fsync(file.fileno())
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def policy_hash(policy):
    # Link/credential rotation must not create a new allowance.
    fields = ['user_id', 'total_bytes', 'period', 'include_legacy', 'enforce', 'enabled', 'regions']
    return hashlib.sha256(json.dumps({k: policy.get(k) for k in fields}, sort_keys=True).encode()).hexdigest()


def validate_snapshot(sample, at):
    if not isinstance(sample, dict) or sample.get('version') != 1 or not isinstance(sample.get('users'), dict):
        raise ValueError('Invalid usage report')
    checked = datetime.fromisoformat(sample['checked_at'])
    if checked.tzinfo is None or not -10 <= (at - checked).total_seconds() <= FRESH_SECONDS:
        raise ValueError('Stale usage report')
    sources = sample.get('sampled_at', {})
    if not isinstance(sources, dict) or set(sources) != set(SOURCES) or sample.get('errors'):
        raise ValueError('Incomplete usage report')
    if any(not -10 <= (at - datetime.fromisoformat(v)).total_seconds() <= FRESH_SECONDS for v in sources.values()):
        raise ValueError('Stale protocol report')
    if len(sample['users']) > 250:
        raise ValueError('Too many identities')
    for user_id, pair in sample['users'].items():
        if user_id != 'legacy-owner' and not re.fullmatch('[a-f0-9]{32}', user_id):
            raise ValueError('Invalid usage identity')
        byte_count(pair['upload']); byte_count(pair['download'])
        if not isinstance(pair['months'], dict) or len(pair['months']) > 1200:
            raise ValueError('Invalid usage periods')
        for month, values in pair['months'].items():
            if not re.fullmatch(r'\d{4}-(0[1-9]|1[0-2])', month):
                raise ValueError('Invalid usage month')
            byte_count(values['upload']); byte_count(values['download'])
    return sample


def merge_snapshot(previous, incoming):
    """Old/retried reports, missing users and restored backups cannot reset usage."""
    result = copy.deepcopy(incoming)
    users = result['users']
    for user_id, old in previous.get('users', {}).items():
        current = users.setdefault(user_id, copy.deepcopy(old))
        for direction in ['upload', 'download']:
            current[direction] = max(old[direction], current[direction])
        for month, pair in old['months'].items():
            target = current['months'].setdefault(month, copy.deepcopy(pair))
            for direction in ['upload', 'download']:
                target[direction] = max(pair[direction], target[direction])
    return result


def decisions(policies, snapshots, at):
    from traffic_stats import subscription_info
    result = {}
    for user_id, policy in policies.items():
        required = REGIONS if policy.get('include_legacy') else policy.get('regions', REGIONS)
        fresh = all(code in snapshots and
                    -10 <= (at - datetime.fromisoformat(snapshots[code]['checked_at'])).total_seconds() <= FRESH_SECONDS
                    for code in required)
        values = dict(part.strip().split('=', 1) for part in subscription_info(policy, list(snapshots.values()), at).split(';'))
        used = int(values['upload']) + int(values['download'])
        limited = policy.get('enforce', False) and policy['total_bytes'] is not None
        reason = 'member-disabled' if not policy.get('enabled', True) else (
            'quota-service-unavailable' if limited and not fresh else
            'quota-exhausted' if limited and used >= policy['total_bytes'] else '')
        result[user_id] = {'blocked': bool(reason), 'reason': reason, 'used_bytes': used,
                           'policy_hash': policy_hash(policy)}
    return {'month': month_key(at), 'valid_until': (at + timedelta(seconds=LEASE_SECONDS)).isoformat(),
            'decisions': result}


def coordinate(payload, authorization, at=None):
    at = at or clock()
    config = load(COORDINATOR)
    code = payload.get('server_id')
    expected = config.get('keys', {}).get(code, '')
    candidate = hashlib.sha256(authorization.encode()).hexdigest()
    if not config.get('enabled') or not expected or not hmac.compare_digest(expected, candidate):
        raise PermissionError('Invalid quota agent')
    sample = validate_snapshot(payload['sample'], at)
    with (COORD_DATA / '.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        store = load(COORD_DATA / 'usage.json', {'snapshots': {}})
        snapshots = store['snapshots']
        old = snapshots.get(code, {})
        if old and sample['checked_at'] < old['checked_at']:
            raise ValueError('Reordered usage report')
        snapshots[code] = merge_snapshot(old, sample)
        atomic_json(COORD_DATA / 'usage.json', store)
        policies = load(POLICIES).get('members', {})
        return decisions(policies, snapshots, at)


def authorized_peer(authorization):
    config = load(COORDINATOR)
    candidate = hashlib.sha256(authorization.encode()).hexdigest()
    return bool(config.get('enabled') and any(hmac.compare_digest(value, candidate) for value in config.get('keys', {}).values()))


def reason_for(identity, control, state, policies, at):
    if not control.get('enabled'):
        return ''
    if identity == 'legacy-owner':
        policy = next((p for p in policies.values() if p.get('include_legacy')), None)
    else:
        policy = policies.get(identity)
    if not policy:
        return 'quota-policy-pending'
    if not policy.get('enabled', True):
        return 'member-disabled'
    if not policy.get('enforce', False) or policy['total_bytes'] is None:
        return ''
    try:
        valid = at < datetime.fromisoformat(state['valid_until']) and state['month'] == month_key(at)
        decision = state['decisions'][policy['user_id']]
        valid = valid and hmac.compare_digest(decision['policy_hash'], policy_hash(policy))
    except (KeyError, ValueError, TypeError):
        valid = False
    if not valid:
        return 'quota-service-unavailable'
    return decision['reason'] if decision['blocked'] else ''


def authentication_blocked(identity):
    try:
        return bool(reason_for(identity, load(CONTROL), load(STATE), load(POLICIES).get('members', {}), clock()))
    except (OSError, ValueError, KeyError, TypeError):
        # With the guard armed, missing/corrupt decisions cannot reopen access.
        return CONTROL.exists()


def session_identity(identity):
    """A restored session cannot consume an old Hysteria one-shot kick flag."""
    control, state, policies = load(CONTROL), load(STATE), load(POLICIES).get('members', {})
    policy = next((p for p in policies.values() if p.get('include_legacy')), None) if identity == 'legacy-owner' else policies.get(identity)
    if not control.get('enabled') or not policy or not policy.get('enforce') or policy['total_bytes'] is None:
        return identity
    period = month_key(clock()) if policy['period'] == 'month' else 'lifetime'
    generation = state.get('generations', {}).get(identity, 0)
    value = f"{policy_hash(policy)}:{period}:{policy.get('revision', 0)}:{generation}"
    return identity + ':' + hashlib.sha256(value.encode()).hexdigest()[:16]


def guarded(configuration, blocked, aliases):
    result = copy.deepcopy(configuration)
    rules = result.setdefault('routing', {}).setdefault('rules', [])
    rules[:] = [rule for rule in rules if rule.get('ruleTag') != RULE]
    names = sorted(name for name, identity in aliases.items() if identity in blocked)
    if names:
        if not any(o.get('tag') == 'blocked' and o.get('protocol') == 'blackhole' for o in result['outbounds']):
            raise ValueError('Missing deny outbound')
        rules.insert(0, {'ruleTag': RULE, 'type': 'field', 'user': names, 'outboundTag': 'blocked'})
    return result


def current_blocks(members, extra):
    aliases = identities(members, extra)
    control, state, policies = load(CONTROL), load(STATE), load(POLICIES).get('members', {})
    return {identity: reason_for(identity, control, state, policies, clock()) for identity in set(aliases.values())}, aliases


def guard_configuration(configuration, members, extra):
    reasons, aliases = current_blocks(members, extra)
    return guarded(configuration, {identity for identity, reason in reasons.items() if reason}, aliases)


def kick_online(blocked):
    if not blocked:
        return
    auth = load(BASE / 'team-auth-state.json')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    deadline = time.monotonic() + 1
    while True:
        request = urllib.request.Request('http://127.0.0.1:24592/online', headers={'Authorization': auth['stats_secret']})
        with opener.open(request, timeout=5) as response:
            online = json.load(response)
        targets = [identity for identity, count in online.items() if count > 0 and identity.partition(':')[0] in blocked]
        if not targets:
            return
        request = urllib.request.Request('http://127.0.0.1:24592/kick', data=json.dumps(targets).encode(),
            headers={'Authorization': auth['stats_secret'], 'Content-Type': 'application/json'})
        with opener.open(request, timeout=5) as response:
            if response.status != 200:
                raise RuntimeError('Could not terminate quota-limited QUIC sessions')
        if time.monotonic() >= deadline:
            return
        time.sleep(.05)


def apply_blocks(reasons, aliases):
    blocked = {identity for identity, reason in reasons.items() if reason}
    candidates = []
    for filename, service in [('xray.json', 'self-vpn'), ('extra-xray.json', 'self-vpn-extra')]:
        path = BASE / filename
        content = json.dumps(guarded(load(path), blocked, aliases))
        if path.read_text() != content:
            candidates.append((path, content, service))
    if candidates:
        with Transaction(paths=[p for p, _, _ in candidates], services=[s for _, _, s in candidates], pause_renewal=False) as transaction:
            for _, content, _ in candidates:
                validate_xray(json.loads(content))
            for path, content, service in candidates:
                changed = write(path, content, 0o640, 'self-vpn')
                # Restart on a transition also terminates existing TCP sessions.
                apply_service(service, changed, transaction)
            transaction.commit()
    kick_online(blocked)


def enforce(sample, apply=True):
    if not CLIENT.exists():
        return {}
    # Serialize a timer, manual collection and a setup/arming request.
    with (DATA / '.quota.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        state = load(STATE)
        config = load(CLIENT)
        error = None
        try:
            request = urllib.request.Request(config['endpoint'], data=json.dumps({'server_id': config['server_id'], 'sample': sample}).encode(),
                headers={'Authorization': config['credential'], 'Content-Type': 'application/json'})
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(request, timeout=5) as response:
                value = json.loads(response.read(2_000_000))
            if (value['month'] != month_key() or not isinstance(value['decisions'], dict)
                    or not clock() < datetime.fromisoformat(value['valid_until']) <= clock() + timedelta(seconds=LEASE_SECONDS + 5)):
                raise ValueError('Invalid quota decision')
            state.update(value)
            state['last_sync'] = stamp()
        except Exception:
            error = '额度服务暂时不可用，超过有效期后暂停代理'
        state.update(error=error, checked_at=stamp(), enabled=bool(load(CONTROL).get('enabled')))
        members, extra = load(BASE / 'team-members.json'), load(BASE / 'extra-secrets.json')
        aliases = identities(members, extra)
        policies, control = load(POLICIES).get('members', {}), load(CONTROL)
        reasons = {identity: reason_for(identity, control, state, policies, clock()) for identity in set(aliases.values())}
        previous = state.setdefault('auth_reasons', {})
        generations = state.setdefault('generations', {})
        for identity, reason in reasons.items():
            if previous.get(identity) and not reason:
                generations[identity] = generations.get(identity, 0) + 1
            previous[identity] = reason
        # Auth sees the new decision/session generation before /kick.
        write(STATE, json.dumps(state), 0o640, 'self-vpn')
        if not apply:
            return public_state(state)
        try:
            apply_blocks(reasons, aliases)
            state['reasons'] = reasons
            state['applied_at'] = stamp()
            state['apply_error'] = None
        except Exception:
            state['apply_error'] = '额度执行暂未完成，将自动重试'
        write(STATE, json.dumps(state), 0o640, 'self-vpn')
        return public_state(state)


def public_state(state=None):
    state = load(STATE) if state is None else state
    return {key: state.get(key) for key in ['enabled', 'checked_at', 'last_sync', 'applied_at', 'error', 'apply_error', 'reasons']}
