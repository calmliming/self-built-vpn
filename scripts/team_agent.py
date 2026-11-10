"""Root-only SSH team changes, with rollback until an external client commits."""
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import select
import shutil
import ssl
import subprocess
import sys
import time
import urllib.request

from operations import BASE, SUB, Transaction, apply_service, run, state, validate_xray, write
from settings import Settings, dump_yaml
from team_auth import normalize_subscription_name

AUTH_SERVICE = 'self-vpn-team-auth'
TEAM_SUB = Path('/var/lib/self-vpn/team-subscriptions')
MANIFEST = BASE / 'team-publications.json'
AUTH_UNIT = '''[Unit]
Description=Self VPN local team authentication
After=network.target
[Service]
User=self-vpn
Group=self-vpn
SupplementaryGroups=www-data
ExecStart=/usr/bin/python3 /etc/self-vpn/team_auth.py
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/self-vpn/quota-coordinator
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
MemoryMax=96M
[Install]
WantedBy=multi-user.target
'''
NGINX_TEAM = '''location ^~ /team-sub/ {
    proxy_pass http://127.0.0.1:24591;
    proxy_connect_timeout 2s;
    proxy_read_timeout 10s;
    proxy_hide_header Server;
}
location = /team-rules/cn-domain.mrs { alias /var/lib/self-vpn/subscription/cn-domain.mrs; }
location = /team-rules/cn-ip.mrs { alias /var/lib/self-vpn/subscription/cn-ip.mrs; }
'''

def nginx_team(owner):
    from quota_control import COORDINATOR, load
    config = load(COORDINATOR)
    endpoint = ''
    if config.get('enabled'):
        # REALITY forwards HTTPS cover traffic over loopback. Its apparent IP is
        # not a peer identity; authenticate every report with the node's key.
        endpoint = 'location = /team-quota/report {\n    limit_except POST { deny all; }\n    client_max_body_size 2m;\n    client_body_timeout 5s;\n    proxy_pass http://127.0.0.1:24591/quota/report;\n    proxy_connect_timeout 2s;\n    proxy_read_timeout 10s;\n}\n'
    return NGINX_TEAM + endpoint + ''.join(
        'location = /sub/' + owner + '/' + name + ' { proxy_pass http://127.0.0.1:24591; proxy_connect_timeout 2s; proxy_read_timeout 10s; }\n'
        for name in ['config.yaml', 'fleet.yaml'])

def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()

def validate_members(members):
    if not isinstance(members, list) or len(members) > 200:
        raise ValueError('Invalid membership list')
    seen = set()
    for member in members:
        if not re.fullmatch('[a-f0-9]{32}', member['id']) or member['id'] in seen:
            raise ValueError('Invalid or duplicate member ID')
        seen.add(member['id'])
        credential = member['credential']
        for key in ['uuid', 'trojan_password', 'hysteria_password', 'http_username', 'http_password', 'socks5_username', 'socks5_password']:
            if not isinstance(credential[key], str) or not re.fullmatch('[A-Za-z0-9_-]{12,80}', credential[key]):
                raise ValueError('Invalid credential')
    return members

def configurations(secret, extra, settings, members):
    from deploy_server import xray_config
    from add_protocol_nodes import extra_xray_config, hysteria_config
    primary = xray_config(secret, settings)
    for member in members:
        primary['inbounds'][0]['settings']['clients'].append({
            'id': member['credential']['uuid'], 'flow': 'xtls-rprx-vision', 'email': 'team-' + member['id'],
        })
    secondary = extra_xray_config(primary, extra, settings)
    for inbound in secondary['inbounds']:
        for member in members:
            credential = member['credential']
            if inbound['protocol'] == 'trojan':
                inbound['settings']['clients'].append({'password': credential['trojan_password'], 'email': 'team-' + member['id']})
            elif inbound['protocol'] in ['http', 'socks']:
                kind = 'socks5' if inbound['protocol'] == 'socks' else 'http'
                inbound['settings']['accounts'].append({'user': credential[kind + '_username'], 'pass': credential[kind + '_password']})
    hy = hysteria_config(extra, settings)
    hy['auth'] = {'type': 'http', 'http': {'url': 'http://127.0.0.1:24591/auth'}}
    from traffic_stats import instrument
    primary, secondary = instrument(primary, 24593), instrument(secondary, 24594)
    from quota_control import guard_configuration
    primary, secondary = guard_configuration(primary, members, extra), guard_configuration(secondary, members, extra)
    return primary, secondary, hy

def commit_handshake(receipt, transaction):
    nonce = secrets.token_hex(16)
    print(json.dumps({'event': 'ready', 'nonce': nonce, **receipt}), flush=True)
    ready, _, _ = select.select([sys.stdin], [], [], 300)
    if not ready:
        raise RuntimeError('External verification timed out')
    message = json.loads(sys.stdin.readline(4096))
    if message != {'action': 'commit', 'nonce': nonce}:
        raise RuntimeError('External verification aborted')
    transaction.commit()
    print(json.dumps({'event': 'committed', **receipt}), flush=True)

def sync(payload, settings):
    from deploy_server import apply_nginx, nginx_config, nginx_uses_http2_directive
    from add_protocol_nodes import HY_SHA256
    if hashlib.sha256(Path('/usr/local/bin/hysteria').read_bytes()).hexdigest() != HY_SHA256:
        raise RuntimeError('Installed Hysteria version differs from supported version')
    members = validate_members(payload['members'])
    if (BASE / 'traffic_stats.py').exists():
        from traffic_stats import collect
        collect()
    with Transaction(services=['nginx', 'self-vpn', 'self-vpn-extra', 'self-vpn-hysteria2', AUTH_SERVICE, 'self-vpn-traffic.timer']) as transaction:
        secret = json.loads((BASE / 'secrets.json').read_text())
        extra = json.loads((BASE / 'extra-secrets.json').read_text())
        old = json.loads((BASE / 'team-members.json').read_text()) if (BASE / 'team-members.json').exists() else []
        auth_state = json.loads((BASE / 'team-auth-state.json').read_text()) if (BASE / 'team-auth-state.json').exists() else {'stats_secret': secrets.token_urlsafe(32)}
        write(BASE / 'team-auth-state.json', json.dumps(auth_state))
        if payload.get('traffic_metadata'):
            traffic_metadata(payload['traffic_metadata'])
        from quota_control import CLIENT, enforce
        if CLIENT.exists():
            from traffic_stats import collect
            enforce(collect(), apply=False)
        primary, secondary, hy = configurations(secret, extra, settings, members)
        hy['trafficStats'] = {'listen': '127.0.0.1:24592', 'secret': auth_state['stats_secret']}
        validate_xray(primary)
        validate_xray(secondary)
        users = {'legacy-owner': hashlib.sha256(extra['hysteria_password'].encode()).hexdigest()}
        users.update({m['id']: hashlib.sha256(m['credential']['hysteria_password'].encode()).hexdigest() for m in members})
        write(BASE / 'team-auth-users.json', json.dumps(users), 0o640, 'self-vpn')
        auth_changed = write(BASE / 'team_auth.py', (Path(__file__).parent / 'team_auth.py').read_bytes(), 0o640, 'self-vpn')
        install_traffic_files(transaction)
        from traffic_stats import POLICIES
        if not POLICIES.exists():
            write(POLICIES, json.dumps({'legacy_token': secret['subscription_token'], 'members': {}, 'snapshots': {}}),
                  0o640, 'self-vpn')
        unit_changed = write('/etc/systemd/system/' + AUTH_SERVICE + '.service', AUTH_UNIT, 0o644)
        apply_service(AUTH_SERVICE, auth_changed or unit_changed, transaction, unit_changed=unit_changed)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        request = urllib.request.Request('http://127.0.0.1:24591/auth', data=json.dumps({'auth': extra['hysteria_password']}).encode(), headers={'Content-Type': 'application/json'})
        deadline = time.monotonic() + 10
        while True:
            try:
                with opener.open(request, timeout=2) as response:
                    from quota_control import authentication_blocked
                    expected = '' if authentication_blocked('legacy-owner') else 'legacy-owner'
                    if json.load(response).get('id', '').partition(':')[0] != expected:
                        raise RuntimeError('Owner authentication compatibility check failed')
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise RuntimeError('Local authentication service did not become ready') from None
                time.sleep(0.15)
        nginx_dir = Path('/etc/nginx/self-vpn-team')
        nginx_dir.mkdir(mode=0o755, exist_ok=True)
        includes_changed = write(nginx_dir / 'subscriptions.conf', nginx_team(secret['subscription_token']), 0o644)
        apply_nginx(nginx_config(True, secret['subscription_token'], settings, nginx_uses_http2_directive()), transaction,
                    includes_changed=includes_changed)
        for path, content, service in [
            (BASE / 'xray.json', json.dumps(primary), 'self-vpn'),
            (BASE / 'extra-xray.json', json.dumps(secondary), 'self-vpn-extra'),
            (BASE / 'hysteria.yaml', dump_yaml(hy), 'self-vpn-hysteria2'),
        ]:
            changed = write(path, content, 0o640, 'self-vpn')
            apply_service(service, changed, transaction)
        current = {m['id']: m for m in members}
        kicked = [m['id'] for m in old if m != current.get(m['id'])]
        if kicked:
            from quota_control import kick_online
            kick_online(set(kicked))
        write(BASE / 'team-members.json', json.dumps(members))
        write(BASE / 'team-managed', 'Managed by Self VPN team console.\n')
        from quota_control import current_blocks
        reasons, _ = current_blocks(members, extra)
        receipt = {'digest': fingerprint(members), 'member_count': len(members), 'services': 'active', 'kicked': len(kicked),
                   'quota_blocked': [key for key, value in reasons.items() if value]}
        commit_handshake(receipt, transaction)

def publication(payload):
    from traffic_stats import POLICIES
    user_id, token = payload['user_id'], payload.get('token')
    if not re.fullmatch('[a-f0-9]{32}', user_id) or (token is not None and not re.fullmatch('[A-Za-z0-9_-]{40,80}', token)):
        raise ValueError('Invalid publication identity')
    with Transaction(paths=[TEAM_SUB, MANIFEST, POLICIES], services=[], pause_renewal=False) as transaction:
        records = json.loads(MANIFEST.read_text()) if MANIFEST.exists() else {}
        old_token = records.get(user_id)
        if token:
            import grp
            TEAM_SUB.mkdir(mode=0o750, exist_ok=True)
            TEAM_SUB.chmod(0o750)
            os.chown(TEAM_SUB, 0, grp.getgrnam('www-data').gr_gid)
            target = TEAM_SUB / token
            target.mkdir(mode=0o750, exist_ok=True)
            target.chmod(0o750)
            os.chown(target, 0, grp.getgrnam('www-data').gr_gid)
            content = payload['content'].encode()
            config = json.loads(content)
            if not config.get('proxies') or hashlib.sha256(content).hexdigest() != payload['digest']:
                raise ValueError('Publication content or digest invalid')
            write(target / 'config.yaml', content, 0o640, 'www-data')
            records[user_id] = token
        else:
            records.pop(user_id, None)
        if old_token and old_token != token:
            if not re.fullmatch('[A-Za-z0-9_-]{40,80}', old_token):
                raise ValueError('Invalid previous publication')
            shutil.rmtree(TEAM_SUB / old_token, ignore_errors=True)
        write(MANIFEST, json.dumps(records))
        if payload.get('traffic_policy') and POLICIES.exists():
            policies = json.loads(POLICIES.read_text())
            policies.setdefault('members', {})[user_id] = validate_policy(payload['traffic_policy'])
            write(POLICIES, json.dumps(policies), 0o640, 'self-vpn')
        commit_handshake({'published': bool(token)}, transaction)

TRAFFIC_UNIT = '''[Unit]
Description=Self VPN traffic counter checkpoint
After=network.target
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /etc/self-vpn/traffic_stats.py
User=root
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/self-vpn/traffic /etc/self-vpn
TimeoutStartSec=90
'''
TRAFFIC_TIMER = '''[Unit]
Description=Check VPN counters and member quotas every ten seconds
[Timer]
OnBootSec=10s
OnUnitInactiveSec=10s
AccuracySec=1s
[Install]
WantedBy=timers.target
'''

def validate_policy(policy):
    from traffic_stats import byte_count
    if (not re.fullmatch('[a-f0-9]{32}', policy['user_id'])
            or not re.fullmatch('[A-Za-z0-9_-]{40,80}', policy['token'])
            or policy['period'] not in ['lifetime', 'month']
            or type(policy['include_legacy']) is not bool):
        raise ValueError('Invalid traffic policy')
    if policy['total_bytes'] is not None:
        byte_count(policy['total_bytes'])
    if type(policy.get('enforce', False)) is not bool or type(policy.get('enabled', True)) is not bool:
        raise ValueError('Invalid quota enforcement flag')
    if not isinstance(policy.get('regions', ['us']), list) or not set(policy.get('regions', ['us'])) <= {'hk', 'sg', 'us'}:
        raise ValueError('Invalid quota regions')
    return policy

def traffic_metadata(payload):
    import grp
    from traffic_stats import DATA, POLICIES
    if payload['server_id'] not in ['hk', 'sg', 'us']:
        raise ValueError('Invalid traffic region')
    policies = [validate_policy(policy) for policy in payload['policies']]
    if len(policies) > 200 or sum(p['include_legacy'] for p in policies) > 1:
        raise ValueError('Invalid legacy traffic owner')
    DATA.mkdir(mode=0o750, parents=True, exist_ok=True)
    DATA.chmod(0o750)
    os.chown(DATA, 0, grp.getgrnam('self-vpn').gr_gid)
    owner = json.loads((BASE / 'secrets.json').read_text())['subscription_token']
    value = json.loads(POLICIES.read_text()) if POLICIES.exists() else {}
    value.update(server_id=payload['server_id'], members={p['user_id']: p for p in policies},
                 legacy_token=owner, snapshots=payload.get('snapshots', {}))
    if 'subscription_name' in payload:
        value['subscription_name'] = normalize_subscription_name(payload['subscription_name'])
    write(POLICIES, json.dumps(value), 0o640, 'self-vpn')
    return {'updated': True}

def refresh_traffic_metadata(payload):
    from traffic_stats import POLICIES
    installed = BASE / 'team_auth.py'
    source = Path(__file__).with_name('team_auth.py').read_bytes()
    if not installed.exists() or installed.read_bytes() == source:
        return traffic_metadata(payload)
    # Upgrade the subscription handler on existing team servers only once.
    with Transaction(paths=[installed, POLICIES], services=[AUTH_SERVICE], pause_renewal=False) as transaction:
        result = traffic_metadata(payload)
        changed = write(installed, source, 0o640, 'self-vpn')
        apply_service(AUTH_SERVICE, changed, transaction)
        transaction.commit()
    return result

def install_traffic_files(transaction):
    import grp
    from traffic_stats import DATA
    DATA.mkdir(mode=0o750, parents=True, exist_ok=True)
    DATA.chmod(0o750)
    os.chown(DATA, 0, grp.getgrnam('self-vpn').gr_gid)
    from quota_control import COORD_DATA
    COORD_DATA.mkdir(mode=0o700, parents=True, exist_ok=True)
    import pwd
    os.chown(COORD_DATA, pwd.getpwnam('self-vpn').pw_uid, grp.getgrnam('self-vpn').gr_gid)
    COORD_DATA.chmod(0o700)
    source = Path(__file__).parent
    for name in ['traffic_stats.py', 'operations.py', 'quota_control.py']:
        write(BASE / name, (source / name).read_bytes(), 0o640, 'self-vpn')
    changed = write('/etc/systemd/system/self-vpn-traffic.service', TRAFFIC_UNIT, 0o644)
    changed = write('/etc/systemd/system/self-vpn-traffic.timer', TRAFFIC_TIMER, 0o644) or changed
    apply_service('self-vpn-traffic.timer', changed, transaction, unit_changed=changed)

def quota_setup(payload, settings):
    """Install with guards unarmed; arm only after all three peers report."""
    import ipaddress
    from urllib.parse import urlsplit
    from quota_control import CONTROL, CLIENT, COORDINATOR
    from deploy_server import apply_nginx, nginx_config, nginx_uses_http2_directive
    setup = payload['quota_setup']
    if setup['server_id'] not in ['hk', 'sg', 'us'] or not re.fullmatch('[A-Za-z0-9_-]{40,80}', setup['credential']):
        raise ValueError('Invalid quota setup')
    url = urlsplit(setup['endpoint'])
    if url.username or url.password or url.query or url.fragment:
        raise ValueError('Invalid quota endpoint')
    if not (url.scheme == 'https' and url.port in [None,443] and url.path == '/team-quota/report'):
        if setup['server_id'] != 'us' or setup['endpoint'] != 'http://127.0.0.1:24591/quota/report':
            raise ValueError('Quota transport requires verified HTTPS')
    ipaddress.ip_address(url.hostname)
    coordinator = setup.get('coordinator')
    if coordinator:
        if setup['server_id'] != 'us' or set(coordinator['keys']) != {'hk','sg','us'}:
            raise ValueError('Invalid quota coordinator')
        for value in coordinator['keys'].values():
            if not re.fullmatch('[a-f0-9]{64}', value):
                raise ValueError('Invalid peer key')
        for address in coordinator['addresses']:
            ipaddress.IPv4Address(address)
    with Transaction(services=[AUTH_SERVICE, 'nginx', 'self-vpn-traffic.timer']) as transaction:
        if not CONTROL.exists():
            write(CONTROL, json.dumps({'enabled': False}), 0o640, 'self-vpn')
        write(CLIENT, json.dumps({k: setup[k] for k in ['server_id','endpoint','credential']}))
        if coordinator:
            write(COORDINATOR, json.dumps({'enabled': True, **coordinator}), 0o640, 'self-vpn')
        install_traffic_files(transaction)
        changed = write(BASE / 'team_auth.py', (Path(__file__).parent / 'team_auth.py').read_bytes(), 0o640, 'self-vpn')
        unit_changed = write('/etc/systemd/system/' + AUTH_SERVICE + '.service', AUTH_UNIT, 0o644)
        apply_service(AUTH_SERVICE, changed or unit_changed, transaction, unit_changed=unit_changed)
        owner = json.loads((BASE / 'secrets.json').read_text())['subscription_token']
        changed = write('/etc/nginx/self-vpn-team/subscriptions.conf', nginx_team(owner), 0o644)
        apply_nginx(nginx_config(True, owner, settings, nginx_uses_http2_directive()), transaction, includes_changed=changed)
        commit_handshake({'quota_installed': True}, transaction)

def quota_poll(arm=False):
    from quota_control import CONTROL, STATE, enforce, load
    from traffic_stats import collect
    report = enforce(collect())
    state = load(STATE)
    if arm:
        if (state.get('error') or not state.get('decisions') or
                any(value.get('reason') == 'quota-service-unavailable' for value in state['decisions'].values())):
            raise RuntimeError('Quota coordinator has not become ready')
        write(CONTROL, json.dumps({'enabled': True}), 0o640, 'self-vpn')
        report = enforce(collect())
        if report.get('error') or report.get('apply_error'):
            raise RuntimeError('Quota enforcement incomplete; retry will reconcile')
    return report

def metering(payload, settings):
    """Enable accounting without changing credentials, routing or Hysteria."""
    from deploy_server import apply_nginx, nginx_config, nginx_uses_http2_directive
    from traffic_stats import POLICIES, STORE, collect, instrument
    services = ['self-vpn', 'self-vpn-extra', AUTH_SERVICE, 'nginx', 'self-vpn-traffic.timer']
    with Transaction(services=services) as transaction:
        traffic_metadata(payload)
        # Freeze the initial Hysteria baseline before any verification traffic.
        collect()
        for filename, port, service in [('xray.json', 24593, 'self-vpn'), ('extra-xray.json', 24594, 'self-vpn-extra')]:
            config = instrument(json.loads((BASE / filename).read_text()), port)
            validate_xray(config)
            changed = write(BASE / filename, json.dumps(config), 0o640, 'self-vpn')
            apply_service(service, changed, transaction)
        auth_changed = write(BASE / 'team_auth.py', (Path(__file__).parent / 'team_auth.py').read_bytes(), 0o640, 'self-vpn')
        install_traffic_files(transaction)
        changed = write('/etc/systemd/system/' + AUTH_SERVICE + '.service', AUTH_UNIT, 0o644)
        apply_service(AUTH_SERVICE, auth_changed or changed, transaction, unit_changed=changed)
        owner = json.loads((BASE / 'secrets.json').read_text())['subscription_token']
        includes_changed = write('/etc/nginx/self-vpn-team/subscriptions.conf', nginx_team(owner), 0o644)
        apply_nginx(nginx_config(True, owner, settings, nginx_uses_http2_directive()), transaction,
                    includes_changed=includes_changed)
        report = collect()
        if report['errors'] or len(report['sampled_at']) != 3:
            raise RuntimeError('Traffic counter acceptance failed')
        commit_handshake({'metering': True, 'sampled_at': report['checked_at']}, transaction)

def prioritize_subscriptions(settings=None, restrict_exit=False):
    """Refresh existing owner subscriptions without changing server credentials."""
    from add_protocol_nodes import prioritize_hysteria, restrict_automatic_exit
    paths = [SUB / name for name in ['config.yaml', 'fleet.yaml'] if (SUB / name).is_file()]
    if not paths:
        raise RuntimeError('No existing owner subscriptions')
    with Transaction(paths=paths, services=[], pause_renewal=False) as transaction:
        digests = {}
        for path in paths:
            content = path.read_text()
            try:
                config = json.loads(content)
            except ValueError:
                import yaml
                config = yaml.safe_load(content)
            if not isinstance(config, dict) or not config.get('proxies'):
                raise ValueError('Invalid existing subscription')
            config = prioritize_hysteria(config)
            if restrict_exit and path.name == 'fleet.yaml':
                config = restrict_automatic_exit(config, settings.server_ip)
            content = json.dumps(config, ensure_ascii=False, indent=2) + '\n'
            write(path, content, 0o640, 'www-data')
            digests[path.name] = hashlib.sha256(content.encode()).hexdigest()
        commit_handshake({'files': digests}, transaction)

def probe(settings):
    from server_agent import doctor
    report = doctor(settings)
    memory = dict(line.replace(':', '').split()[:2] for line in Path('/proc/meminfo').read_text().splitlines())
    disk = shutil.disk_usage('/')
    cert = subprocess.run(['openssl', 'x509', '-in', '/etc/letsencrypt/live/self-vpn-ip/fullchain.pem', '-noout', '-enddate'], capture_output=True, text=True, timeout=5)
    cert_expiry = cert.stdout.strip().split('=', 1)[-1]
    report.update({'memory_total_mb': int(memory['MemTotal']) // 1024,
        'memory_used_mb': (int(memory['MemTotal']) - int(memory['MemAvailable'])) // 1024,
        'disk_total_gb': round(disk.total / 1024**3, 1), 'disk_used_gb': round(disk.used / 1024**3, 1),
        'load': list(os.getloadavg()), 'cpu_count': os.cpu_count(),
        'uptime_seconds': float(Path('/proc/uptime').read_text().split()[0]), 'certificate_expires': cert_expiry,
        'team_auth_active': state(AUTH_SERVICE) == 'active',
        'team_managed': (BASE / 'team-managed').exists(),
        'member_count': len(json.loads((BASE / 'team-members.json').read_text())) if (BASE / 'team-members.json').exists() else 0,
    })
    return report

def main(payload):
    if os.geteuid() != 0:
        raise RuntimeError('Root is required')
    settings = Settings(**payload['settings'])
    action = payload['action']
    if action == 'probe':
        print(json.dumps(probe(settings)), flush=True)
    elif action == 'sync':
        sync(payload, settings)
    elif action == 'publication':
        publication(payload)
    elif action == 'prioritize':
        restrict_exit = payload.get('restrict_automatic_exit', False)
        if type(restrict_exit) is not bool:
            raise ValueError('Invalid automatic exit policy')
        prioritize_subscriptions(settings, restrict_exit)
    elif action == 'metering':
        metering(payload, settings)
    elif action == 'traffic':
        from traffic_stats import collect
        print(json.dumps(collect()), flush=True)
    elif action == 'traffic-metadata':
        print(json.dumps(refresh_traffic_metadata(payload)), flush=True)
    elif action == 'quota-setup':
        quota_setup(payload, settings)
    elif action == 'quota-poll':
        print(json.dumps(quota_poll()), flush=True)
    elif action == 'quota-arm':
        print(json.dumps(quota_poll(arm=True)), flush=True)
    else:
        raise ValueError('Unsupported team action')
