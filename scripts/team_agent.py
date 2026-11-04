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

AUTH_SERVICE = 'self-vpn-team-auth'
TEAM_SUB = Path('/var/lib/self-vpn/team-subscriptions')
MANIFEST = BASE / 'team-publications.json'
AUTH_UNIT = '''[Unit]
Description=Self VPN local team authentication
After=network.target
[Service]
User=self-vpn
Group=self-vpn
ExecStart=/usr/bin/python3 /etc/self-vpn/team_auth.py
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
MemoryMax=96M
[Install]
WantedBy=multi-user.target
'''
NGINX_TEAM = '''location ^~ /team-sub/ {
    alias /var/lib/self-vpn/team-subscriptions/;
    autoindex off;
    default_type application/yaml;
    add_header Cache-Control "private, no-store" always;
    add_header profile-update-interval "6" always;
    add_header X-Content-Type-Options nosniff always;
}
location = /team-rules/cn-domain.mrs { alias /var/lib/self-vpn/subscription/cn-domain.mrs; }
location = /team-rules/cn-ip.mrs { alias /var/lib/self-vpn/subscription/cn-ip.mrs; }
'''

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
    with Transaction(services=['nginx', 'self-vpn', 'self-vpn-extra', 'self-vpn-hysteria2', AUTH_SERVICE]) as transaction:
        secret = json.loads((BASE / 'secrets.json').read_text())
        extra = json.loads((BASE / 'extra-secrets.json').read_text())
        old = json.loads((BASE / 'team-members.json').read_text()) if (BASE / 'team-members.json').exists() else []
        auth_state = json.loads((BASE / 'team-auth-state.json').read_text()) if (BASE / 'team-auth-state.json').exists() else {'stats_secret': secrets.token_urlsafe(32)}
        write(BASE / 'team-auth-state.json', json.dumps(auth_state))
        primary, secondary, hy = configurations(secret, extra, settings, members)
        hy['trafficStats'] = {'listen': '127.0.0.1:24592', 'secret': auth_state['stats_secret']}
        validate_xray(primary)
        validate_xray(secondary)
        users = {'legacy-owner': hashlib.sha256(extra['hysteria_password'].encode()).hexdigest()}
        users.update({m['id']: hashlib.sha256(m['credential']['hysteria_password'].encode()).hexdigest() for m in members})
        write(BASE / 'team-auth-users.json', json.dumps(users), 0o640, 'self-vpn')
        auth_changed = write(BASE / 'team_auth.py', (Path(__file__).parent / 'team_auth.py').read_bytes(), 0o640, 'self-vpn')
        unit_changed = write('/etc/systemd/system/' + AUTH_SERVICE + '.service', AUTH_UNIT, 0o644)
        apply_service(AUTH_SERVICE, auth_changed or unit_changed, transaction, unit_changed=unit_changed)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        request = urllib.request.Request('http://127.0.0.1:24591/auth', data=json.dumps({'auth': extra['hysteria_password']}).encode(), headers={'Content-Type': 'application/json'})
        deadline = time.monotonic() + 10
        while True:
            try:
                with opener.open(request, timeout=2) as response:
                    if json.load(response).get('id') != 'legacy-owner':
                        raise RuntimeError('Owner authentication compatibility check failed')
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise RuntimeError('Local authentication service did not become ready') from None
                time.sleep(0.15)
        nginx_dir = Path('/etc/nginx/self-vpn-team')
        nginx_dir.mkdir(mode=0o755, exist_ok=True)
        write(nginx_dir / 'subscriptions.conf', NGINX_TEAM, 0o644)
        apply_nginx(nginx_config(True, secret['subscription_token'], settings, nginx_uses_http2_directive()), transaction)
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
            request = urllib.request.Request('http://127.0.0.1:24592/kick', data=json.dumps(kicked).encode(), headers={'Authorization': auth_state['stats_secret'], 'Content-Type': 'application/json'})
            with opener.open(request, timeout=5) as response:
                if response.status != 200:
                    raise RuntimeError('Could not revoke established Hysteria sessions')
        write(BASE / 'team-members.json', json.dumps(members))
        write(BASE / 'team-managed', 'Managed by Self VPN team console.\n')
        receipt = {'digest': fingerprint(members), 'member_count': len(members), 'services': 'active', 'kicked': len(kicked)}
        commit_handshake(receipt, transaction)

def publication(payload):
    user_id, token = payload['user_id'], payload.get('token')
    if not re.fullmatch('[a-f0-9]{32}', user_id) or (token is not None and not re.fullmatch('[A-Za-z0-9_-]{40,80}', token)):
        raise ValueError('Invalid publication identity')
    with Transaction(paths=[TEAM_SUB, MANIFEST], services=[], pause_renewal=False) as transaction:
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
        commit_handshake({'published': bool(token)}, transaction)

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
    else:
        raise ValueError('Unsupported team action')
