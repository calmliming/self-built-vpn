#!/usr/bin/env python3
"""Add protocol choices on the existing server; do not publish before WAN tests."""
import copy
import grp
import hashlib
import json
import os
from pathlib import Path
import secrets

from settings import dump_env, dump_yaml, load_settings, server_parser
from operations import apply_service, require_active, run, validate_xray, write
from routing_rules import download

BASE = Path('/etc/self-vpn')
SUB = Path('/var/lib/self-vpn/subscription')
HY_VERSION = '2.13.0'
HY_URL = 'https://github.com/HyNetworks/hysteria/releases/download/app/v2.13.0/hysteria-linux-amd64'
HY_SHA256 = '907ba8c9693edb104b20582681fb7dc15639d5b64a9cbb616a7b539190a86691'


def unit(description, command, low_port=False):
    capabilities = 'AmbientCapabilities=CAP_NET_BIND_SERVICE\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\n' if low_port else 'CapabilityBoundingSet=\n'
    return f'''[Unit]
Description={description}
After=network-online.target
Wants=network-online.target

[Service]
User=self-vpn
Group=self-vpn
ExecStart={command}
Restart=on-failure
RestartSec=3
LimitNOFILE=65536
{capabilities}NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true

[Install]
WantedBy=multi-user.target
'''


def prioritize_hysteria(configuration):
    result = copy.deepcopy(configuration)
    kinds = {node['name']: node['type'] for node in result.get('proxies', [])}
    for group in result.get('proxy-groups', []):
        if group.get('type') == 'fallback' and 'proxies' in group:
            group['proxies'].sort(key=lambda name: kinds.get(name) != 'hysteria2')
    return result


def restrict_automatic_exit(configuration, server_ip):
    """Keep manual choices intact while confining automatic traffic to one VPS."""
    result = copy.deepcopy(configuration)
    names = {node['name'] for node in result.get('proxies', []) if node['server'] == server_ip}
    if not names:
        raise ValueError('The fixed exit has no nodes in this subscription')
    for group in result.get('proxy-groups', []):
        if group.get('name') in ['地区自动回退', '规则下载'] and group.get('type') == 'fallback':
            group['proxies'] = [name for name in group['proxies'] if name in names]
            if not group['proxies']:
                raise ValueError('The fixed exit has no automatic fallback nodes')
    return result


def profile(base, extra, settings):
    result = copy.deepcopy(base)
    main = result['proxies'][0]
    reality = copy.deepcopy(main)
    names = settings.node_names
    reality.update(name=names[1], port=settings.reality_alt_port)
    trojan = {
        'name': names[2], 'type': 'trojan', 'server': settings.server_ip, 'port': settings.trojan_port,
        'password': extra['trojan_password'], 'sni': settings.server_ip, 'udp': True,
        'skip-cert-verify': False, 'client-fingerprint': 'chrome',
    }
    hysteria = {
        'name': names[3], 'type': 'hysteria2', 'server': settings.server_ip, 'port': settings.hysteria2_port,
        'password': extra['hysteria_password'], 'sni': settings.server_ip, 'skip-cert-verify': False,
    }
    if settings.hysteria2_obfs:
        hysteria.update(obfs=settings.hysteria2_obfs, **{'obfs-password': extra['hysteria_obfs_password']})
    result['proxies'] = [main, reality, trojan, hysteria]
    for _, kind, port in settings.optional_proxy_ports:
        node = {
            'name': names[len(result['proxies'])], 'type': kind, 'server': settings.server_ip, 'port': port,
            'username': extra[kind + '_username'], 'password': extra[kind + '_password'],
            'tls': True, 'sni': settings.server_ip, 'skip-cert-verify': False,
        }
        if kind == 'socks5':
            node['udp'] = False
        result['proxies'].append(node)
    names = [node['name'] for node in result['proxies']]
    result['proxy-groups'] = [
        {'name': settings.ai_group_name, 'type': 'select', 'proxies': [settings.auto_group_name, *names]},
        {'name': settings.auto_group_name, 'type': 'fallback', 'proxies': [names[3], *names[:3], *names[4:]],
         'url': settings.healthcheck_url, 'interval': settings.healthcheck_interval, 'timeout': settings.healthcheck_timeout_ms},
        {'name': settings.rules_group_name, 'type': 'fallback', 'proxies': [names[3], names[2], names[1], names[0], *names[4:]],
         'url': settings.healthcheck_url, 'interval': settings.healthcheck_interval,
         'timeout': settings.healthcheck_timeout_ms, 'hidden': True},
    ]
    for provider in result['rule-providers'].values():
        provider['proxy'] = settings.rules_group_name
    return result


def extra_xray_config(original, extra, settings):
    tls = BASE / 'tls'
    configuration = copy.deepcopy(original)
    secondary = copy.deepcopy(original['inbounds'][0])
    secondary.update(tag=f'reality-{settings.reality_alt_port}', port=settings.reality_alt_port)
    trojan = {
        'tag': f'trojan-{settings.trojan_port}', 'listen': '0.0.0.0', 'port': settings.trojan_port, 'protocol': 'trojan',
        'settings': {'clients': [{'password': extra['trojan_password'], 'email': 'personal-trojan'}]},
        'streamSettings': {'network': 'tcp', 'security': 'tls', 'tlsSettings': {
            'minVersion': '1.2', 'certificates': [{
                'certificateFile': str(tls / 'fullchain.pem'), 'keyFile': str(tls / 'privkey.pem'),
            }],
        }},
    }
    configuration['inbounds'] = [secondary, trojan]
    for _, kind, port in settings.optional_proxy_ports:
        # Xray v26.3.27 uses "accounts" for HTTP and SOCKS authentication.
        authentication = {'accounts': [{'user': extra[kind + '_username'], 'pass': extra[kind + '_password']}]}
        if kind == 'socks5':
            authentication.update(auth='password', udp=False)
        else:
            authentication['allowTransparent'] = False
        configuration['inbounds'].append({
            'tag': f'{kind}-{port}', 'listen': '0.0.0.0', 'port': port,
            'protocol': 'socks' if kind == 'socks5' else 'http',
            'settings': authentication, 'streamSettings': copy.deepcopy(trojan['streamSettings']),
        })
    return configuration


def hysteria_config(extra, settings):
    tls = BASE / 'tls'
    networks = ['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16', '224.0.0.0/4', '::1/128', 'fc00::/7', 'fe80::/10']
    configuration = {
        'listen': f'0.0.0.0:{settings.hysteria2_port}',
        'tls': {'cert': str(tls / 'fullchain.pem'), 'key': str(tls / 'privkey.pem')},
        'auth': {'type': 'password', 'password': extra['hysteria_password']},
        'acl': {'inline': [f'reject({network})' for network in networks] + ['direct(all)']},
        'outbounds': [{'name': 'direct', 'type': 'direct', 'direct': {'mode': '4'}}],
        'masquerade': {'type': 'string', 'string': {'content': 'Not Found', 'statusCode': 404}},
    }
    if settings.hysteria2_obfs:
        configuration['obfs'] = {
            'type': settings.hysteria2_obfs,
            settings.hysteria2_obfs: {'password': extra['hysteria_obfs_password']},
        }
    return configuration



def install(settings, transaction):
    from deploy_server import client_config, write_candidate
    require_active('self-vpn')
    original = json.loads((BASE / 'xray.json').read_text())
    primary = original['inbounds'][0]
    reality = primary['streamSettings']['realitySettings']
    if primary['port'] != settings.reality_port or settings.server_ip not in reality['serverNames'] or reality['target'] != f'127.0.0.1:{settings.nginx_tls_port}':
        raise RuntimeError('Main config differs from requested settings; run manage.py deploy first')
    key_file = BASE / 'extra-secrets.json'
    if key_file.exists():
        extra = json.loads(key_file.read_text())
    else:
        extra = {'trojan_password': secrets.token_urlsafe(32), 'hysteria_password': secrets.token_urlsafe(32)}
        write(key_file, json.dumps(extra, indent=2))
    if settings.hysteria2_obfs and not extra.get('hysteria_obfs_password'):
        extra['hysteria_obfs_password'] = secrets.token_urlsafe(32)
        write(key_file, json.dumps(extra, indent=2))
    for _, kind, _ in settings.optional_proxy_ports:
        if not extra.get(kind + '_username'):
            extra[kind + '_username'] = 'u_' + secrets.token_urlsafe(12)
        if not extra.get(kind + '_password'):
            extra[kind + '_password'] = secrets.token_urlsafe(32)
    write(key_file, json.dumps(extra, indent=2))
    tls = BASE / 'tls'
    tls.mkdir(exist_ok=True)
    tls.chmod(0o750)
    os.chown(tls, 0, grp.getgrnam('self-vpn').gr_gid)
    certificate_changed = False
    for name in ['fullchain.pem', 'privkey.pem']:
        certificate_changed = write(tls / name, Path('/etc/letsencrypt/live/self-vpn-ip', name).read_bytes(), 0o640, 'self-vpn') or certificate_changed
    configuration = extra_xray_config(original, extra, settings)
    validate_xray(configuration)
    xray_changed = write(BASE / 'extra-xray.json', json.dumps(configuration, indent=2), 0o640, 'self-vpn')
    extra_unit_changed = write('/etc/systemd/system/self-vpn-extra.service', unit('Personal VPN alternate protocol endpoints', '/usr/local/bin/xray run -config /etc/self-vpn/extra-xray.json', low_port=min(settings.tcp_proxy_ports[1:]) < 1024), 0o644)
    binary = Path('/usr/local/bin/hysteria')
    binary_changed = False
    if not binary.exists() or hashlib.sha256(binary.read_bytes()).hexdigest() != HY_SHA256:
        content = download(HY_URL, maximum=50_000_000)
        if hashlib.sha256(content).hexdigest() != HY_SHA256:
            raise RuntimeError('Hysteria checksum mismatch')
        binary_changed = write(binary, content, 0o755)
    hy_changed = write(BASE / 'hysteria.yaml', dump_yaml(hysteria_config(extra, settings)), 0o640, 'self-vpn')
    hy_unit_changed = write('/etc/systemd/system/self-vpn-hysteria2.service', unit('Personal VPN Hysteria2', '/usr/local/bin/hysteria server --config /etc/self-vpn/hysteria.yaml', low_port=settings.hysteria2_port < 1024), 0o644)
    hook = """#!/bin/sh
set -eu
install -o root -g self-vpn -m 640 /etc/letsencrypt/live/self-vpn-ip/fullchain.pem /etc/self-vpn/tls/fullchain.pem.new
install -o root -g self-vpn -m 640 /etc/letsencrypt/live/self-vpn-ip/privkey.pem /etc/self-vpn/tls/privkey.pem.new
mv -f /etc/self-vpn/tls/fullchain.pem.new /etc/self-vpn/tls/fullchain.pem
mv -f /etc/self-vpn/tls/privkey.pem.new /etc/self-vpn/tls/privkey.pem
/usr/sbin/nginx -t
/bin/systemctl reload nginx
/bin/systemctl try-restart self-vpn-extra.service
"""
    write('/etc/letsencrypt/renewal-hooks/deploy/self-vpn-nginx', hook, 0o755)
    apply_service('self-vpn-extra', xray_changed or certificate_changed or extra_unit_changed, transaction, unit_changed=extra_unit_changed)
    apply_service('self-vpn-hysteria2', hy_changed or binary_changed or hy_unit_changed, transaction, unit_changed=hy_unit_changed)
    secret = json.loads((BASE / 'secrets.json').read_text())
    write_candidate(secret, settings, profile(client_config(secret, settings), extra, settings))
    print('Extra nodes prepared; candidate subscription remains private.', flush=True)


def read_candidate(settings):
    from deploy_server import client_config, client_metadata
    configuration = json.loads((BASE / 'candidate.json').read_text())
    metadata = json.loads((BASE / 'candidate-metadata.json').read_text())
    secret = json.loads((BASE / 'secrets.json').read_text())
    expected = client_config(secret, settings)
    if len(configuration.get('proxies', [])) > 1:
        extra = json.loads((BASE / 'extra-secrets.json').read_text())
        expected = profile(expected, extra, settings)
    if configuration != expected or metadata != client_metadata(secret, settings, expected):
        raise RuntimeError('Candidate differs from settings or credentials; prepare it again')
    content = (BASE / 'candidate.yaml').read_bytes()
    if content != dump_yaml(configuration).encode():
        raise RuntimeError('Candidate YAML and JSON differ; prepare it again')
    services = ['self-vpn', 'nginx']
    if len(configuration['proxies']) > 1:
        services += ['self-vpn-extra', 'self-vpn-hysteria2']
    for service in services:
        require_active(service)
    return configuration, metadata, hashlib.sha256(content).hexdigest()


def publish(settings, verified_digest):
    configuration, metadata, digest = read_candidate(settings)
    if digest != verified_digest:
        raise RuntimeError('Verified candidate changed before publication')
    write(SUB / 'config.yaml', (BASE / 'candidate.yaml').read_bytes(), 0o640, 'www-data')
    write(BASE / 'client.json', json.dumps(metadata, indent=2))
    if len(configuration['proxies']) > 1:
        write(BASE / 'multi-enabled', '1\n')
    write(BASE / 'deployment.env', dump_env(settings))


if __name__ == '__main__':
    parser = server_parser(__doc__)
    parser.add_argument('--publish', action='store_true')
    args = parser.parse_args()
    from server_agent import run_action
    run_action('publish' if args.publish else 'add-nodes', load_settings(args.config, environ={}))
