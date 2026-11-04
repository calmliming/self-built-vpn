#!/usr/bin/env python3
"""Run as root on the VPN server. Keeps existing client credentials on rerun."""
import base64
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import subprocess
import uuid
import zipfile

from settings import dump_yaml, load_settings, server_parser
from operations import apply_service, run, validate_nginx, validate_xray, write
from routing_rules import download, update_rules

XRAY_VERSION = "26.3.27"
XRAY_SHA256 = "23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae"
BASE = Path("/etc/self-vpn")
DATA = Path("/var/lib/self-vpn")
SUB = DATA / "subscription"
CERT_NAME = "self-vpn-ip"

def nginx_config(with_tls, token, settings, modern_http2=True):
    config = f"""server {{
    listen 80 default_server;
    server_name {settings.server_ip};
    server_tokens off;
    access_log off;
    location ^~ /.well-known/acme-challenge/ {{
        root {DATA}/acme;
        try_files $uri =404;
    }}
    location / {{ return 404; }}
}}
"""
    if with_tls:
        tls_options = 'ssl default_server' if modern_http2 else 'ssl http2 default_server'
        http2_directive = '    http2 on;\n' if modern_http2 else ''
        config += f"""
server {{
    listen 127.0.0.1:{settings.nginx_tls_port} {tls_options};
{http2_directive}    server_name {settings.server_ip};
    server_tokens off;
    access_log off;
    ssl_certificate /etc/letsencrypt/live/{CERT_NAME}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{CERT_NAME}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    add_header X-Robots-Tag "noindex, nofollow" always;
    add_header X-Content-Type-Options nosniff always;
    include /etc/nginx/self-vpn-team/*.conf;
    location ^~ /sub/{token}/ {{
        alias {SUB}/;
        autoindex off;
        default_type application/octet-stream;
        add_header Cache-Control "private, no-store" always;
        add_header profile-update-interval "24" always;
    }}
    location / {{ return 404; }}
}}
"""
    return config


def nginx_uses_http2_directive():
    result = subprocess.run(['nginx', '-v'], capture_output=True, text=True, check=True, timeout=10)
    version = re.search(r'\bnginx/(\d+)\.(\d+)\.(\d+)', result.stdout + result.stderr)
    if not version:
        raise RuntimeError('Cannot determine installed Nginx version')
    return tuple(map(int, version.groups())) >= (1, 25, 1)


def client_config(secret, settings):
    prefix = f"{settings.https_origin}/sub/{secret['subscription_token']}"
    node_name = settings.node_names[0]
    providers = {}
    for name, behavior in [("cn-domain", "domain"), ("cn-ip", "ipcidr")]:
        providers[name] = {
            "type": "http", "behavior": behavior, "format": "mrs",
            "url": f"{prefix}/{name}.mrs", "path": f"./ruleset/self-vpn-{name}.mrs",
            "interval": 86400, "proxy": settings.ai_group_name,
        }
    return {
        "mixed-port": 7890, "allow-lan": False, "bind-address": "127.0.0.1",
        "mode": "rule", "log-level": "warning", "ipv6": False,
        "tcp-concurrent": True,
        "tun": {
            "enable": True, "stack": "mixed", "auto-route": True,
            "auto-detect-interface": True, "dns-hijack": ["any:53", "tcp://any:53"],
        },
        "dns": {
            "enable": True, "listen": "127.0.0.1:1053", "ipv6": False,
            "enhanced-mode": "fake-ip", "fake-ip-range": "198.18.0.1/16",
            "fake-ip-filter": ["*.lan", "*.local", "localhost"],
            "default-nameserver": ["223.5.5.5", "119.29.29.29"],
            "proxy-server-nameserver": ["223.5.5.5", "119.29.29.29"],
            "nameserver": [f"https://1.1.1.1/dns-query#{settings.ai_group_name}", f"https://8.8.8.8/dns-query#{settings.ai_group_name}"],
            "nameserver-policy": {
                "rule-set:cn-domain": ["https://dns.alidns.com/dns-query", "https://doh.pub/dns-query"],
            },
        },
        "proxies": [{
            "name": node_name, "type": "vless", "server": settings.server_ip, "port": settings.reality_port,
            "uuid": secret["uuid"], "network": "tcp", "tls": True,
            "flow": "xtls-rprx-vision", "servername": settings.server_ip,
            "client-fingerprint": "chrome", "udp": True, "packet-encoding": "xudp",
            "reality-opts": {"public-key": secret["public_key"], "short-id": secret["short_id"]},
        }],
        "proxy-groups": [{"name": settings.ai_group_name, "type": "select", "proxies": [node_name]}],
        "rule-providers": providers,
        "rules": [
            f"IP-CIDR,{settings.server_ip}/32,DIRECT,no-resolve",
            "DOMAIN-SUFFIX,lan,DIRECT", "DOMAIN-SUFFIX,local,DIRECT",
            "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve", "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
            "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve", "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
            "IP-CIDR,169.254.0.0/16,DIRECT,no-resolve", "IP-CIDR,100.64.0.0/10,DIRECT,no-resolve",
            "RULE-SET,cn-domain,DIRECT", "RULE-SET,cn-ip,DIRECT", f"MATCH,{settings.ai_group_name}",
        ],
    }


def xray_config(secret, settings):
    private_networks = ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "::1/128", "fc00::/7", "fe80::/10"]
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "personal-vpn", "listen": "0.0.0.0", "port": settings.reality_port, "protocol": "vless",
            "settings": {"clients": [{"id": secret["uuid"], "flow": "xtls-rprx-vision", "email": "personal"}], "decryption": "none"},
            "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {
                "show": False, "target": f"127.0.0.1:{settings.nginx_tls_port}", "xver": 0,
                "serverNames": ["", settings.server_ip], "privateKey": secret["private_key"], "shortIds": [secret["short_id"]],
            }},
        }],
        "outbounds": [{"tag": "internet", "protocol": "freedom", "settings": {"domainStrategy": "UseIPv4"}}, {"tag": "blocked", "protocol": "blackhole"}],
        "routing": {"domainStrategy": "IPIfNonMatch", "rules": [{"type": "field", "ip": private_networks, "outboundTag": "blocked"}]},
    }


def client_metadata(secret, settings, client):
    metadata = {
        "server": settings.server_ip, "ssh_user": settings.ssh_user, "ssh_key": settings.ssh_key,
        "subscription_url": f"{settings.https_origin}/sub/{secret['subscription_token']}/config.yaml",
        "uuid": secret["uuid"], "public_key": secret["public_key"], "short_id": secret["short_id"],
        "tls_name": settings.server_ip, "xray_version": XRAY_VERSION,
        "nodes": client["proxies"], "deployment": settings.as_dict(),
    }
    if len(client["proxies"]) > 1:
        from add_protocol_nodes import HY_VERSION
        metadata["hysteria_version"] = HY_VERSION
    return metadata



def ensure_credentials():
    secret_file = BASE / "secrets.json"
    if secret_file.exists():
        return json.loads(secret_file.read_text())
    raw = run(["/usr/local/bin/xray", "x25519"])
    fields = {key.strip(): value.strip() for key, value in (line.split(":", 1) for line in raw.splitlines() if ":" in line)}
    private_key = fields["PrivateKey"]
    private_bytes = base64.urlsafe_b64decode(private_key + "=" * (-len(private_key) % 4))
    if len(private_bytes) != 32:
        raise RuntimeError("Unexpected X25519 private key length")
    private_der = bytes.fromhex("302e020100300506032b656e04220420") + private_bytes
    derived = subprocess.run(["openssl", "pkey", "-inform", "DER", "-pubout", "-outform", "DER"], input=private_der, capture_output=True, check=True)
    if len(derived.stdout) != 44:
        raise RuntimeError("Unexpected X25519 public key encoding")
    secret = {
        "uuid": str(uuid.uuid4()), "subscription_token": secrets.token_urlsafe(32),
        "private_key": private_key,
        "public_key": base64.urlsafe_b64encode(derived.stdout[-32:]).decode().rstrip("="),
        "short_id": secrets.token_hex(8),
    }
    write(secret_file, json.dumps(secret, indent=2))
    return secret


def install_xray():
    binary = Path('/usr/local/bin/xray')
    record_path = BASE / 'release.json'
    record = json.loads(record_path.read_text()) if record_path.exists() else {}
    if binary.exists() and record.get('archive_sha256') == XRAY_SHA256 and record.get('binary_sha256') == hashlib.sha256(binary.read_bytes()).hexdigest():
        return False
    archive = download(f"https://github.com/XTLS/Xray-core/releases/download/v{XRAY_VERSION}/Xray-linux-64.zip")
    if hashlib.sha256(archive).hexdigest() != XRAY_SHA256:
        raise RuntimeError("Xray checksum mismatch")
    import io
    with zipfile.ZipFile(io.BytesIO(archive)) as package:
        content = package.read('xray')
    changed = write(binary, content, 0o755)
    run([str(binary), 'version'])
    write(record_path, json.dumps({'archive_sha256': XRAY_SHA256, 'binary_sha256': hashlib.sha256(content).hexdigest()}))
    return changed


def apply_nginx(site, transaction, certificate_changed=False, includes_changed=False):
    validate_nginx(site)
    changed = write('/etc/nginx/sites-available/self-vpn', site, 0o644)
    enabled = Path('/etc/nginx/sites-enabled/self-vpn')
    target = Path('/etc/nginx/sites-available/self-vpn')
    if not enabled.is_symlink() or enabled.readlink() != target:
        if enabled.exists() or enabled.is_symlink():
            enabled.unlink()
        enabled.symlink_to(target)
        changed = True
    default = Path('/etc/nginx/sites-enabled/default')
    if default.is_symlink():
        default.unlink()
        changed = True
    run(['nginx', '-t'])
    apply_service('nginx', changed or certificate_changed or includes_changed, transaction, reload_service=True)


def write_candidate(secret, settings, client):
    write(BASE / 'candidate.json', json.dumps(client, indent=2))
    write(BASE / 'candidate.yaml', dump_yaml(client))
    write(BASE / 'candidate-metadata.json', json.dumps(client_metadata(secret, settings, client), indent=2))


def prepare(settings, transaction):
    if os.geteuid() != 0:
        raise RuntimeError("Run as root")
    import platform
    import shutil
    if platform.system() != 'Linux' or platform.machine() not in ['x86_64', 'amd64']:
        raise RuntimeError('Deployment requires Linux amd64')
    for program in ['nginx', 'openssl', 'systemctl', '/snap/bin/certbot']:
        if not shutil.which(program):
            raise RuntimeError('Missing server prerequisite: ' + Path(program).name)
    modern_http2 = nginx_uses_http2_directive()
    multi_enabled = (BASE / 'multi-enabled').exists()
    if multi_enabled and not (BASE / 'extra-secrets.json').exists():
        raise RuntimeError('Restore missing multi-node credentials before deploying')
    binary_changed = install_xray()
    try:
        pwd.getpwnam('self-vpn')
    except KeyError:
        run(['useradd', '--system', '--user-group', '--no-create-home', '--shell', '/usr/sbin/nologin', 'self-vpn'])
    BASE.chmod(0o750)
    os.chown(BASE, 0, grp.getgrnam('self-vpn').gr_gid)
    DATA.mkdir(exist_ok=True)
    DATA.chmod(0o755)
    SUB.mkdir(exist_ok=True)
    SUB.chmod(0o750)
    os.chown(SUB, 0, grp.getgrnam('www-data').gr_gid)
    acme = DATA / 'acme'
    acme.mkdir(mode=0o755, exist_ok=True)
    acme.chmod(0o755)
    secret = ensure_credentials()
    config = xray_config(secret, settings)
    validate_xray(config)
    changed = write(BASE / 'xray.json', json.dumps(config, indent=2), 0o640, 'self-vpn')
    unit = """[Unit]
Description=Personal VPN Xray REALITY
After=network-online.target
Wants=network-online.target

[Service]
User=self-vpn
Group=self-vpn
ExecStart=/usr/local/bin/xray run -config /etc/self-vpn/xray.json
Restart=on-failure
RestartSec=3
LimitNOFILE=65536
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true

[Install]
WantedBy=multi-user.target
"""
    unit_changed = write('/etc/systemd/system/self-vpn.service', unit, 0o644)
    update_rules(force=False)
    certificate = Path(f'/etc/letsencrypt/live/{CERT_NAME}/fullchain.pem')
    apply_nginx(nginx_config(certificate.exists(), secret['subscription_token'], settings, modern_http2), transaction)
    cert_matches = certificate.exists() and all(subprocess.run(args, capture_output=True).returncode == 0 for args in [
        ['openssl', 'x509', '-in', str(certificate), '-noout', '-checkip', settings.server_ip],
        ['openssl', 'x509', '-in', str(certificate), '-noout', '-checkend', '0'],
    ])
    if not cert_matches:
        if Path('/etc/letsencrypt/renewal-hooks/deploy/self-vpn-nginx').exists():
            transaction.touch_service('nginx')
            transaction.touch_service('self-vpn-extra')
        args = ['/snap/bin/certbot', 'certonly', '--non-interactive', '--agree-tos', '--register-unsafely-without-email', '--webroot', '--webroot-path', str(DATA / 'acme'), '--ip-address', settings.server_ip, '--preferred-profile', 'shortlived', '--cert-name', CERT_NAME]
        if certificate.exists():
            args.append('--force-renewal')
        run(args, timeout=300)
    apply_nginx(nginx_config(True, secret['subscription_token'], settings, modern_http2), transaction, certificate_changed=not cert_matches)
    if not multi_enabled:
        write('/etc/letsencrypt/renewal-hooks/deploy/self-vpn-nginx', '#!/bin/sh\nset -eu\n/usr/sbin/nginx -t\n/bin/systemctl reload nginx\n', 0o755)
    apply_service('self-vpn', changed or unit_changed or binary_changed, transaction, unit_changed=unit_changed)
    if multi_enabled:
        from add_protocol_nodes import install
        install(settings, transaction)
    else:
        write_candidate(secret, settings, client_config(secret, settings))
    print('Server configuration prepared; waiting for external verification.', flush=True)


def main():
    args = server_parser(__doc__).parse_args()
    from server_agent import run_action
    run_action('deploy', load_settings(args.config, environ={}))


if __name__ == '__main__':
    main()
