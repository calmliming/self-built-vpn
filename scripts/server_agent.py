"""Server coordinator. Publication requires an external verifier's live handshake."""
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import select
import signal
import ssl
import subprocess
import sys

from operations import BASE, SUB, RENEW_TIMER, Transaction, state
from settings import load_settings, server_parser


PREFIX = 'SELF_VPN_EVENT '


def event(kind, **values):
    print(PREFIX + json.dumps({'event': kind, **values}), flush=True)


def wait_message(expected, nonce, digest, timeout=300):
    ready, _, _ = select.select([sys.stdin], [], [], timeout)
    if not ready:
        raise RuntimeError('External verification timed out')
    line = sys.stdin.readline(8193)
    if not line or len(line) > 8192:
        raise RuntimeError('External verifier disconnected')
    message = json.loads(line)
    if message != {'action': expected, 'nonce': nonce, 'digest': digest}:
        raise RuntimeError('External verification rejected or candidate proof differs')


def run_action(action, settings, receive=wait_message):
    if action in ['deploy', 'add-nodes', 'publish'] and (BASE / 'team-managed').exists():
        raise RuntimeError('Team credentials are managed by the web backend; use the team console to avoid overwriting member access')
    from add_protocol_nodes import install, publish, read_candidate
    from deploy_server import prepare
    old_handlers = {}

    def interrupt(number, frame):
        raise RuntimeError('Deployment interrupted; rolling back')

    transaction = None
    try:
        for number in [signal.SIGTERM, signal.SIGINT, signal.SIGHUP]:
            old_handlers[number] = signal.signal(number, interrupt)
        context = Transaction(paths=[SUB / 'cn-domain.mrs', SUB / 'cn-ip.mrs'], services=[], pause_renewal=False) if action == 'update-rules' else Transaction()
        with context as transaction:
            if action == 'deploy':
                prepare(settings, transaction)
            elif action == 'add-nodes':
                if (BASE / 'multi-enabled').exists():
                    old = json.loads((BASE / 'client.json').read_text())
                    ports = settings.node_ports
                    if old.get('server') != settings.server_ip or [(p['name'], p['port']) for p in old.get('nodes', [])] != list(zip(settings.node_names, ports)):
                        raise RuntimeError('Use deploy to change published multi-node addresses or ports')
                install(settings, transaction)
            elif action == 'update-rules':
                from routing_rules import update_rules
                update_rules()
                print('Routing rules prepared; waiting for external verification.', flush=True)
            elif action != 'publish':
                raise ValueError('Unknown deployment action')
            if action == 'update-rules':
                digest = export_profile(settings)['digest']
            else:
                _, _, digest = read_candidate(settings)
            nonce = secrets.token_hex(16)
            event('ready', nonce=nonce, digest=digest)
            if action in ['add-nodes', 'update-rules']:
                receive('prepare', nonce, digest)
            else:
                receive('publish', nonce, digest)
                publish(settings, digest)
                event('published', nonce=nonce, digest=digest)
                receive('commit', nonce, digest)
            transaction.commit()
        event('done')
    except BaseException:
        event('not-started' if transaction is None else ('rolled-back' if transaction.rolled_back else 'rollback-incomplete'))
        raise
    finally:
        for number, handler in old_handlers.items():
            signal.signal(number, handler)


def export_profile(settings, candidate=False):
    if candidate:
        from add_protocol_nodes import read_candidate
        configuration, metadata, digest = read_candidate(settings)
        content = (BASE / 'candidate.yaml').read_bytes()
    else:
        from add_protocol_nodes import profile
        from deploy_server import client_config
        metadata = json.loads((BASE / 'client.json').read_text())
        if metadata['server'] != settings.server_ip:
            raise RuntimeError('Published server differs from local settings')
        content = (SUB / 'config.yaml').read_bytes()
        try:
            configuration = json.loads(content)
        except (ValueError, UnicodeDecodeError):
            try:
                import yaml
            except ImportError:
                raise RuntimeError('Install PyYAML to read this legacy YAML subscription') from None
            configuration = yaml.safe_load(content)
        if not isinstance(configuration, dict):
            raise RuntimeError('Published subscription must contain a configuration object')
        secret = json.loads((BASE / 'secrets.json').read_text())
        expected = client_config(secret, settings)
        if len(metadata.get('nodes', [])) > 1:
            expected = profile(expected, json.loads((BASE / 'extra-secrets.json').read_text()), settings)
        expected_nodes = metadata.get('nodes') or expected['proxies']
        if expected_nodes != expected['proxies'] or configuration.get('proxies') != expected_nodes:
            raise RuntimeError('Published nodes differ from local settings')
        digest = hashlib.sha256(content).hexdigest()
    return {'configuration': configuration, 'metadata': metadata, 'yaml': base64.b64encode(content).decode(), 'digest': digest}


def doctor(settings):
    checks = []

    def record(name, ok, detail):
        checks.append({'name': name, 'ok': bool(ok), 'detail': detail})

    multi = (BASE / 'multi-enabled').exists()
    for service in ['nginx', 'self-vpn'] + (['self-vpn-extra', 'self-vpn-hysteria2'] if multi else []):
        record(service, state(service) == 'active', state(service))
    record('certificate-renewal-timer', state(RENEW_TIMER) == 'active', state(RENEW_TIMER))
    renewed = subprocess.run(['systemctl', 'show', 'snap.certbot.renew.service', '--property=Result', '--value'], capture_output=True, text=True, timeout=20)
    record('last-certificate-renewal', renewed.returncode == 0 and renewed.stdout.strip() == 'success', renewed.stdout.strip() or 'unknown')
    certificate = Path('/etc/letsencrypt/live/self-vpn-ip/fullchain.pem')
    try:
        result = subprocess.run(['openssl', 'x509', '-in', str(certificate), '-enddate', '-noout'], capture_output=True, text=True, check=True, timeout=10)
        expiry = ssl.cert_time_to_seconds(result.stdout.strip().split('=', 1)[1])
        hours = (expiry - datetime.now(timezone.utc).timestamp()) / 3600
        record('certificate-expiry', hours >= settings.certificate_warning_hours, f'{hours:.1f} hours remaining')
        result = subprocess.run(['openssl', 'x509', '-in', str(certificate), '-noout', '-checkip', settings.server_ip], capture_output=True, timeout=10)
        record('certificate-address', result.returncode == 0, 'matches configured IP' if result.returncode == 0 else 'mismatch')
    except (OSError, ValueError, subprocess.SubprocessError):
        record('certificate', False, 'missing or unreadable')
    result = subprocess.run(['ss', '-H', '-lntu'], capture_output=True, text=True, timeout=10)
    listeners = {'tcp': set(), 'udp': set()}
    internal_addresses = []
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) < 5 or fields[0] not in listeners:
            continue
        address, port = fields[4].rsplit(':', 1)
        if port.isdigit():
            listeners[fields[0]].add(int(port))
        if port == str(settings.nginx_tls_port):
            internal_addresses.append(address)
    required_tcp = [settings.ssh_port, 80, settings.reality_port] + (settings.tcp_proxy_ports[1:] if multi else [])
    record('tcp-listeners', set(required_tcp).issubset(listeners['tcp']), 'expected TCP ports: ' + ','.join(map(str, required_tcp)))
    if multi:
        record('udp-listener', settings.hysteria2_port in listeners['udp'], 'expected UDP port: ' + str(settings.hysteria2_port))
    record('nginx-private-listener', bool(internal_addresses) and all(a in ['127.0.0.1', '[::1]'] for a in internal_addresses), 'loopback only' if internal_addresses else 'missing')
    pending = []
    for path in (BASE / 'backups').glob('transaction-*/manifest.json'):
        if json.loads(path.read_text()).get('status') in ['pending', 'snapshotting', 'rollback-incomplete']:
            pending.append(path.parent.name)
    record('deployment-journal', not pending, 'no pending transaction' if not pending else 'uncommitted transaction requires recovery')
    return {'healthy': all(c['ok'] for c in checks), 'checks': checks}


def main():
    parser = server_parser(__doc__)
    parser.add_argument('--action', required=True, choices=['deploy', 'add-nodes', 'publish', 'update-rules', 'recover', 'doctor', 'export-current', 'export-candidate'])
    args = parser.parse_args()
    settings = load_settings(args.config, environ={})
    if os.geteuid() != 0:
        raise RuntimeError('Run the server coordinator as root')
    if args.action in ['export-current', 'export-candidate']:
        print(json.dumps(export_profile(settings, candidate=args.action == 'export-candidate')))
    elif args.action == 'doctor':
        report = doctor(settings)
        print(json.dumps(report))
        return 0 if report['healthy'] else 1
    elif args.action == 'recover':
        with Transaction(paths=[], services=[], pause_renewal=False) as transaction:
            transaction.commit()
        print(json.dumps({'recovered': True}))
    else:
        run_action(args.action, settings)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (RuntimeError, ValueError, OSError, subprocess.SubprocessError) as error:
        print('Deployment failed: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
