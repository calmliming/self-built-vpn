#!/usr/bin/env python3
"""Local deployment, verification, diagnostics and independent routing updates."""
import argparse
import json
import queue
import shlex
import subprocess
import sys
import threading
import time

from settings import ROOT, load_settings
from verification import preflight, validate_packet, verify_profile, verify_published
from operations import write


SOURCES = ['settings.py', 'operations.py', 'routing_rules.py', 'deploy_server.py', 'add_protocol_nodes.py', 'server_agent.py']
PREFIX = 'SELF_VPN_EVENT '
BOOTSTRAP = '''import json, os, pathlib, subprocess, sys, tempfile
os.umask(0o077)
payload = json.loads(sys.stdin.readline())
with tempfile.TemporaryDirectory(prefix="self-vpn-deploy-") as folder:
    directory = pathlib.Path(folder)
    for name, source in payload["files"].items():
        (directory / name).write_text(source, encoding="utf-8")
    sys.path.insert(0, str(directory))
    from settings import Settings, dump_env
    config = directory / "deployment.env"
    config.write_text(dump_env(Settings(**payload["settings"])), encoding="utf-8")
    result = subprocess.run([sys.executable, "-u", str(directory / "server_agent.py"), "--env-file", str(config), "--action", payload["action"]])
    raise SystemExit(result.returncode)
'''


def remote_payload(settings, action):
    return json.dumps({'settings': settings.as_dict(), 'action': action,
                       'files': {name: (ROOT / 'scripts' / name).read_text() for name in SOURCES}}) + '\n'


def remote_command(settings):
    return settings.ssh_args() + ['sudo -n python3 -u -c ' + shlex.quote(BOOTSTRAP)]


def read_remote(settings, action, check=True):
    result = subprocess.run(remote_command(settings), input=remote_payload(settings, action), capture_output=True, text=True, timeout=180)
    if check and result.returncode:
        folder = ROOT / '.runtime'
        folder.mkdir(mode=0o700, exist_ok=True)
        folder.chmod(0o700)
        write(folder / 'last-remote-error.log', result.stdout + result.stderr)
        raise RuntimeError('Remote operation failed; private details: .runtime/last-remote-error.log')
    try:
        return json.loads(result.stdout), result.returncode
    except ValueError:
        raise RuntimeError('Remote operation returned an invalid response') from None


def managed_action(settings, action, executable, interface):
    folder = ROOT / '.runtime'
    folder.mkdir(mode=0o700, exist_ok=True)
    folder.chmod(0o700)
    path = folder / 'last-deployment.log'
    received = queue.Queue()
    events = []
    with path.open('w') as log:
        path.chmod(0o600)
        process = subprocess.Popen(remote_command(settings), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)

        def pump():
            for line in process.stdout:
                log.write(line)
                log.flush()
                received.put(line)
                if line.startswith(PREFIX):
                    try:
                        events.append(json.loads(line[len(PREFIX):]))
                    except ValueError:
                        pass
            received.put(None)

        reader = threading.Thread(target=pump, daemon=True)
        reader.start()

        def receive(kind, timeout=600):
            deadline = time.monotonic() + timeout
            while True:
                try:
                    line = received.get(timeout=max(0, deadline - time.monotonic()))
                except queue.Empty:
                    raise RuntimeError('Remote deployment response timed out') from None
                if line is None:
                    raise RuntimeError('Remote deployment ended before ' + kind)
                if line.startswith(PREFIX):
                    event = json.loads(line[len(PREFIX):])
                    if event['event'] == kind:
                        return event
                    raise RuntimeError('Unexpected deployment state: ' + event['event'])
                # Keep detailed diagnostics private. Operational progress is concise.
                if line.startswith(('Server configuration prepared', 'Extra nodes prepared', 'Routing rules prepared')):
                    print(line.strip(), flush=True)

        proof = {}

        def send(action_name):
            process.stdin.write(json.dumps({'action': action_name, **proof}) + '\n')
            process.stdin.flush()

        try:
            process.stdin.write(remote_payload(settings, action))
            process.stdin.flush()
            ready = receive('ready')
            proof = {'nonce': ready['nonce'], 'digest': ready['digest']}
            packet, _ = read_remote(settings, 'export-current' if action == 'update-rules' else 'export-candidate')
            validate_packet(packet, settings, ready['digest'])
            verify_profile(packet, settings, executable, interface)
            if action in ['add-nodes', 'update-rules']:
                send('prepare')
            else:
                send('publish')
                published = receive('published', timeout=60)
                if {key: published[key] for key in ['nonce', 'digest']} != proof:
                    raise RuntimeError('Published candidate proof differs')
                verify_published(packet, settings, interface)
                send('commit')
            receive('done', timeout=60)
            process.stdin.close()
            if process.wait(timeout=30):
                raise RuntimeError('Remote deployment did not finish successfully')
            message = 'Routing rules verified; no service restart.' if action == 'update-rules' else ('Candidate verified and prepared.' if action == 'add-nodes' else 'Deployment verified and committed.')
            print(message, flush=True)
        except BaseException as error:
            if process.poll() is None:
                try:
                    send('abort')
                    process.stdin.close()
                except (OSError, ValueError):
                    pass
                try:
                    process.wait(timeout=90)
                except subprocess.TimeoutExpired:
                    process.terminate()
                    try:
                        process.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
            reader.join(timeout=3)
            rolled_back = any(item.get('event') == 'rolled-back' for item in events)
            if isinstance(error, KeyboardInterrupt):
                detail = 'Interrupted'
            else:
                detail = str(error)
            committed = any(item.get('event') == 'done' for item in events)
            not_started = any(item.get('event') == 'not-started' for item in events)
            state = 'server has committed; check its state with doctor' if committed else ('server did not apply the deployment' if not_started else ('server rollback completed' if rolled_back else 'check rollback status with doctor before retrying'))
            raise RuntimeError(detail + '; ' + state + '. Private log: .runtime/last-deployment.log') from None
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=15)
            reader.join(timeout=3)
            process.stdout.close()
            if not process.stdin.closed:
                process.stdin.close()


def fetch_client(settings):
    packet, _ = read_remote(settings, 'export-current')
    validate_packet(packet, settings)
    folder = ROOT / '.secrets'
    folder.mkdir(mode=0o700, exist_ok=True)
    folder.chmod(0o700)
    write(folder / 'client.json', json.dumps(packet['metadata'], indent=2))
    print('Private client metadata saved to .secrets/client.json')


def doctor(settings, interface):
    packet, code = read_remote(settings, 'doctor', check=False)
    for check in packet['checks']:
        print(('OK   ' if check['ok'] else 'FAIL ') + check['name'] + ': ' + check['detail'])
    try:
        if not interface:
            raise ValueError('Set verification_interface for the external subscription check')
        current, _ = read_remote(settings, 'export-current')
        metrics = verify_published(current, settings, interface)
        print('OK   public-subscription: HTTPS ' + str(metrics['http']) + ', certificate and content match')
    except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as error:
        print('FAIL public-subscription: ' + str(error))
        code = 1
    return code


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['check', 'deploy', 'add-nodes', 'publish', 'verify', 'doctor', 'update-rules', 'recover', 'fetch-client'])
    parser.add_argument('--env-file', '--config', dest='config', help='Defaults to .env or SELF_VPN_ENV_FILE')
    parser.add_argument('--mihomo', help='Path to an already installed Mihomo binary')
    parser.add_argument('--interface', help='Physical interface used for public verification')
    parser.add_argument('--candidate', action='store_true', help='Verify the private candidate instead of the published profile')
    args = parser.parse_args()
    try:
        settings = load_settings(args.config)
        if args.action == 'check':
            print('Deployment config valid. Required public inbound ports:')
            print(f'TCP: {settings.ssh_port} (SSH), 80 (ACME), {settings.reality_port} (REALITY/HTTPS), {settings.reality_alt_port} (REALITY), {settings.trojan_port} (Trojan)')
            for label, _, port in settings.optional_proxy_ports:
                print(f'TCP: {port} ({label} + TLS, authenticated)')
            print(f'UDP: {settings.hysteria2_port} (Hysteria2)')
            print(f'Internal only: 127.0.0.1:{settings.nginx_tls_port}')
        elif args.action == 'fetch-client':
            fetch_client(settings)
        elif args.action == 'doctor':
            return doctor(settings, args.interface or settings.verification_interface)
        elif args.action == 'recover':
            read_remote(settings, 'recover')
            print('Pending deployment recovery completed.')
        else:
            executable, interface = preflight(settings, args.mihomo, args.interface)
            if args.action == 'verify':
                packet, _ = read_remote(settings, 'export-candidate' if args.candidate else 'export-current')
                verify_profile(packet, settings, executable, interface)
                if not args.candidate:
                    verify_published(packet, settings, interface)
                print('Public verification passed.')
            else:
                managed_action(settings, args.action, executable, interface)
    except (ValueError, OSError, RuntimeError, subprocess.SubprocessError) as error:
        print('Error: ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
