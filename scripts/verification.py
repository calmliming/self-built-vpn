"""Use an isolated Mihomo client to verify real public node connections."""
import base64
from concurrent.futures import ThreadPoolExecutor
import copy
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request
from urllib.parse import quote, urlsplit

from operations import write
from settings import ROOT


def preflight(settings, executable=None, interface=None):
    interface = interface or settings.verification_interface
    if not interface:
        raise ValueError('Set verification_interface to the physical network interface before deployment')
    socket.if_nametoindex(interface)
    executable = executable or shutil.which('mihomo') or ROOT / '.runtime/mihomo'
    executable = Path(executable).expanduser().resolve()
    if not executable.is_file() or not os.access(executable, os.X_OK) or not shutil.which('curl'):
        raise ValueError('Public verification requires an existing Mihomo binary and curl')
    result = subprocess.run([str(executable), '-v'], capture_output=True, timeout=10)
    if result.returncode:
        raise ValueError('The configured Mihomo binary did not start')
    return executable, interface


def validate_packet(packet, settings, digest=None):
    content = base64.b64decode(packet['yaml'], validate=True)
    if hashlib.sha256(content).hexdigest() != packet['digest'] or (digest and digest != packet['digest']):
        raise ValueError('Candidate changed before external verification')
    configuration = packet['configuration']
    nodes = configuration.get('proxies', [])
    ports = settings.node_ports
    if len(nodes) not in [1, len(settings.node_names)]:
        raise ValueError('Unexpected number of candidate nodes')
    for node, name, port in zip(nodes, settings.node_names, ports):
        if (node['server'], node['name'], node['port']) != (settings.server_ip, name, port):
            raise ValueError('Candidate node differs from local settings')
    metadata = packet['metadata']
    url = urlsplit(metadata['subscription_url'])
    if metadata['server'] != settings.server_ip or url.scheme != 'https' or url.hostname != settings.server_ip or (url.port or 443) != settings.reality_port or url.username or url.password:
        raise ValueError('Candidate subscription address differs from local settings')
    return configuration


def https_request(url, folder, label, interface=None, proxy=None):
    output = Path(folder) / (label + '.body')
    command = ['curl', '--silent', '--show-error', '--connect-timeout', '10', '--max-time', '25', '--max-filesize', '8000000', '--output', str(output), '--write-out', '%{json}']
    if proxy:
        command += ['--proxy', proxy, '--noproxy', '']
    else:
        command += ['--noproxy', '*', '--interface', interface]
    result = subprocess.run(command + [url], capture_output=True, text=True, timeout=30)
    try:
        metrics = json.loads(result.stdout)
    except ValueError:
        metrics = {}
    if result.returncode or metrics.get('ssl_verify_result') != 0:
        raise RuntimeError('HTTPS verification failed: ' + label)
    return ({'http': metrics['http_code'], 'tls_verify': metrics['ssl_verify_result'], 'seconds': round(metrics['time_total'], 3)}, output.read_bytes())


def verify_published(packet, settings, interface):
    validate_packet(packet, settings)
    with tempfile.TemporaryDirectory(prefix='subscription-verify-') as folder:
        metrics, content = https_request(packet['metadata']['subscription_url'], folder, 'subscription', interface=interface)
    if metrics['http'] != 200 or hashlib.sha256(content).hexdigest() != packet['digest']:
        raise RuntimeError('Published subscription differs from the verified candidate')
    return metrics


def _ports(count):
    held = []
    try:
        for _ in range(count):
            listener = socket.socket()
            listener.bind(('127.0.0.1', 0))
            held.append(listener)
        return [listener.getsockname()[1] for listener in held]
    finally:
        for listener in held:
            listener.close()


def _dns_probe(port):
    identifier = secrets.randbelow(65536)
    query = struct.pack('!6H', identifier, 0x0100, 1, 0, 0, 0)
    query += b''.join(bytes([len(label)]) + label.encode() for label in 'www.baidu.com'.split('.')) + b'\0'
    query += struct.pack('!HH', 1, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
        connection.settimeout(8)
        connection.sendto(query, ('127.0.0.1', port))
        response, _ = connection.recvfrom(4096)
    header = struct.unpack('!6H', response[:12])
    if header[0] != identifier or header[1] & 15 or header[3] == 0:
        raise RuntimeError('Client DNS verification failed')


@contextmanager
def _proxy_tls(node, interface):
    if not node.get('tls') or node.get('skip-cert-verify'):
        raise ValueError('HTTP and SOCKS5 endpoints require verified TLS')
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection.settimeout(10)
    try:
        if interface:
            if sys.platform == 'darwin':
                connection.setsockopt(socket.IPPROTO_IP, 25, socket.if_nametoindex(interface))  # Darwin IP_BOUND_IF
            elif hasattr(socket, 'SO_BINDTODEVICE'):
                connection.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode() + b'\0')
            else:
                raise RuntimeError('Cannot bind proxy authentication checks to the physical interface')
        connection.connect((node['server'], node['port']))
        with ssl.create_default_context().wrap_socket(connection, server_hostname=node.get('sni', node['server'])) as secured:
            yield secured
    finally:
        connection.close()


def _read_exact(connection, count):
    content = b''
    while len(content) < count:
        chunk = connection.recv(count - len(content))
        if not chunk:
            raise RuntimeError('Proxy closed the authentication exchange')
        content += chunk
    return content


def verify_proxy_authentication(node, interface):
    if node['type'] == 'http':
        for wrong_password in [False, True]:
            with _proxy_tls(node, interface) as connection:
                authorization = ''
                if wrong_password:
                    encoded = base64.b64encode((node['username'] + ':__wrong_password__').encode()).decode()
                    authorization = 'Proxy-Authorization: Basic ' + encoded + '\r\n'
                request = 'CONNECT www.gstatic.com:443 HTTP/1.1\r\nHost: www.gstatic.com:443\r\n' + authorization + '\r\n'
                connection.sendall(request.encode())
                line = b''
                while not line.endswith(b'\r\n') and len(line) < 4096:
                    line += _read_exact(connection, 1)
                status = line.split()
                if len(status) < 2 or status[1] != b'407':
                    raise RuntimeError('HTTP proxy did not reject missing or incorrect credentials')
    elif node['type'] == 'socks5':
        with _proxy_tls(node, interface) as connection:
            connection.sendall(b'\x05\x01\x00')
            if _read_exact(connection, 2) != b'\x05\xff':
                raise RuntimeError('SOCKS5 proxy allowed authentication without a password')
        with _proxy_tls(node, interface) as connection:
            connection.sendall(b'\x05\x01\x02')
            if _read_exact(connection, 2) != b'\x05\x02':
                raise RuntimeError('SOCKS5 proxy did not require password authentication')
            username = node['username'].encode()
            password = b'__wrong_password__'
            connection.sendall(bytes([1, len(username)]) + username + bytes([len(password)]) + password)
            response = _read_exact(connection, 2)
            if response[0] != 1 or response[1] == 0:
                raise RuntimeError('SOCKS5 proxy accepted an incorrect password')
    else:
        raise ValueError('Unexpected authenticated proxy type')
    return {'tls_verified': True, 'unauthenticated_rejected': True, 'wrong_password_rejected': True}


def verify_profile(packet, settings, executable, interface, artifact_dir=None):
    configuration = copy.deepcopy(validate_packet(packet, settings))
    mixed, controller, dns = _ports(3)
    controller_secret = secrets.token_urlsafe(24)
    names = [node['name'] for node in configuration['proxies']]
    for node in configuration['proxies']:
        node['interface-name'] = interface
    configuration.update({'mixed-port': mixed, 'external-controller': f'127.0.0.1:{controller}', 'secret': controller_secret,
                          'interface-name': interface, 'allow-lan': False, 'bind-address': '127.0.0.1', 'log-level': 'info'})
    configuration['tun'] = {'enable': False}
    configuration['dns']['listen'] = f'127.0.0.1:{dns}'
    # Keep the actual DNS, routing and fallback configuration for the acceptance test.
    folder_root = Path(artifact_dir) if artifact_dir else ROOT / '.runtime'
    folder_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    folder_root.chmod(0o700)
    report = {'tested_at': datetime.now(timezone.utc).isoformat(timespec='seconds'), 'interface': interface,
              'candidate_digest': packet['digest'], 'nodes_sha256': hashlib.sha256(json.dumps(packet['metadata'].get('nodes', packet['configuration']['proxies']), sort_keys=True).encode()).hexdigest(),
              'verified': False, 'nodes': {}}
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def api(path, value=None):
        request = urllib.request.Request(f'http://127.0.0.1:{controller}' + path,
            data=json.dumps(value).encode() if value is not None else None,
            headers={'Content-Type': 'application/json', 'Authorization': 'Bearer ' + controller_secret},
            method='PUT' if value is not None else 'GET')
        with opener.open(request, timeout=5) as response:
            content = response.read()
            return json.loads(content) if content else None

    try:
        with tempfile.TemporaryDirectory(prefix='verify-', dir=folder_root) as folder:
            folder = Path(folder)
            config_path = folder / 'config.json'
            write(config_path, json.dumps(configuration))
            check = subprocess.run([str(executable), '-t', '-d', str(folder), '-f', str(config_path)], capture_output=True, timeout=20)
            if check.returncode:
                write(folder_root / 'last-verification.log', check.stdout + check.stderr)
                raise RuntimeError('Mihomo rejected the candidate configuration')
            log_path = folder / 'mihomo.log'
            with log_path.open('wb') as log:
                log_path.chmod(0o600)
                process = subprocess.Popen([str(executable), '-d', str(folder), '-f', str(config_path)], stdout=log, stderr=subprocess.STDOUT)
                try:
                    deadline = time.monotonic() + 35
                    while True:
                        if process.poll() is not None:
                            raise RuntimeError('Verification client exited during startup')
                        try:
                            providers = api('/providers/rules')['providers']
                            if len(providers) == 2 and all(p.get('ruleCount', 0) > 0 for p in providers.values()):
                                break
                        except (OSError, ValueError, KeyError):
                            pass
                        if time.monotonic() >= deadline:
                            raise RuntimeError('Client routing rules did not load')
                        time.sleep(0.2)
                    report['rule_counts'] = {name: provider['ruleCount'] for name, provider in providers.items()}
                    proxy = f'http://127.0.0.1:{mixed}'
                    metrics, _ = https_request(settings.https_origin + '/', folder, 'https-entry', interface=interface)
                    if metrics['http'] != 404:
                        raise RuntimeError('Unexpected HTTPS entry response')
                    report['https_entry'] = metrics
                    _dns_probe(dns)
                    report['dns'] = True
                    for node in configuration['proxies']:
                        if node['type'] in ['http', 'socks5']:
                            report.setdefault('authentication', {})[node['name']] = verify_proxy_authentication(node, interface)
                    for name in names:
                        api('/proxies/' + quote(settings.ai_group_name, safe=''), {'name': name})
                        with ThreadPoolExecutor(max_workers=2) as pool:
                            trace_future = pool.submit(https_request, 'https://www.cloudflare.com/cdn-cgi/trace', folder, 'trace', proxy=proxy)
                            health_future = pool.submit(https_request, settings.healthcheck_url, folder, 'health', proxy=proxy)
                            trace_metrics, body = trace_future.result()
                            health_metrics, _ = health_future.result()
                        trace = dict(line.split('=', 1) for line in body.decode().splitlines() if '=' in line)
                        if trace_metrics['http'] != 200 or trace.get('ip') != settings.server_ip or (settings.expected_exit_country and trace.get('loc') != settings.expected_exit_country) or not 200 <= health_metrics['http'] < 300:
                            raise RuntimeError('Public node verification failed: ' + name)
                        report['nodes'][name] = {'exit_ip': trace['ip'], 'country': trace.get('loc'), 'https': trace_metrics, 'health': health_metrics}
                        print('Verified public node: ' + name, flush=True)
                    api('/proxies/' + quote(settings.ai_group_name, safe=''), {'name': settings.auto_group_name if len(names) > 1 else names[0]})
                    metrics, _ = https_request('https://www.baidu.com/', folder, 'domestic', proxy=proxy)
                    if metrics['http'] != 200:
                        raise RuntimeError('Domestic routing verification failed')
                    routing_logs = log_path.read_text(errors='replace')
                    if not any('www.baidu.com:443' in line and 'DIRECT' in line for line in routing_logs.splitlines()):
                        raise RuntimeError('Domestic traffic did not use DIRECT')
                    report['domestic_direct'] = metrics
                    report['verified'] = True
                finally:
                    process.terminate()
                    try:
                        process.wait(timeout=8)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
                    write(folder_root / 'last-verification.log', log_path.read_bytes())
    except BaseException as error:
        report['error'] = str(error)
        raise
    finally:
        private = folder_root if artifact_dir else ROOT / '.secrets'
        private.mkdir(mode=0o700, exist_ok=True)
        private.chmod(0o700)
        write(private / 'last-verification.json', json.dumps(report, indent=2))
    return report
