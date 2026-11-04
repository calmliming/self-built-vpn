"""Bounded HTTPS downloads through a private client bound to the physical NIC."""
import copy
import json
import math
from pathlib import Path
import secrets
import subprocess
import tempfile
import time
import urllib.request

from .config import PROJECT, RUNTIME
from .remote import settings_for
from verification import _ports, preflight

PAYLOAD_BYTES = 3_000_000
TIMEOUT_SECONDS = 12
DOWNLOAD_URL = f'https://speed.cloudflare.com/__down?bytes={PAYLOAD_BYTES}'

def download_sample(proxy):
    # No user-supplied URL, redirects, curlrc, file output, or certificate bypass.
    command = ['curl', '--disable', '--silent', '--show-error', '--proto', '=https',
        '--proxy', proxy, '--noproxy', '', '--connect-timeout', '5',
        '--max-time', str(TIMEOUT_SECONDS), '--max-filesize', str(PAYLOAD_BYTES),
        '--output', '/dev/null', '--write-out', '%{json}', DOWNLOAD_URL]
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=TIMEOUT_SECONDS + 3)
        metrics = json.loads(completed.stdout)
        elapsed = float(metrics['time_total'])
        size = int(metrics['size_download'])
        http = int(metrics['http_code'])
        tls = int(metrics['ssl_verify_result'])
        valid = (http == 200 and tls == 0 and 0 < size <= PAYLOAD_BYTES
                 and math.isfinite(elapsed) and elapsed > 0)
        complete = valid and completed.returncode == 0 and size == PAYLOAD_BYTES
        timed_sample = valid and completed.returncode == 28
        measured = complete or timed_sample
        return {'status': 'complete' if complete else 'sampled' if timed_sample else 'failed',
            'mbps': round(size * 8 / elapsed / 1_000_000, 3) if measured else None,
            'bytes': size if measured else 0, 'seconds': round(elapsed, 3) if measured else None,
            'http_status': http, 'curl_exit': completed.returncode,
            'message': '完整下载' if complete else '达到时限，按已下载数据采样' if timed_sample else
                       '下载未通过，请检查节点或稍后重测'}
    except (subprocess.TimeoutExpired, ValueError, KeyError, TypeError, OSError):
        return {'status': 'failed', 'mbps': None, 'bytes': 0, 'seconds': None,
                'message': '下载未完成，请稍后重测'}

def measure_nodes(server, nodes, on_start):
    settings = settings_for(server)
    executable, interface = preflight(settings, PROJECT / '.runtime/mihomo')
    mixed, controller = _ports(2)
    secret = secrets.token_urlsafe(24)
    proxies = copy.deepcopy(nodes)
    for node in proxies:
        node['interface-name'] = interface
    config = {'mixed-port': mixed, 'allow-lan': False, 'bind-address': '127.0.0.1',
        'external-controller': f'127.0.0.1:{controller}', 'secret': secret,
        'interface-name': interface, 'mode': 'rule', 'ipv6': False, 'log-level': 'warning',
        'tun': {'enable': False}, 'dns': {'enable': False}, 'proxies': proxies,
        'proxy-groups': [{'name': 'SPEED', 'type': 'select', 'proxies': [n['name'] for n in proxies]}],
        'rules': ['MATCH,SPEED']}
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    def api(path, value=None):
        request = urllib.request.Request(f'http://127.0.0.1:{controller}' + path,
            data=json.dumps(value).encode() if value is not None else None,
            headers={'Authorization': 'Bearer ' + secret, 'Content-Type': 'application/json'},
            method='PUT' if value is not None else 'GET')
        with opener.open(request, timeout=2) as response:
            return response.read()
    with tempfile.TemporaryDirectory(prefix='speed-', dir=RUNTIME) as temp:
        folder = Path(temp)
        path = folder / 'client.json'
        path.write_text(json.dumps(config)); path.chmod(0o600)
        with (folder / 'client.log').open('wb') as log:
            process = subprocess.Popen([str(executable), '-d', str(folder), '-f', str(path)], stdout=log, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 10
                while True:
                    try:
                        api('/version')
                        break
                    except OSError:
                        if process.poll() is not None or time.monotonic() >= deadline:
                            raise RuntimeError('测速客户端启动失败') from None
                        time.sleep(.1)
                for node in proxies:
                    on_start(node)
                    api('/proxies/SPEED', {'name': node['name']})
                    yield node, download_sample(f'socks5h://127.0.0.1:{mixed}')
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait(timeout=5)
