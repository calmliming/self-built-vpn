"""External authentication checks use an isolated, non-TUN Mihomo process."""
import json
from pathlib import Path
import secrets
import subprocess
import time
import urllib.request
from urllib.parse import quote
from .config import PROJECT
from .remote import settings_for
from .subscriptions import server_packet, member_nodes
from .security import unseal
from verification import verify_profile, _ports
from verification import https_request, _dns_probe

def verify_member(user, server, us, log_dir):
    settings = settings_for(server)
    packet = server_packet(user, server, us)
    return verify_profile(packet, settings, PROJECT / '.runtime' / 'mihomo', settings.verification_interface, artifact_dir=log_dir)

def verify_denied(user, server, log_dir):
    folder = Path(log_dir) / ('denial-' + server.id)
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    nodes = member_nodes(server, unseal(user.credential_blob)[server.id])
    mixed, controller = _ports(2)
    secret = secrets.token_urlsafe(24)
    config = {'mixed-port': mixed, 'allow-lan': False, 'bind-address': '127.0.0.1',
        'external-controller': f'127.0.0.1:{controller}', 'secret': secret, 'mode': 'rule',
        'tun': {'enable': False}, 'log-level': 'warning', 'proxies': nodes,
        'proxy-groups': [{'name': 'CHECK', 'type': 'select', 'proxies': [n['name'] for n in nodes]}], 'rules': ['MATCH,CHECK']}
    for node in config['proxies']:
        node['interface-name'] = settings_for(server).verification_interface
    path = folder / 'client.json'
    path.write_text(json.dumps(config)); path.chmod(0o600)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    report = {}
    with (folder / 'client.log').open('w') as output:
        process = subprocess.Popen([str(PROJECT / '.runtime/mihomo'), '-d', str(folder), '-f', str(path)], stdout=output, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 10
            while True:
                try:
                    with opener.open(urllib.request.Request(f'http://127.0.0.1:{controller}/version', headers={'Authorization': 'Bearer ' + secret}), timeout=1):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise RuntimeError('撤销验收客户端启动失败') from None
                    time.sleep(.1)
            for node in nodes:
                request = urllib.request.Request(f'http://127.0.0.1:{controller}/proxies/CHECK', data=json.dumps({'name': node['name']}).encode(), headers={'Authorization': 'Bearer ' + secret, 'Content-Type': 'application/json'}, method='PUT')
                with opener.open(request, timeout=3):
                    pass
                result = subprocess.run(['curl', '--silent', '--show-error', '--proxy', f'http://127.0.0.1:{mixed}', '--noproxy', '', '--max-time', '6', '--output', '/dev/null', '--write-out', '%{http_code}', 'https://www.gstatic.com/generate_204'], capture_output=True, text=True, timeout=8)
                if result.returncode == 0 and result.stdout == '204':
                    raise RuntimeError('旧凭据仍可连接：' + node['name'])
                report[node['name']] = {'denied': True}
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait()
    (folder / 'report.json').write_text(json.dumps(report))
    (folder / 'report.json').chmod(0o600)
    return report

def verify_fleet(configuration, servers, log_dir):
    """Load the actual combined subscription and exercise its groups and DNS."""
    import copy
    from .subscriptions import REGIONS
    folder = Path(log_dir)
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    mixed, controller, dns = _ports(3)
    secret = secrets.token_urlsafe(24)
    config = copy.deepcopy(configuration)
    config.update({'mixed-port': mixed, 'external-controller': f'127.0.0.1:{controller}',
        'secret': secret, 'tun': {'enable': False}, 'log-level': 'info'})
    interface = settings_for(servers[0]).verification_interface
    config['interface-name'] = interface
    for node in config['proxies']:
        node['interface-name'] = interface
    config['dns']['listen'] = f'127.0.0.1:{dns}'
    config_path = folder / 'client.json'
    config_path.write_text(json.dumps(config)); config_path.chmod(0o600)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    def api(path, value=None):
        request = urllib.request.Request(f'http://127.0.0.1:{controller}' + path, data=None if value is None else json.dumps(value).encode(),
            headers={'Authorization': 'Bearer ' + secret, 'Content-Type': 'application/json'}, method='GET' if value is None else 'PUT')
        with opener.open(request, timeout=3) as response:
            return json.loads(response.read() or '{}')
    report = {'verified': False, 'regions': {}}
    with (folder / 'client.log').open('w') as output:
        process = subprocess.Popen([str(PROJECT / '.runtime/mihomo'), '-d', str(folder), '-f', str(config_path)], stdout=output, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 40
            while True:
                try:
                    providers = api('/providers/rules')['providers']
                    if len(providers) == 2 and all(provider.get('ruleCount', 0) > 0 for provider in providers.values()):
                        break
                except (OSError, ValueError, KeyError):
                    pass
                if process.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError('组合订阅规则加载失败')
                time.sleep(.15)
            _dns_probe(dns)
            report['dns'] = True
            configured_ips = {node['server'] for node in config['proxies']}
            for server in servers:
                if server.ip not in configured_ips:
                    continue
                api('/proxies/' + quote('代理选择', safe=''), {'name': REGIONS[server.id] + '节点'})
                metrics, body = https_request('https://www.cloudflare.com/cdn-cgi/trace', folder, 'trace-' + server.id, proxy=f'http://127.0.0.1:{mixed}')
                trace = dict(line.split('=', 1) for line in body.decode().splitlines() if '=' in line)
                if metrics['http'] != 200 or trace.get('ip') != server.ip or trace.get('loc') != server.country:
                    raise RuntimeError('组合订阅地区出口不匹配')
                chosen = api('/proxies/' + quote(REGIONS[server.id] + '节点', safe='')).get('now')
                chosen_type = next((n['type'] for n in config['proxies'] if n['name'] == chosen), None)
                report['regions'][server.id] = {'exit_ip': trace['ip'], 'country': trace['loc'], 'tls_verified': True,
                                               'selected_node': chosen, 'selected_protocol': chosen_type}
            api('/proxies/' + quote('代理选择', safe=''), {'name': '地区自动回退'})
            metrics, body = https_request('https://www.cloudflare.com/cdn-cgi/trace', folder, 'automatic', proxy=f'http://127.0.0.1:{mixed}')
            trace = dict(line.split('=', 1) for line in body.decode().splitlines() if '=' in line)
            if metrics['http'] != 200 or trace.get('ip') not in configured_ips:
                raise RuntimeError('自动组出口不在订阅允许范围内')
            report['automatic'] = {'exit_ip': trace['ip'], 'country': trace.get('loc'),
                'selected_node': api('/proxies/' + quote('地区自动回退', safe='')).get('now')}
            metrics, _ = https_request('https://www.baidu.com/', folder, 'domestic', proxy=f'http://127.0.0.1:{mixed}')
            if metrics['http'] != 200 or not any('www.baidu.com:443' in line and 'DIRECT' in line for line in (folder / 'client.log').read_text().splitlines()):
                raise RuntimeError('组合订阅国内直连验收失败')
            report.update(verified=True, domestic_direct=True)
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait()
    (folder / 'report.json').write_text(json.dumps(report))
    (folder / 'report.json').chmod(0o600)
    return report
