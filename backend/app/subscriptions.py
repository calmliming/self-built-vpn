import copy
import hashlib
import json
from .security import unseal

REGIONS = {'hk': '香港', 'sg': '新加坡', 'us': '美国'}

def preferred_names(nodes):
    """Keep region and backup order, putting every Hysteria2 endpoint first."""
    return [node['name'] for node in sorted(nodes, key=lambda node: node['type'] != 'hysteria2')]

def member_nodes(server, credentials):
    packet = unseal(server.packet_blob)
    nodes = copy.deepcopy(packet['configuration']['proxies'])
    for node in nodes:
        if node['type'] == 'vless':
            node['uuid'] = credentials['uuid']
        elif node['type'] == 'trojan':
            node['password'] = credentials['trojan_password']
        elif node['type'] == 'hysteria2':
            node['password'] = credentials['hysteria_password']
        elif node['type'] in ['http', 'socks5']:
            kind = node['type']
            node.update(username=credentials[kind + '_username'], password=credentials[kind + '_password'])
        else:
            raise ValueError('不支持的入口协议')
    return nodes

def rule_sources(configuration, us_ip):
    for key, provider in configuration['rule-providers'].items():
        provider['url'] = f'https://{us_ip}/team-rules/{key}.mrs'
        provider['path'] = f'./ruleset/self-vpn-{key}.mrs'

def server_packet(user, server, us):
    packet = copy.deepcopy(unseal(server.packet_blob))
    nodes = member_nodes(server, unseal(user.credential_blob)[server.id])
    packet['configuration']['proxies'] = nodes
    packet['metadata']['nodes'] = nodes
    rule_sources(packet['configuration'], us.ip)
    content = json.dumps(packet['configuration'], ensure_ascii=False, indent=2).encode()
    import base64
    packet.update(yaml=base64.b64encode(content).decode(), digest=hashlib.sha256(content).hexdigest())
    return packet

def fleet(user, servers):
    mapping = {s.id: s for s in servers}
    regions = json.loads(user.regions)
    exit_region = getattr(user, 'exit_region', None)
    if exit_region:
        if exit_region not in regions:
            raise ValueError('出口地区未授权')
        regions = [exit_region]
    credentials = unseal(user.credential_blob)
    result = copy.deepcopy(unseal(mapping['us'].packet_blob)['configuration'])
    result['proxies'] = [node for code in regions for node in member_nodes(mapping[code], credentials[code])]
    names = [node['name'] for node in result['proxies']]
    health = {'url': 'https://www.gstatic.com/generate_204', 'interval': 300, 'timeout': 8000}
    region_groups = [REGIONS[code] + '节点' for code in regions]
    result['proxy-groups'] = [
        {'name': '代理选择', 'type': 'select', 'proxies': ['地区自动回退', *region_groups, *names]},
        {'name': '地区自动回退', 'type': 'fallback', 'proxies': preferred_names(result['proxies']), **health},
    ]
    for code in regions:
        result['proxy-groups'].append({'name': REGIONS[code] + '节点', 'type': 'fallback',
            'proxies': preferred_names([n for n in result['proxies'] if n['server'] == mapping[code].ip]), **health})
    priority = {'hysteria2': 0, 'trojan': 1, 'vless': 2, 'http': 3, 'socks5': 4}
    result['proxy-groups'].append({'name': '规则下载', 'type': 'fallback', 'hidden': True,
        'proxies': [n['name'] for n in sorted(result['proxies'], key=lambda n: priority[n['type']])], **health})
    rule_sources(result, mapping['us'].ip)
    for provider in result['rule-providers'].values():
        provider['proxy'] = '规则下载'
    result['dns']['nameserver'] = [value.rsplit('#', 1)[0] + '#代理选择' for value in result['dns']['nameserver']]
    result['rules'] = [rule for rule in result['rules'] if not rule.startswith('MATCH,')]
    for server in servers:
        rule = f'IP-CIDR,{server.ip}/32,DIRECT,no-resolve'
        if rule not in result['rules']:
            result['rules'].insert(0, rule)
    result['rules'].append('MATCH,代理选择')
    return result

def subscription_url(user, us):
    return f'https://{us.ip}/team-sub/{unseal(user.token_blob)}/config.yaml'
