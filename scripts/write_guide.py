#!/usr/bin/env python3
"""Generate a private guide from local settings, fetched metadata and real test results."""
import argparse
from datetime import datetime
import json
import hashlib
import os
from pathlib import Path
import shlex
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

from settings import ROOT, load_settings


def validation_notes(settings, folder, client=None):
    current = folder / 'last-verification.json'
    if current.exists() and client and client.get('nodes'):
        report = json.loads(current.read_text())
        fingerprint = hashlib.sha256(json.dumps(client['nodes'], sort_keys=True).encode()).hexdigest()
        if report.get('verified') and report.get('nodes_sha256') == fingerprint and set(report.get('nodes', {})) == {n['name'] for n in client['nodes']} and all(n.get('exit_ip') == settings.server_ip for n in report.get('nodes', {}).values()):
            stamp = datetime.fromisoformat(report['tested_at']).astimezone(ZoneInfo('Asia/Shanghai')).strftime('%Y-%m-%d %H:%M 中国标准时间')
            return f"最近公网验收：{stamp}，物理网卡 {report.get('interface', '未记录')}。{len(report['nodes'])} 个节点的 HTTPS 与出口检查通过；分流规则已加载，DNS 响应和国内 DIRECT 路由检查通过。此项验收未使用个人 AI API Key。"
    path = folder / "multi-wan-validation.json"
    if not path.exists():
        return "本地尚无四节点公网测试记录，请按 README 完成验证。"
    report = json.loads(path.read_text())
    nodes = report.get("nodes", {})
    ports = [settings.reality_port, settings.reality_alt_port, settings.trojan_port, settings.hysteria2_port]
    valid = all(
        nodes.get(name, {}).get("network_pass")
        and nodes[name].get("port") == port
        and nodes[name].get("checks", {}).get("trace", {}).get("ip") == settings.server_ip
        for name, port in zip(settings.node_names, ports)
    )
    if not valid:
        return "本地公网测试记录与当前参数不完全匹配，请重新验证。"
    trace = nodes[settings.node_names[0]]["checks"]["trace"]
    notes = f"公网测试记录：{report.get('tested_at', '时间未记录')}，网卡 {report.get('interface', '未记录')}。四个节点出口均为 {settings.server_ip}，国家 {trace.get('loc', '未记录')}、机房 {trace.get('colo', '未记录')}，HTTPS 连通性检查通过。"
    api_ok = all(nodes[name]["checks"].get(api, {}).get("http_code") == 401 for name in settings.node_names for api in ["openai", "anthropic"])
    if api_ok:
        notes += "\nOpenAI 和 Anthropic API 均返回缺少认证信息的 401；测试未使用个人 API Key，未验证账号权限或额度。"
    routing_path = folder / "multi-routing-validation.json"
    if routing_path.exists():
        routing = json.loads(routing_path.read_text())
        regular = routing.get("published-rules", {})
        fallback = routing.get("fallback-simulation", {})
        if regular.get("checks", {}).get("trace", {}).get("ip") == settings.server_ip and regular.get("checks", {}).get("domestic", {}).get("http") == 200:
            notes += f"\n完整规则配置测试：国内网站使用 DIRECT 并返回 HTTP 200，海外检测经 {settings.ai_group_name} 转发。"
        if fallback.get("auto_selected") == settings.node_names[1] and fallback.get("checks", {}).get("trace", {}).get("ip") == settings.server_ip:
            notes += f"\n独立客户端模拟主入口不可用时，{settings.auto_group_name} 切换到 {settings.node_names[1]}，出口检测通过。"
    return notes


def render_guide(settings, client, evidence):
    url = urlsplit(client["subscription_url"])
    if client.get("server") != settings.server_ip or url.scheme != "https" or url.hostname != settings.server_ip or (url.port or 443) != settings.reality_port:
        raise ValueError("Client metadata differs from local deployment settings; fetch it again")
    if client.get("deployment") and client["deployment"] != settings.as_dict():
        raise ValueError("Client metadata uses different deployment settings; deploy or restore matching settings first")
    nodes = client.get("nodes") or [{"name": settings.node_names[0], "type": "vless", "port": settings.reality_port}]
    expected_ports = settings.node_ports
    if len(nodes) not in [1, len(settings.node_names)] or any((node["name"], node["port"]) != (name, port) for node, name, port in zip(nodes, settings.node_names, expected_ports)):
        raise ValueError("Client node names or ports differ from local settings")
    multi = len(nodes) > 1
    selection = settings.auto_group_name if multi else settings.node_names[0]
    protocols = {"vless": "VLESS + REALITY / TCP", "trojan": "Trojan + TLS / TCP", "hysteria2": "Hysteria2 / UDP", "http": "HTTP + TLS / TCP", "socks5": "SOCKS5 + TLS / TCP"}
    table = "\n".join(f"{node['name']}    {protocols[node['type']]}    端口 {node['port']}" for node in nodes)
    udp_note = '\nHysteria2 已启用 Salamander 混淆。客户端须刷新原订阅以获取匹配参数；旧的 UDP 节点配置不再匹配。混淆无法保证所有网络都允许 UDP，连接异常时使用前三个 TCP 入口。\n' if multi and settings.hysteria2_obfs else ''
    ssh = shlex.join(["ssh", "-i", str(Path(settings.ssh_key).expanduser()), "-p", str(settings.ssh_port), f"{settings.ssh_user}@{settings.server_ip}"])
    aws = f"区域：{settings.aws_region}"
    if settings.aws_security_group_id:
        aws += f"，安全组：{settings.aws_security_group_id}"
    if settings.aws_instance_id:
        aws += f"，实例：{settings.aws_instance_id}"
    stamp = datetime.now(ZoneInfo("Asia/Shanghai")).strftime("%Y-%m-%d %H:%M 中国标准时间")
    text = f"""个人 VPN 使用与维护说明
生成时间：{stamp}

一 私人订阅链接

{client['subscription_url']}

链接含私人访问令牌，持有链接的人可以下载节点认证配置。将链接、此文件、.env 和 .secrets/ 保存在本地；Git 仓库只提交 .env.example 等公共源文件。

二 FlClash 导入与更新

1. 打开“配置”，点击右上角“＋”并选择“链接”。
2. 名称填写 {settings.ai_group_name}，链接填写第一节的完整地址，“age 私钥”留空，点击“提交”。
3. 选中 {settings.ai_group_name} 配置卡片，进入“代理”，在 {settings.ai_group_name} 策略组选择 {selection}。
4. “仪表盘”出站模式选择“规则”，开启服务、“虚拟网卡”和“系统代理”。
5. 已导入的用户刷新原配置即可；更新后核对一次 {settings.ai_group_name} 的选择。节点或策略组改名后，客户端可能需要重新选择。

SSH 私钥只用于服务器管理，不填写到 FlClash 的“age 私钥”中。国内和局域网流量使用 DIRECT，其他流量经 {settings.ai_group_name} 转发。首次导入需要等待规则文件下载完成。

三 节点与端口

出口 IPv4：{settings.server_ip}
{aws}

{table}
{udp_note}

主入口和 HTTPS 订阅共用 TCP {settings.reality_port}；内部 Nginx 仅监听 127.0.0.1:{settings.nginx_tls_port}，该内部端口不需要公网放行。TCP 80 用于 ACME 证书验证。AWS 安全组需按配置放行相应 TCP/UDP 入口。

四 配置与维护

本地项目：{ROOT}
本地私有配置：.env
公开配置模板：.env.example

检查本地参数：
python3 scripts/manage.py check

按当前参数部署或更新服务（只重启发生变化的服务，公网验收失败会回滚）：
python3 scripts/manage.py deploy

准备额外协议的候选配置：
python3 scripts/manage.py add-nodes

自动验证端口和候选节点后发布：
python3 scripts/manage.py publish

只读诊断和公网检查：
python3 scripts/manage.py doctor
python3 scripts/manage.py verify

独立更新分流规则（不重启代理服务）：
python3 scripts/manage.py update-rules

恢复上次中断的变更：
python3 scripts/manage.py recover

获取最新客户端参数并生成此说明：
python3 scripts/manage.py fetch-client
python3 scripts/write_guide.py

SSH 登录：
{ssh}

在服务器检查服务：
sudo systemctl status self-vpn self-vpn-extra self-vpn-hysteria2 nginx --no-pager

服务端配置：
/etc/self-vpn/deployment.env                    私有部署参数
/etc/self-vpn/xray.json                          主入口
/etc/self-vpn/extra-xray.json                    额外 REALITY 与 Trojan
/etc/self-vpn/hysteria.yaml                      Hysteria2
/etc/self-vpn/secrets.json                       主节点与订阅凭据
/etc/self-vpn/extra-secrets.json                 额外协议凭据
/etc/self-vpn/client.json                        已发布客户端参数
/etc/self-vpn/candidate.yaml                     未发布候选订阅
/etc/self-vpn/backups/                           受保护的变更快照与日志
/var/lib/self-vpn/subscription/config.yaml        已发布订阅

五 HTTPS 证书

使用 Let's Encrypt IP 证书，Certbot 定时检查续期；续期钩子同步证书并重新加载 Nginx 和额外 Xray 服务。Hysteria2 在 TLS 握手时读取最新证书。

检查续期定时器与证书：
sudo systemctl status snap.certbot.renew.timer --no-pager
sudo /snap/bin/certbot certificates --cert-name self-vpn-ip

续期演练：
sudo /snap/bin/certbot renew --cert-name self-vpn-ip --dry-run --run-deploy-hooks --no-random-sleep-on-renew

六 验证记录

{validation_notes(settings, evidence, client)}

测试记录反映记录时的网络状态。具体 AI 账号的登录、权限、额度及服务风控需另外核实。

七 地址、费用与备份

多协议入口共用一台服务器和一个出口 IP，出口信誉仍由该 IP 决定；IP 整体不可达时会同时受影响。自动分配的 AWS 公网 IPv4 在实例停止后再启动时可能变化；更换 IP 后需要修改本地参数、重新部署、重新签发匹配的证书并更新客户端链接。

AWS 实例、磁盘、IPv4 和出站流量按账户方案计费。备份 /etc/self-vpn、/etc/letsencrypt 和 SSH 私钥；不要将这些文件放进 GitHub 仓库。公开代码前运行 README 中的仓库检查命令。
"""
    if multi:
        text += f"""
八 自动切换

{settings.auto_group_name} 优先 Hysteria2，其余协议作为备用，顺序为：{' → '.join([settings.node_names[3], *settings.node_names[:3], *settings.node_names[4:]])}。
规则下载使用独立回退组 {settings.rules_group_name}，优先 Hysteria2，避免慢速 TCP 链路造成首次规则加载超时；它不改变 {settings.ai_group_name} 的日常流量选择。
检查地址：{settings.healthcheck_url}
检查间隔：{settings.healthcheck_interval} 秒，单次超时：{settings.healthcheck_timeout_ms} 毫秒。
可手动选择具体入口。网络限制 UDP 时优先使用 TCP 入口。健康检查针对一般网络连通性，无法覆盖所有 AI 账号访问限制。
"""
    return text


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--env-file', '--config', dest='config', help='Private deployment .env file')
    parser.add_argument("--client", type=Path, default=ROOT / ".secrets/client.json")
    args = parser.parse_args()
    settings = load_settings(args.config)
    client = json.loads(args.client.read_text())
    text = render_guide(settings, client, ROOT / ".secrets")
    destination = ROOT / "使用与维护说明.txt"
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(text)
    destination.chmod(0o600)
    print(str(destination))


if __name__ == "__main__":
    main()
