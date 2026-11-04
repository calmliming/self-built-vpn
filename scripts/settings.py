"""Typed deployment settings read from .env and namespaced process variables."""
import argparse
from dataclasses import asdict, dataclass, fields
import ipaddress
import json
import os
from pathlib import Path
import re
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Settings:
    server_ip: str
    ssh_user: str = "ubuntu"
    ssh_key: str = "~/.ssh/vpn.pem"
    ssh_port: int = 22
    aws_region: str = "us-east-1"
    aws_security_group_id: str = ""
    aws_instance_id: str = ""
    node_prefix: str = "AWS-US"
    node_name_style: str = "protocol"
    ai_group_name: str = "US-AI"
    auto_group_name: str = "US-AUTO"
    rules_group_name: str = "US-RULES"
    reality_port: int = 443
    reality_alt_port: int = 20001
    trojan_port: int = 20002
    hysteria2_port: int = 20003
    hysteria2_obfs: str = ""
    http_port: int = 0
    socks5_port: int = 0
    nginx_tls_port: int = 8443
    healthcheck_url: str = "https://www.gstatic.com/generate_204"
    healthcheck_interval: int = 300
    healthcheck_timeout_ms: int = 8000
    verification_interface: str = ""
    expected_exit_country: str = "US"
    certificate_warning_hours: int = 48

    def __post_init__(self):
        for field in fields(self):
            value = getattr(self, field.name)
            if isinstance(value, str) and any(c in value for c in '\0\r\n'):
                raise ValueError(f'Control characters are not allowed in {field.name}')
        try:
            if not isinstance(self.server_ip, str):
                raise ValueError
            ipaddress.IPv4Address(self.server_ip)
        except (ipaddress.AddressValueError, ValueError):
            raise ValueError("server_ip must be an IPv4 address") from None
        patterns = {
            "ssh_user": r"[a-z_][a-z0-9_-]*",
            "node_name_style": r"(?:protocol|compact)",
            "hysteria2_obfs": r"(?:salamander)?",
            "aws_region": r"[a-z]{2}(?:-[a-z]+)+-[0-9]+",
            "aws_security_group_id": r"(?:sg-[0-9a-f]{8,17})?",
            "aws_instance_id": r"(?:i-[0-9a-f]{8,17})?",
            "verification_interface": r"[A-Za-z0-9_.-]{0,32}",
            "expected_exit_country": r"(?:[A-Z]{2})?",
        }
        for name, pattern in patterns.items():
            value = getattr(self, name)
            if not isinstance(value, str) or not re.fullmatch(pattern, value):
                raise ValueError(f"Invalid {name}")
        for name in ['node_prefix', 'ai_group_name', 'auto_group_name', 'rules_group_name']:
            value = getattr(self, name)
            if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9\u3400-\u9fff][A-Za-z0-9\u3400-\u9fff _·-]{0,39}', value) or value != value.strip():
                raise ValueError(f"Invalid {name}")
        group_names = [self.ai_group_name, self.auto_group_name, self.rules_group_name]
        if len(set(group_names)) != 3 or set(group_names) & (set(self.node_names) | {'DIRECT', 'REJECT', 'GLOBAL', 'PASS', 'COMPATIBLE'}):
            raise ValueError('Proxy group names must be unique and distinct from node and built-in names')
        if not isinstance(self.ssh_key, str) or not self.ssh_key or any(c in self.ssh_key for c in "\0\r\n"):
            raise ValueError("Invalid ssh_key path")
        for name in ["ssh_port", "reality_port", "reality_alt_port", "trojan_port", "hysteria2_port", "nginx_tls_port", "http_port", "socks5_port"]:
            value = getattr(self, name)
            minimum = 0 if name in ['http_port', 'socks5_port'] else 1
            if type(value) is not int or not minimum <= value <= 65535:
                raise ValueError(f"{name} must be an integer from {minimum} to 65535")
        tcp_ports = [80, self.ssh_port, self.nginx_tls_port, *self.tcp_proxy_ports]
        if len(set(tcp_ports)) != len(tcp_ports):
            raise ValueError("Configured TCP listeners must use distinct ports")
        for name in ["healthcheck_interval", "healthcheck_timeout_ms", "certificate_warning_hours"]:
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if not isinstance(self.healthcheck_url, str):
            raise ValueError("healthcheck_url must be an HTTPS URL")
        url = urlsplit(self.healthcheck_url)
        if url.scheme != "https" or not url.hostname or url.username or url.password:
            raise ValueError("healthcheck_url must be an HTTPS URL without credentials")

    @property
    def https_origin(self):
        suffix = "" if self.reality_port == 443 else f":{self.reality_port}"
        return f"https://{self.server_ip}{suffix}"

    @property
    def optional_proxy_ports(self):
        return [(label, kind, port) for label, kind, port in [
            ('HTTP', 'http', self.http_port), ('SOCKS5', 'socks5', self.socks5_port),
        ] if port]

    @property
    def tcp_proxy_ports(self):
        return [self.reality_port, self.reality_alt_port, self.trojan_port, *[port for _, _, port in self.optional_proxy_ports]]

    @property
    def node_ports(self):
        return [self.reality_port, self.reality_alt_port, self.trojan_port, self.hysteria2_port, *[port for _, _, port in self.optional_proxy_ports]]

    @property
    def node_names(self):
        if self.node_name_style == 'compact':
            return [f'{self.node_prefix}{number:02}' for number in range(1, len(self.node_ports) + 1)]
        return [
            f"{self.node_prefix}-REALITY",
            f"{self.node_prefix}-REALITY-{self.reality_alt_port}",
            f"{self.node_prefix}-TROJAN-{self.trojan_port}",
            f"{self.node_prefix}-HYSTERIA2-{self.hysteria2_port}",
        ] + [f'{self.node_prefix}-{label}-{port}' for label, _, port in self.optional_proxy_ports]

    def as_dict(self):
        return asdict(self)

    def ssh_args(self):
        return [
            "ssh", "-F", "/dev/null", "-i", str(Path(self.ssh_key).expanduser()),
            "-p", str(self.ssh_port), "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=12", f"{self.ssh_user}@{self.server_ip}",
        ]


ENV_FIELDS = {'VPN_' + field.name.upper(): field for field in fields(Settings)}


def _env_value(value, line):
    if not value or value.startswith('#'):
        return ''
    if value.startswith('"'):
        try:
            result, end = json.JSONDecoder().raw_decode(value)
        except ValueError:
            raise ValueError(f'Invalid quoted .env value on line {line}') from None
    elif value.startswith("'"):
        result = ''
        end = 1
        while end < len(value):
            char = value[end]
            if char == "'":
                end += 1
                break
            if char == '\\' and end + 1 < len(value) and value[end + 1] in ["'", '\\']:
                end += 1
                char = value[end]
            result += char
            end += 1
        else:
            raise ValueError(f'Unclosed .env quote on line {line}')
    else:
        return re.split(r'[ \t]+#', value, maxsplit=1)[0].rstrip()
    tail = value[end:].strip()
    if tail and not tail.startswith('#'):
        raise ValueError(f'Unexpected text after .env value on line {line}')
    return result


def parse_env(text):
    """Read flat KEY=value data; never source a shell or interpolate variables."""
    result = {}
    for number, line in enumerate(text.lstrip('\ufeff').splitlines(), 1):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        match = re.fullmatch(r'(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*(.*)', line)
        if not match:
            raise ValueError(f'Invalid .env assignment on line {number}')
        name, value = match.groups()
        if name in result:
            raise ValueError(f'Duplicate .env variable on line {number}: {name}')
        result[name] = _env_value(value, number)
    return result


def dump_env(settings):
    values = settings.as_dict()
    lines = ['# Private deployment settings. Keep this file out of Git.']
    for name, field in ENV_FIELDS.items():
        value = values[field.name]
        lines.append(name + '=' + (str(value) if type(value) is int else json.dumps(value, ensure_ascii=False)))
    return '\n'.join(lines) + '\n'


def load_settings(path=None, *, environ=None):
    environment = os.environ if environ is None else environ
    explicit = path or environment.get('SELF_VPN_ENV_FILE')
    selected = Path(explicit or ROOT / '.env').expanduser()
    try:
        raw = parse_env(selected.read_text(encoding='utf-8-sig'))
    except FileNotFoundError:
        if explicit or 'VPN_SERVER_IP' not in environment:
            raise ValueError(f'Config not found: {selected}. Copy .env.example to .env first.') from None
        raw = {}
    unknown = set(raw) - set(ENV_FIELDS)
    if unknown:
        raise ValueError('Unknown .env variables: ' + ', '.join(sorted(unknown)))
    raw.update({name: environment[name] for name in ENV_FIELDS if name in environment})
    if 'VPN_SERVER_IP' not in raw:
        raise ValueError('Missing required variable: VPN_SERVER_IP')
    values = {}
    for name, value in raw.items():
        if not isinstance(value, str):
            raise ValueError(f'{name} must be a string environment value')
        field = ENV_FIELDS[name]
        if field.type is int:
            if not re.fullmatch(r'[0-9]+', value):
                raise ValueError(f'{name} must be an integer')
            value = int(value)
        values[field.name] = value
    return Settings(**values)


def server_parser(description):
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('--env-file', '--config', dest='config', default='/etc/self-vpn/deployment.env', help='Private deployment .env file')
    return parser


def dump_yaml(value):
    """JSON is a YAML subset, so fresh installs do not require PyYAML."""
    try:
        import yaml
    except ImportError:
        return json.dumps(value, ensure_ascii=False, indent=2) + "\n"
    return yaml.safe_dump(value, allow_unicode=True, sort_keys=False)
