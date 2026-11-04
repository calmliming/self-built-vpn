#!/usr/bin/env python3
"""Check staged Git files for private deployment data before committing."""
import ipaddress
import json
import re
import subprocess
import sys

from settings import ROOT, parse_env


DNS_IPS = {"1.1.1.1", "8.8.8.8", "223.5.5.5", "119.29.29.29"}
PATTERNS = {
    "private key": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
    "AWS access key": r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
    "AWS resource ID": r"\b(?:sg|i)-[0-9a-f]{8,17}\b",
    "AWS account ID": r"\b[0-9]{12}\b",
    "private subscription token": r"/sub/[A-Za-z0-9_-]{24,}/",
    "UUID credential": r"\b[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\b",
    "personal home path": r"/(?:Users|home)/[A-Za-z0-9_.-]+/",
}
PRIVATE_PATHS = [".env", "deployment.env", "vpn.local.json", ".secrets/client.json", ".runtime/check.json", "使用与维护说明.txt", "vpn.pem", "private.key"]


def known_private_values(root):
    values = set()

    def visit(item):
        if isinstance(item, dict):
            for key, value in item.items():
                if key in {"server", "server_ip", "uuid", "username", "password", "obfs-password", "hysteria_obfs_password", "subscription_token", "subscription_url", "private_key", "public_key", "short_id", "public-key", "short-id", "aws_security_group_id", "aws_instance_id"} and isinstance(value, str) and len(value) >= 8:
                    values.add(value)
                else:
                    visit(value)
        elif isinstance(item, list):
            for value in item:
                visit(value)

    for path in [root / "vpn.local.json", root / ".secrets/client.json"]:
        if path.exists():
            visit(json.loads(path.read_text()))
    path = root / '.env'
    if path.exists():
        environment = parse_env(path.read_text(encoding='utf-8-sig'))
        for key in ['VPN_SERVER_IP', 'VPN_AWS_SECURITY_GROUP_ID', 'VPN_AWS_INSTANCE_ID']:
            if len(environment.get(key, '')) >= 8:
                values.add(environment[key])
    return values


def scan_text(text, private_values=()):
    reasons = [label for label, pattern in PATTERNS.items() if re.search(pattern, text)]
    if any(value in text for value in private_values):
        reasons.append("value from local private configuration")
    for raw in re.findall(r"(?<![\d.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![\d.])", text):
        try:
            address = ipaddress.IPv4Address(raw)
        except ipaddress.AddressValueError:
            continue
        if address.is_global and not address.is_multicast and raw not in DNS_IPS:
            reasons.append("non-example public IPv4 address")
            break
    return reasons


def check_repository(root):
    files = subprocess.check_output(["git", "ls-files", "--cached", "-z"], cwd=root).decode().split("\0")
    files = [name for name in files if name]
    if not files:
        raise ValueError("No staged/tracked files to check; stage the public source files first")
    errors = []
    for path in PRIVATE_PATHS:
        result = subprocess.run(["git", "check-ignore", "-q", "--", path], cwd=root)
        if result.returncode != 0:
            errors.append(f"{path}: private file is not protected by .gitignore, or is already tracked")
    private_values = known_private_values(root)
    for name in files:
        ignored = subprocess.run(["git", "check-ignore", "-q", "--no-index", "--", name], cwd=root)
        if ignored.returncode == 0:
            errors.append(f"{name}: tracked file matches private/runtime ignore rules")
        data = subprocess.check_output(["git", "show", ":" + name], cwd=root)
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            errors.append(f"{name}: binary file requires manual review")
            continue
        if "\0" in text:
            errors.append(f"{name}: binary file requires manual review")
            continue
        for reason in scan_text(text, private_values):
            errors.append(f"{name}: {reason}")
    return len(files), errors


def main():
    try:
        count, errors = check_repository(ROOT)
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f"Repository check failed: {error}", file=sys.stderr)
        return 1
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print(f"PASS: {count} staged/tracked text files checked; private files are ignored.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
