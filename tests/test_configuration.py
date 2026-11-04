import base64
from dataclasses import replace
import json
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from add_protocol_nodes import extra_xray_config, hysteria_config, profile
from deploy_server import client_config, client_metadata, nginx_config, nginx_uses_http2_directive, xray_config
from manage import BOOTSTRAP, remote_payload
from settings import Settings, dump_env, dump_yaml, load_settings
from write_guide import render_guide


SECRET = {
    "uuid": str(uuid.UUID(int=0)),
    "subscription_token": "test-only-token",
    "private_key": base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("="),
    "public_key": base64.urlsafe_b64encode(bytes(reversed(range(32)))).decode().rstrip("="),
    "short_id": "00" * 8,
}
EXTRA = {"trojan_password": "test-only-trojan-password", "hysteria_password": "test-only-hysteria-password"}


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.settings = Settings(
            server_ip="203.0.113.20", ssh_user="operator", ssh_key="~/.ssh/example key.pem",
            ssh_port=2222, node_prefix="美国自建", ai_group_name="美国AI",
            auto_group_name="自动切换", rules_group_name="规则下载", reality_port=1443,
            reality_alt_port=21001, trojan_port=21002, hysteria2_port=21003,
            nginx_tls_port=18443, healthcheck_interval=60, healthcheck_timeout_ms=4000,
        )

    def test_changed_address_and_ports_reach_every_client_endpoint(self):
        settings = self.settings
        single = client_config(SECRET, settings)
        multi = profile(single, EXTRA, settings)
        self.assertEqual(single["proxy-groups"][0]["proxies"], [settings.node_names[0]])
        self.assertEqual([p["name"] for p in multi["proxies"]], settings.node_names)
        self.assertEqual([p["port"] for p in multi["proxies"]], [1443, 21001, 21002, 21003])
        self.assertTrue(all(p["server"] == settings.server_ip for p in multi["proxies"]))
        self.assertTrue(all(p.get("sni", p.get("servername")) == settings.server_ip for p in multi["proxies"]))
        self.assertIn(f"IP-CIDR,{settings.server_ip}/32,DIRECT,no-resolve", multi["rules"])
        self.assertTrue(all(p["url"].startswith(settings.https_origin + "/sub/") for p in multi["rule-providers"].values()))
        self.assertTrue(all(p['proxy'] == settings.ai_group_name for p in single['rule-providers'].values()))
        self.assertTrue(all(p['proxy'] == settings.rules_group_name for p in multi['rule-providers'].values()))
        self.assertEqual(multi['rules'][-1], 'MATCH,' + settings.ai_group_name)
        self.assertTrue(all(url.endswith('#' + settings.ai_group_name) for url in multi['dns']['nameserver']))
        available = {node['name'] for node in multi['proxies']} | {group['name'] for group in multi['proxy-groups']}
        self.assertTrue(all(name in available for group in multi['proxy-groups'] for name in group['proxies']))
        self.assertEqual(multi['proxy-groups'][2]['proxies'], list(reversed(settings.node_names)))
        self.assertTrue(multi['proxy-groups'][2]['hidden'])
        self.assertEqual(multi["proxy-groups"][1]["proxies"], [settings.node_names[3], *settings.node_names[:3]])
        self.assertEqual(multi["proxy-groups"][1]["interval"], 60)
        self.assertEqual(multi["proxy-groups"][1]["timeout"], 4000)
        self.assertFalse(multi["proxies"][2]["skip-cert-verify"])
        self.assertFalse(multi["proxies"][3]["skip-cert-verify"])
        self.assertEqual(len(single["proxies"]), 1, "Building extra nodes must not mutate the original profile")

    def test_nginx_http2_syntax_matches_installed_version(self):
        for version, modern in [('1.24.0 (Ubuntu)', False), ('1.25.0', False), ('1.25.1', True), ('1.28.0 (Ubuntu)', True)]:
            with self.subTest(version=version):
                result = type('Result', (), {'stdout': '', 'stderr': 'nginx version: nginx/' + version})()
                with patch('deploy_server.subprocess.run', return_value=result):
                    detected = nginx_uses_http2_directive()
                self.assertEqual(detected, modern)
                site = nginx_config(True, SECRET['subscription_token'], self.settings, detected)
                if modern:
                    self.assertIn('ssl default_server;', site)
                    self.assertIn('http2 on;', site)
                else:
                    self.assertIn('ssl http2 default_server;', site)
                    self.assertNotIn('http2 on;', site)
        result = type('Result', (), {'stdout': '', 'stderr': 'unrecognized server'})()
        with patch('deploy_server.subprocess.run', return_value=result), self.assertRaisesRegex(RuntimeError, 'Nginx version'):
            nginx_uses_http2_directive()

    def test_server_listeners_and_reality_target_follow_settings(self):
        main = xray_config(SECRET, self.settings)
        extra = extra_xray_config(main, EXTRA, self.settings)
        hy = hysteria_config(EXTRA, self.settings)
        nginx = nginx_config(True, SECRET["subscription_token"], self.settings)
        self.assertEqual(main["inbounds"][0]["port"], 1443)
        self.assertEqual([i["port"] for i in extra["inbounds"]], [21001, 21002])
        reality = extra["inbounds"][0]["streamSettings"]["realitySettings"]
        self.assertEqual(reality["target"], "127.0.0.1:18443")
        self.assertIn(self.settings.server_ip, reality["serverNames"])
        self.assertEqual(hy["listen"], "0.0.0.0:21003")
        self.assertEqual(hy["auth"]["password"], EXTRA["hysteria_password"])
        self.assertIn("listen 127.0.0.1:18443 ssl", nginx)
        self.assertIn(f"server_name {self.settings.server_ip};", nginx)
        self.assertNotIn("listen 0.0.0.0:18443", nginx)
        self.assertEqual(main["inbounds"][0]["port"], 1443)

    def test_compact_names_and_obfuscation_match_between_client_and_server(self):
        settings = replace(self.settings, node_prefix='弗州', node_name_style='compact', hysteria2_obfs='salamander')
        extra = {**EXTRA, 'hysteria_obfs_password': 'test-only-obfuscation-password'}
        client = profile(client_config(SECRET, settings), extra, settings)
        server = hysteria_config(extra, settings)
        self.assertEqual([node['name'] for node in client['proxies']], ['弗州01', '弗州02', '弗州03', '弗州04'])
        self.assertEqual(client['proxies'][3]['obfs'], server['obfs']['type'])
        self.assertEqual(client['proxies'][3]['obfs-password'], server['obfs']['salamander']['password'])
        self.assertEqual(client['proxies'][3]['password'], EXTRA['hysteria_password'])
        self.assertNotIn('obfs', hysteria_config(EXTRA, self.settings))
        self.assertNotIn('obfs', profile(client_config(SECRET, self.settings), EXTRA, self.settings)['proxies'][3])

    def test_optional_http_and_socks_use_tls_and_matching_required_credentials(self):
        settings = replace(self.settings, node_prefix='弗州', node_name_style='compact', http_port=23004, socks5_port=23005)
        extra = {**EXTRA, 'http_username': 'test-http-user', 'http_password': 'test-http-password',
                 'socks5_username': 'test-socks-user', 'socks5_password': 'test-socks-password'}
        client = profile(client_config(SECRET, settings), extra, settings)
        server = extra_xray_config(xray_config(SECRET, settings), extra, settings)
        self.assertEqual([node['name'] for node in client['proxies']], ['弗州01', '弗州02', '弗州03', '弗州04', '弗州05', '弗州06'])
        self.assertEqual([node['port'] for node in client['proxies']], settings.node_ports)
        for node, inbound in zip(client['proxies'][4:], server['inbounds'][2:]):
            self.assertTrue(node['tls'])
            self.assertFalse(node['skip-cert-verify'])
            self.assertEqual(inbound['streamSettings']['security'], 'tls')
            self.assertEqual(inbound['settings']['accounts'], [{'user': node['username'], 'pass': node['password']}])
            self.assertEqual(inbound['port'], node['port'])
        self.assertEqual(server['inbounds'][3]['settings']['auth'], 'password')
        self.assertFalse(server['inbounds'][3]['settings']['udp'])
        self.assertFalse(client['proxies'][5]['udp'])
        names = set(settings.node_names) | {group['name'] for group in client['proxy-groups']}
        self.assertTrue(all(name in names for group in client['proxy-groups'] for name in group['proxies']))
        metadata = client_metadata(SECRET, settings, client)
        with tempfile.TemporaryDirectory() as folder:
            guide = render_guide(settings, metadata, Path(folder))
        self.assertIn('弗州06', guide)
        self.assertIn('SOCKS5 + TLS', guide)

    def test_metadata_and_guide_follow_private_settings(self):
        settings = self.settings
        multi = profile(client_config(SECRET, settings), EXTRA, settings)
        metadata = client_metadata(SECRET, settings, multi)
        self.assertTrue(metadata["subscription_url"].startswith(settings.https_origin + "/sub/"))
        self.assertEqual(metadata["deployment"], settings.as_dict())
        with tempfile.TemporaryDirectory() as folder:
            text = render_guide(settings, metadata, Path(folder))
        self.assertIn(settings.server_ip, text)
        self.assertIn(settings.auto_group_name, text)
        self.assertIn("21003", text)
        self.assertIn("本地尚无四节点公网测试记录", text)
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(ValueError):
                render_guide(replace(settings, server_ip="198.51.100.20"), metadata, Path(folder))

    def test_invalid_configuration_fails_before_remote_execution(self):
        for change in [
            {"server_ip": "example.invalid"}, {"server_ip": "::1"}, {"server_ip": 123},
            {"trojan_port": 1443}, {"reality_port": 80}, {"ssh_port": 18443},
            {"hysteria2_port": True}, {"hysteria2_port": 65536},
            {"http_port": 1443}, {"socks5_port": -1}, {"http_port": True},
            {"http_port": 23004, "socks5_port": 23004},
            {"ssh_user": "user;bad"}, {"node_prefix": "bad\nname"},
            {"node_name_style": "unknown"}, {"hysteria2_obfs": "unknown"},
            {"ai_group_name": "美国AI,REJECT"}, {"auto_group_name": "美国AI"},
            {"rules_group_name": "DIRECT"}, {"ai_group_name": self.settings.node_names[0]},
            {"healthcheck_url": "http://example.invalid"}, {"healthcheck_interval": 0},
        ]:
            with self.subTest(fields=list(change)), self.assertRaises(ValueError):
                replace(self.settings, **change)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "config.env"
            path.write_text('VPN_SERVER_IP=203.0.113.20\nUNEXPECTED=true\n')
            with self.assertRaises(ValueError):
                load_settings(path,environ={})
            path.write_text(dump_env(self.settings))
            self.assertEqual(load_settings(path,environ={}), self.settings)

    def test_standard_https_port_and_ssh_paths_with_spaces(self):
        self.assertEqual(Settings(server_ip="203.0.113.20").https_origin, "https://203.0.113.20")
        self.assertEqual(self.settings.https_origin, "https://203.0.113.20:1443")
        args = self.settings.ssh_args()
        self.assertEqual(args[args.index("-i") + 1], str(Path(self.settings.ssh_key).expanduser()))
        self.assertEqual(args[-1], "operator@203.0.113.20")

    def test_remote_job_contains_settings_and_all_module_dependencies(self):
        observed = {}

        def inspect_run(command, **kwargs):
            config = Path(command[command.index("--env-file") + 1])
            observed["settings"] = load_settings(config,environ={}).as_dict()
            observed["files"] = {p.name for p in config.parent.iterdir()}
            observed["publish"] = command[command.index("--action") + 1]
            self.assertEqual(config.stat().st_mode & 0o777, 0o600)
            return type('Result', (), {'returncode': 0})()

        with patch("subprocess.run", side_effect=inspect_run), patch('sys.stdin', io.StringIO(remote_payload(self.settings, 'publish'))):
            with self.assertRaises(SystemExit) as finished:
                exec(compile(BOOTSTRAP, "remote-job", "exec"), {})
            self.assertEqual(finished.exception.code, 0)
        self.assertEqual(observed["settings"], self.settings.as_dict())
        self.assertTrue({"settings.py", "operations.py", "routing_rules.py", "deploy_server.py", "add_protocol_nodes.py", "server_agent.py"}.issubset(observed["files"]))
        self.assertEqual(observed["publish"], "publish")

    def test_yaml_fallback_remains_valid_client_configuration(self):
        multi = profile(client_config(SECRET, self.settings), EXTRA, self.settings)
        with patch.dict(sys.modules, {"yaml": None}):
            self.assertEqual(json.loads(dump_yaml(multi)), multi)


if __name__ == "__main__":
    unittest.main()
