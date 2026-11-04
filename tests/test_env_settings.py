from dataclasses import fields
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))

from settings import ENV_FIELDS, ROOT, Settings, dump_env, load_settings, parse_env


class EnvSettingsTests(unittest.TestCase):
    def test_template_lists_every_supported_variable(self):
        example = ROOT / '.env.example'
        self.assertEqual(set(parse_env(example.read_text())), set(ENV_FIELDS))
        self.assertEqual(set(ENV_FIELDS), {'VPN_' + field.name.upper() for field in fields(Settings)})
        self.assertEqual(load_settings(example, environ={}).server_ip, '203.0.113.10')

    def test_roundtrip_preserves_types_paths_and_empty_values(self):
        original = Settings(server_ip='203.0.113.20', ssh_port=2222,
            ssh_key='~/.ssh/a # "quoted" key.pem', expected_exit_country='',
            node_prefix='美国自建', ai_group_name='美国AI',
            auto_group_name='自动切换', rules_group_name='规则下载',
            node_name_style='compact', hysteria2_obfs='salamander', http_port=23004, socks5_port=23005)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'private.env'
            path.write_text(dump_env(original))
            loaded = load_settings(path, environ={})
        self.assertEqual(loaded, original)
        self.assertIs(type(loaded.ssh_port), int)
        self.assertEqual(loaded.aws_instance_id, '')
        self.assertEqual(loaded.expected_exit_country, '')

    def test_quotes_comments_export_and_url_fragments(self):
        text = '''# comment
export VPN_SERVER_IP = 203.0.113.20 # server
VPN_SSH_KEY = '~/.ssh/a key.pem' # private path
VPN_HEALTHCHECK_URL=https://example.invalid/check#fragment # comment
VPN_SSH_PORT="2222"
VPN_AWS_INSTANCE_ID= # optional
'''
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'private.env'
            path.write_text(text)
            loaded = load_settings(path, environ={})
        self.assertEqual(loaded.ssh_key, '~/.ssh/a key.pem')
        self.assertEqual(loaded.healthcheck_url, 'https://example.invalid/check#fragment')
        self.assertEqual(loaded.ssh_port, 2222)
        self.assertEqual(loaded.aws_instance_id, '')

    def test_environment_overrides_file_without_mutating_process_variables(self):
        environment = {'VPN_SERVER_IP': '198.51.100.20', 'VPN_SSH_PORT': '2223', 'USER': 'untouched'}
        before = environment.copy()
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'private.env'
            path.write_text('VPN_SERVER_IP=203.0.113.20\nVPN_SSH_PORT=2222\n')
            loaded = load_settings(path, environ=environment)
        self.assertEqual(loaded.server_ip, '198.51.100.20')
        self.assertEqual(loaded.ssh_port, 2223)
        self.assertEqual(environment, before)

    def test_environment_only_configuration_is_supported(self):
        with tempfile.TemporaryDirectory() as folder, patch('settings.ROOT', Path(folder)):
            loaded = load_settings(environ={'VPN_SERVER_IP': '203.0.113.20'})
        self.assertEqual(loaded.server_ip, '203.0.113.20')
        self.assertEqual(loaded.reality_port, 443)

    def test_explicit_missing_file_is_an_error_even_with_environment_values(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(ValueError):
                load_settings(Path(folder) / 'missing.env', environ={'VPN_SERVER_IP': '203.0.113.20'})

    def test_file_selector_and_explicit_path_precedence(self):
        with tempfile.TemporaryDirectory() as folder:
            first = Path(folder) / 'first.env'
            second = Path(folder) / 'second.env'
            first.write_text('VPN_SERVER_IP=203.0.113.20\n')
            second.write_text('VPN_SERVER_IP=198.51.100.20\n')
            environment = {'SELF_VPN_ENV_FILE': str(second)}
            self.assertEqual(load_settings(environ=environment).server_ip, '198.51.100.20')
            self.assertEqual(load_settings(first, environ=environment).server_ip, '203.0.113.20')

    def test_shell_substitutions_and_variable_expansion_remain_literal(self):
        text = 'VPN_SERVER_IP=203.0.113.20\nVPN_SSH_KEY=\'${HOME}/$(touch ignored)/`echo ignored`\'\n'
        with tempfile.TemporaryDirectory() as folder, patch('subprocess.run', side_effect=AssertionError('A config file must not execute commands')):
            path = Path(folder) / 'private.env'
            path.write_text(text)
            loaded = load_settings(path, environ={'HOME': '/unused'})
        self.assertEqual(loaded.ssh_key, '${HOME}/$(touch ignored)/`echo ignored`')

    def test_duplicate_unknown_and_malformed_assignments_are_rejected(self):
        invalid = [
            'VPN_SERVER_IP=203.0.113.20\nVPN_SERVER_IP=198.51.100.20\n',
            'VPN_SERVER_IP=203.0.113.20\nVPN_UNKNOWN=true\n',
            'VPN_SERVER_IP=203.0.113.20\nVPN_SSH_PORT\n',
            'VPN_SERVER_IP=203.0.113.20\nVPN_SSH_KEY="unclosed\n',
            'VPN_SERVER_IP=203.0.113.20\nVPN_SSH_KEY="quoted" extra\n',
            'VPN_SERVER_IP=203.0.113.20\nVPN_SSH_PORT=true\n',
            'VPN_SERVER_IP=203.0.113.20\nVPN_SSH_PORT=\n',
            'VPN_SSH_USER=ubuntu\n',
            'VPN_SERVER_IP=\n',
            '{"server_ip": "203.0.113.20"}\n',
        ]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'private.env'
            for number, text in enumerate(invalid):
                with self.subTest(case=number):
                    path.write_text(text)
                    with self.assertRaises(ValueError):
                        load_settings(path, environ={})

    def test_bom_and_crlf_are_supported_but_multiline_values_are_rejected(self):
        self.assertEqual(parse_env('\ufeffVPN_SERVER_IP=203.0.113.20\r\n')['VPN_SERVER_IP'], '203.0.113.20')
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'private.env'
            path.write_text('VPN_SERVER_IP=203.0.113.20\nVPN_HEALTHCHECK_URL="https://example.invalid/\\ncheck"\n')
            with self.assertRaises(ValueError):
                load_settings(path, environ={})


if __name__ == '__main__':
    unittest.main()
