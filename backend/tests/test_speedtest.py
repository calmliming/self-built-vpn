import json
import subprocess
from types import SimpleNamespace
from unittest.mock import patch
import pytest

from backend.app.speedtest import download_sample, PAYLOAD_BYTES, TIMEOUT_SECONDS
from add_protocol_nodes import prioritize_hysteria, restrict_automatic_exit

@pytest.mark.parametrize('code,size,seconds,http,tls,status,mbps', [
    (0, 3000000, 2, 200, 0, 'complete', 12),
    (28, 300000, 12, 200, 0, 'sampled', .2),
    (28, 0, 12, 200, 0, 'failed', None),
    (0, 1000, 1, 403, 0, 'failed', None),
    (60, 3000000, 1, 200, 20, 'failed', None),
    (0, 3000000, 0, 200, 0, 'failed', None),
    (0, 3000000, float('nan'), 200, 0, 'failed', None),
    (0, 500, 1, 200, 0, 'failed', None),
])
def test_download_does_not_report_errors_as_fast_connections(code,size,seconds,http,tls,status,mbps):
    response = SimpleNamespace(returncode=code, stdout=json.dumps({'size_download':size,'time_total':seconds,
        'http_code':http,'ssl_verify_result':tls}))
    with patch('backend.app.speedtest.subprocess.run', return_value=response) as run:
        result = download_sample('socks5h://127.0.0.1:12345')
    assert result['status'] == status and result['mbps'] == mbps
    command = run.call_args.args[0]
    assert command[:2] == ['curl','--disable']
    assert command[command.index('--max-filesize')+1] == str(PAYLOAD_BYTES)
    assert command[command.index('--max-time')+1] == str(TIMEOUT_SECONDS)
    assert '--insecure' not in command and '--location' not in command

def test_curl_hang_and_invalid_metrics_are_failed_samples():
    for value in [subprocess.TimeoutExpired('curl',15), ValueError('invalid')]:
        with patch('backend.app.speedtest.subprocess.run', side_effect=value):
            assert download_sample('socks5h://127.0.0.1:12345')['mbps'] is None

def test_priority_update_only_reorders_fallback_groups():
    before = {'proxies':[{'name':'tcp','type':'vless'},{'name':'udp','type':'hysteria2'}],
        'proxy-groups':[{'name':'manual','type':'select','proxies':['tcp','udp']},
                        {'name':'auto','type':'fallback','proxies':['tcp','udp']}],
        'rules':['MATCH,manual'],'dns':{'enable':True}}
    after = prioritize_hysteria(before)
    assert after['proxy-groups'][1]['proxies'] == ['udp','tcp']
    assert before['proxy-groups'][1]['proxies'] == ['tcp','udp']
    after['proxy-groups'][1]['proxies'] = ['tcp','udp']
    assert before == after

def test_legacy_exit_lock_keeps_manual_choices_and_credentials():
    config = {'proxies':[{'name':'HK','server':'203.0.113.1','type':'hysteria2','password':'test-only-hk'},
                        {'name':'US-HY','server':'203.0.113.2','type':'hysteria2','password':'test-only-us'},
                        {'name':'US-TCP','server':'203.0.113.2','type':'trojan','password':'test-only-tcp'}],
        'proxy-groups':[{'name':'代理选择','type':'select','proxies':['地区自动回退','HK','US-HY']},
                        {'name':'地区自动回退','type':'fallback','proxies':['HK','US-HY','US-TCP']},
                        {'name':'规则下载','type':'fallback','proxies':['HK','US-HY','US-TCP']}],
        'rules':['MATCH,代理选择']}
    locked = restrict_automatic_exit(config, '203.0.113.2')
    assert locked['proxies'] == config['proxies']
    assert locked['proxy-groups'][0] == config['proxy-groups'][0]
    assert all(g['proxies']==['US-HY','US-TCP'] for g in locked['proxy-groups'][1:])
    assert config['proxy-groups'][1]['proxies'][0] == 'HK'
    with pytest.raises(ValueError):
        restrict_automatic_exit(config,'203.0.113.3')
