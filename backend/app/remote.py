"""Only typed, allowlisted operations cross SSH. No browser-supplied shell commands."""
import json
from pathlib import Path
import select
import shlex
import subprocess
import sys
import threading
import time

from .config import PROJECT, RUNTIME
sys.path.insert(0, str(PROJECT / 'scripts'))
from settings import load_settings
from manage import read_remote

SOURCES = ['settings.py', 'operations.py', 'routing_rules.py', 'deploy_server.py', 'add_protocol_nodes.py', 'server_agent.py', 'team_agent.py', 'team_auth.py', 'traffic_stats.py', 'quota_control.py']
BOOTSTRAP = '''import json,os,pathlib,sys,tempfile
os.umask(0o077)
payload=json.loads(sys.stdin.readline())
with tempfile.TemporaryDirectory(prefix="self-vpn-team-") as folder:
    for name,source in payload.pop("sources").items():
        pathlib.Path(folder,name).write_text(source)
    sys.path.insert(0,folder)
    from team_agent import main
    main(payload)
'''

def settings_for(server):
    return load_settings(server.config_path, environ={})

def export(server):
    return read_remote(settings_for(server), 'export-current')[0]

def payload_for(server, action, data):
    return {'action': action, 'settings': settings_for(server).as_dict(),
            'sources': {name: (PROJECT / 'scripts' / name).read_text() for name in SOURCES}, **data}

def command(server):
    return settings_for(server).ssh_args() + ['sudo -n python3 -u -c ' + shlex.quote(BOOTSTRAP)]

def probe(server):
    report = read_action(server, 'probe')
    return report

def read_action(server, action, data=None):
    start = time.monotonic()
    result = subprocess.run(command(server), input=json.dumps(payload_for(server, action, data or {})) + '\n', capture_output=True, text=True, timeout=80)
    if result.returncode:
        raise RuntimeError('SSH 诊断失败，请检查服务器连接或任务记录')
    report = json.loads(result.stdout)
    if action == 'probe':
        report['ssh_roundtrip_ms'] = round((time.monotonic() - start) * 1000)
    return report

def transaction(server, action, data, verify, log_dir):
    log_dir = Path(log_dir)
    log_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    process = subprocess.Popen(command(server), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
    errors = []
    reader = threading.Thread(target=lambda: errors.append(process.stderr.read()), daemon=True)
    reader.start()
    receipt = None
    try:
        process.stdin.write(json.dumps(payload_for(server, action, data)) + '\n')
        process.stdin.flush()
        deadline = time.monotonic() + 150
        while time.monotonic() < deadline:
            readable, _, _ = select.select([process.stdout], [], [], 1)
            if readable:
                line = process.stdout.readline()
                if not line:
                    break
                value = json.loads(line)
                if value.get('event') == 'ready':
                    receipt = value
                    break
            elif process.poll() is not None:
                break
        if not receipt:
            raise RuntimeError('服务器未完成准备，已请求回滚')
        verify(receipt)
        process.stdin.write(json.dumps({'action': 'commit', 'nonce': receipt['nonce']}) + '\n')
        process.stdin.flush()
        process.stdin.close()
        line = process.stdout.readline()
        if not line or json.loads(line).get('event') != 'committed' or process.wait(timeout=30):
            raise RuntimeError('提交响应中断；重试将核对并恢复服务器状态')
        return receipt
    except BaseException:
        if process.poll() is None:
            try:
                if not process.stdin.closed:
                    process.stdin.write('{"action":"abort"}\n')
                    process.stdin.flush()
                    process.stdin.close()
            except (OSError, ValueError):
                pass
            try:
                process.wait(timeout=90)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        raise
    finally:
        reader.join(timeout=3)
        (log_dir / (server.id + '-remote.log')).write_text(''.join(errors))
        (log_dir / (server.id + '-remote.log')).chmod(0o600)
        for stream in [process.stdout, process.stderr]:
            stream.close()
        if not process.stdin.closed:
            process.stdin.close()
