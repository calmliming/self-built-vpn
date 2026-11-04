"""Explicit live acceptance: isolated members, revocation, rotation, and cleanup.

Run from the repository root with the private admin account already initialized.
No credentials, member URLs, or configuration contents are printed.
"""
import copy
import hashlib
import json
from pathlib import Path
import sys
import time
import uuid

PROJECT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT))
import httpx
from sqlalchemy import select
from backend.app.config import STATE, RUNTIME, INVENTORY
from backend.app.db import SessionLocal
from backend.app.models import User, Server
from backend.app.security import unseal
from backend.app.checks import verify_member, verify_fleet
from backend.app.remote import export, settings_for
from verification import https_request, verify_profile

BASE_URL = 'http://127.0.0.1:55139'
RESUME = len(sys.argv) == 3 and sys.argv[1] == '--resume'
REPORT_DIR = Path(sys.argv[2]).resolve() if RESUME else RUNTIME / ('live-acceptance-' + uuid.uuid4().hex[:8])
REPORT_DIR.mkdir(mode=0o700, parents=True, exist_ok=RESUME)
report = json.loads((REPORT_DIR / 'report.json').read_text()) if RESUME else {'started_at': time.time(), 'checks': {}, 'test_members': [], 'complete': False}

def save():
    path = REPORT_DIR / 'report.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2))
    path.chmod(0o600)

def check(name, value=True):
    assert value, name
    report['checks'][name] = True
    save()
    print(json.dumps({'check': name, 'passed': True}), flush=True)

admin_password = (STATE / '管理员登录.txt').read_text().split('密码：', 1)[1].splitlines()[0]
admin = httpx.Client(base_url=BASE_URL + '/api', trust_env=False, timeout=20)
login = admin.post('/auth/login', json={'username': 'admin', 'password': admin_password})
login.raise_for_status()
auth = login.json()
admin.headers['X-CSRF-Token'] = auth['csrf']

def api(method, path, body=None):
    response = admin.request(method, path, json=body)
    response.raise_for_status()
    return response.json()

def wait(task):
    task_id = task['id']
    deadline = time.monotonic() + 1100
    last = ''
    while time.monotonic() < deadline:
        item = api('GET', '/tasks/' + task_id)
        events = item['details']
        status = item['status'] + ':' + (events[-1]['step'] + ':' + events[-1]['status'] if events else '')
        if status != last:
            print(json.dumps({'task': task_id[:8], 'progress': status}), flush=True)
            last = status
        if item['status'] not in ['running', 'queued']:
            assert item['status'] == 'succeeded', 'Live task did not succeed: ' + task_id
            return item
        time.sleep(2)
    raise RuntimeError('Live task timed out')

def download(url, label, expected=200):
    folder = REPORT_DIR / label
    folder.mkdir(mode=0o700)
    metrics, body = https_request(url, folder, 'download', interface='en0')
    assert metrics['http'] == expected and metrics['tls_verify'] == 0, label
    return body

def finish_validation():
    assert report['checks'].get('disabled_member_all_18_old_node_credentials_rejected')
    ids = report['test_members']
    members = {member['id']: member for member in api('GET', '/members')}
    b_data = members[ids[1]]
    b_body = (REPORT_DIR / 'member-b/download.body').read_bytes()
    with SessionLocal() as db:
        b_user = db.get(User, ids[1])
        servers = db.scalars(select(Server)).all()
    us = next(server for server in servers if server.id == 'us')
    for server in servers:
        if not report['checks'].get('member_b_remains_usable_' + server.id):
            verify_member(b_user, server, us, REPORT_DIR / 'b-independent' / server.id)
            check('member_b_remains_usable_' + server.id)
        if not report['checks'].get('legacy_owner_remains_usable_' + server.id):
            packet = export(server)
            verify_profile(packet, settings_for(server), PROJECT / '.runtime/mihomo', 'en0', artifact_dir=REPORT_DIR / 'legacy-independent' / server.id)
            check('legacy_owner_remains_usable_' + server.id)
    if not report['checks'].get('combined_subscription_groups_dns_and_routing'):
        verify_fleet(json.loads(b_body), servers, REPORT_DIR / 'combined-subscription')
        check('combined_subscription_groups_dns_and_routing')
    legacy = json.loads((INVENTORY / 'deployment/fleet-verification.json').read_text())['subscription_url']
    if not report['checks'].get('legacy_subscription_unchanged'):
        check('legacy_subscription_unchanged', download(legacy, 'legacy-after') == (REPORT_DIR / 'legacy-before/download.body').read_bytes())
    for member_id in ids:
        if member_id in {member['id'] for member in api('GET', '/members')}:
            wait(api('POST', '/members/' + member_id + '/actions', {'action': 'delete'}))
    check('temporary_members_revoked_and_removed', not ({member['id'] for member in api('GET', '/members')} & set(ids)))
    report.update(complete=True, finished_at=time.time())
    save()
    print(json.dumps({'complete': True, 'checks': len(report['checks']), 'report': str(REPORT_DIR / 'report.json')}), flush=True)

if RESUME:
    finish_validation()
    raise SystemExit(0)

try:
    me = api('GET', '/auth/me')['user']
    if not me['ready']:
        wait(api('POST', '/members/' + me['id'] + '/actions', {'action': 'retry'}))
    check('admin_independent_subscription_ready', api('GET', '/auth/me')['user']['ready'])
    legacy = json.loads((INVENTORY / 'deployment/fleet-verification.json').read_text())['subscription_url']
    legacy_before = download(legacy, 'legacy-before')
    new_members = []
    for letter in ['a', 'b']:
        username = 'verify_' + letter + '_' + uuid.uuid4().hex[:8]
        created = api('POST', '/members', {'username': username, 'display_name': '验收成员 ' + letter.upper(), 'note': '自动验收临时成员，完成后撤销'})
        member = created['member']
        report['test_members'].append(member['id'])
        save()
        wait(created['task'])
        member = next(m for m in api('GET', '/members') if m['id'] == member['id'])
        body = download(member['subscription_url'], 'member-' + letter)
        config = json.loads(body)
        check('member_' + letter + '_18_nodes', len(config['proxies']) == 18)
        client = httpx.Client(base_url=BASE_URL + '/api', trust_env=False, timeout=15)
        signed = client.post('/auth/login', json={'username': username, 'password': created['initial_password']})
        signed.raise_for_status()
        client.headers['X-CSRF-Token'] = signed.json()['csrf']
        check('member_' + letter + '_own_records_only', [m['id'] for m in client.get('/members').json()] == [member['id']])
        check('member_' + letter + '_admin_apis_forbidden', client.get('/servers').status_code == 403 and client.get('/audit').status_code == 403)
        new_members.append({'member': member, 'client': client, 'config': config, 'body': body})
    a, b = new_members
    with SessionLocal() as db:
        users = [db.get(User, item['member']['id']) for item in new_members]
        admin_user = db.get(User, me['id'])
        for code in ['hk', 'sg', 'us']:
            values = [unseal(user.credential_blob)[code] for user in [*users, admin_user]]
            for key in values[0]:
                assert len({value[key] for value in values}) == 3
        check('credentials_distinct_per_member_and_region', len({unseal(users[0].credential_blob)[code]['uuid'] for code in ['hk', 'sg', 'us']}) == 3)
    old_url = a['member']['subscription_url']
    wait(api('POST', '/members/' + a['member']['id'] + '/actions', {'action': 'reset-link'}))
    a['member'] = next(m for m in api('GET', '/members') if m['id'] == a['member']['id'])
    body = download(a['member']['subscription_url'], 'a-link-rotation')
    download(old_url, 'a-old-link-rejected', 404)
    check('link_rotation_preserves_node_credentials', body == a['body'])
    old_url = a['member']['subscription_url']
    old_nodes = json.loads(body)['proxies']
    wait(api('POST', '/members/' + a['member']['id'] + '/actions', {'action': 'reset-all'}))
    a['member'] = next(m for m in api('GET', '/members') if m['id'] == a['member']['id'])
    body = download(a['member']['subscription_url'], 'a-full-rotation')
    download(old_url, 'a-previous-full-link-rejected', 404)
    new_nodes = json.loads(body)['proxies']
    check('full_rotation_replaces_all_18_node_credentials', all(old.get('uuid', old.get('password')) != new.get('uuid', new.get('password')) for old, new in zip(old_nodes, new_nodes)))
    check('full_rotation_old_18_node_credentials_rejected')
    revoked_url = a['member']['subscription_url']
    wait(api('POST', '/members/' + a['member']['id'] + '/actions', {'action': 'disable'}))
    disabled = next(m for m in api('GET', '/members') if m['id'] == a['member']['id'])
    check('disabled_member_three_regions_revoked', not disabled['enabled'] and disabled['sync_complete'] and all(not state['applied_enabled'] for state in disabled['sync']))
    check('disabled_member_session_rejected', a['client'].get('/auth/me').status_code == 401)
    download(revoked_url, 'disabled-subscription', 404)
    check('disabled_member_public_link_rejected')
    check('disabled_member_all_18_old_node_credentials_rejected')
    check('member_b_subscription_unchanged', download(b['member']['subscription_url'], 'b-after-a-disabled') == b['body'])
    finish_validation()
except BaseException:
    save()
    raise
