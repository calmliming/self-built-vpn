import hashlib
import json
import os
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from backend.app.db import migrate, SessionLocal, engine
from backend.app.models import Base, Server, User, AccessState, Task, Session, Audit, NodeSpeed
from backend.app.security import seal, unseal, password_matches, new_credentials
from backend.app.services import create_member, queue_task
from backend.app.main import create_app
from backend.app import worker
from backend.app.config import STATE
from backend.app.subscriptions import fleet
from settings import Settings
from deploy_server import client_config
from add_protocol_nodes import profile
from team_agent import configurations, fingerprint, validate_members
from team_auth import authenticate

PASSWORD = 'isolated-test-password-123'
SECRET = {'uuid': str(uuid.UUID(int=0)), 'private_key': 'test-only-private',
          'public_key': 'test-only-public', 'short_id': '1234', 'subscription_token': 'test-only-owner-token'}
EXTRA = {'trojan_password': 'test-only-owner-trojan', 'hysteria_password': 'test-only-owner-hysteria',
         'http_username': 'test-owner-http', 'http_password': 'test-owner-http-password',
         'socks5_username': 'test-owner-socks', 'socks5_password': 'test-owner-socks-password'}

@pytest.fixture(autouse=True)
def state():
    assert 'self-vpn-panel-tests-' in str(STATE)
    migrate()
    with engine.begin() as connection:
        for table in reversed(Base.metadata.sorted_tables):
            connection.execute(table.delete())
    with SessionLocal.begin() as db:
        for index, code in enumerate(['hk', 'sg', 'us']):
            settings = Settings(server_ip='203.0.113.' + str(20 + index), node_prefix=code.upper(), http_port=20004, socks5_port=20005)
            config = profile(client_config(SECRET, settings), EXTRA, settings)
            packet = {'configuration': config, 'metadata': {'server': settings.server_ip, 'subscription_url': settings.https_origin + '/sub/test-only/config.yaml', 'nodes': config['proxies']}}
            db.add(Server(id=code, name=code, region='test-region', country='US', ip=settings.server_ip, config_path='/tmp/test-only.env', packet_blob=seal(packet)))
        db.flush()
        user, _ = create_member(db, 'admin', '测试管理员', 'admin', PASSWORD)
        member, _ = create_member(db, 'member', '测试成员', password=PASSWORD)
        yield_ids = (user.id, member.id)
    yield yield_ids

@pytest.fixture
def client():
    with TestClient(create_app(bootstrap_state=False, run_worker=False)) as client:
        yield client

def signed(client, username='admin'):
    result = client.post('/api/auth/login', json={'username': username, 'password': PASSWORD})
    assert result.status_code == 200
    client.headers['X-CSRF-Token'] = result.json()['csrf']
    return result.json()['user']

def test_authentication_and_csrf_are_required(client):
    assert client.get('/api/dashboard').status_code == 401
    assert client.get('/api/health').json() == {'ok': True}
    signed(client)
    csrf = client.headers.pop('X-CSRF-Token')
    assert client.post('/api/servers/all/probe').status_code == 403
    client.headers['X-CSRF-Token'] = csrf
    assert client.post('/api/servers/all/probe', headers={'Origin': 'https://untrusted.example'}).status_code == 403
    assert client.get('/api/dashboard', headers={'Host': 'untrusted.example'}).status_code == 400

def test_member_cannot_read_other_members_or_admin_data(client, state):
    signed(client, 'member')
    assert [user['id'] for user in client.get('/api/members').json()] == [state[1]]
    assert client.get('/api/servers').status_code == 403
    assert client.get('/api/audit').status_code == 403
    assert client.post('/api/members', json={'username': 'attacker', 'display_name': '禁止'}).status_code == 403
    assert client.post('/api/members/' + state[0] + '/actions', json={'action': 'reset-all'}).status_code == 403

def test_new_member_has_independent_encrypted_credentials(client, state):
    signed(client)
    response = client.post('/api/members', json={'username': 'new_member', 'display_name': '新成员'})
    assert response.status_code == 201
    body = response.json()
    with SessionLocal() as db:
        new = db.get(User, body['member']['id'])
        old = db.get(User, state[1])
        first, second = unseal(new.credential_blob), unseal(old.credential_blob)
        assert password_matches(body['initial_password'], new.password_hash)
        assert len({first[code]['uuid'] for code in ['hk', 'sg', 'us']}) == 3
        assert all(first[code][key] != second[code][key] for code in first for key in first[code])
        assert first['hk']['trojan_password'] not in new.credential_blob
    assert body['member']['subscription_url'] is None
    assert all(key not in json.dumps(body) for key in ['credential_blob', 'password_hash', 'token_blob', 'context_blob'])

def test_link_rotation_keeps_credentials_and_hides_old_token(client, state):
    signed(client)
    with SessionLocal() as db:
        before = db.get(User, state[1])
        old_blob, old_token = before.credential_blob, unseal(before.token_blob)
    result = client.post('/api/members/' + state[1] + '/actions', json={'action': 'reset-link'})
    assert result.status_code == 200
    assert old_token not in json.dumps(result.json())
    with SessionLocal() as db:
        after = db.get(User, state[1])
        assert after.credential_blob == old_blob
        assert after.credential_version == 1 and after.revision == 2
        assert unseal(after.token_blob) != old_token
        assert unseal(db.get(Task, result.json()['id']).context_blob)['previous_token'] == old_token

def test_full_rotation_retains_private_revocation_proof(client, state):
    signed(client)
    with SessionLocal() as db:
        before = unseal(db.get(User, state[1]).credential_blob)
    result = client.post('/api/members/' + state[1] + '/actions', json={'action': 'reset-all'})
    assert result.status_code == 200
    with SessionLocal() as db:
        member = db.get(User, state[1])
        after = unseal(member.credential_blob)
        assert member.credential_version == 2
        assert all(before[code][key] != after[code][key] for code in before for key in before[code])
        assert unseal(db.get(Task, result.json()['id']).context_blob)['previous_credentials'] == before

def test_disable_invalidates_login_but_keeps_remote_revocation_pending(client, state):
    with TestClient(create_app(False, False)) as member:
        signed(member, 'member')
        signed(client)
        result = client.post('/api/members/' + state[1] + '/actions', json={'action': 'disable'})
        assert result.status_code == 200
        assert member.get('/api/auth/me').status_code == 401
        data = next(row for row in client.get('/api/members').json() if row['id'] == state[1])
        assert not data['enabled'] and not data['sync_complete'] and data['subscription_url'] is None
        assert all(row['status'] == 'pending' for row in data['sync'])

def test_inflight_member_action_cannot_be_overwritten(client, state):
    signed(client)
    route = '/api/members/' + state[1] + '/actions'
    assert client.post(route, json={'action': 'reset-link'}).status_code == 200
    assert client.post(route, json={'action': 'disable'}).status_code == 409

def test_self_disable_and_invalid_regions_are_rejected(client, state):
    signed(client)
    assert client.post('/api/members/' + state[0] + '/actions', json={'action': 'disable'}).status_code == 400
    assert client.post('/api/members', json={'username': 'bad', 'display_name': '无效', 'regions': ['hk','hk']}).status_code == 422
    assert client.post('/api/members', json={'username': 'bad', 'display_name': '无效', 'regions': ['other']}).status_code == 422

def test_node_inventory_never_exposes_authentication_material(client):
    signed(client)
    response = client.get('/api/nodes')
    assert response.status_code == 200 and len(response.json()) == 18
    assert all(key not in response.text for key in ['password', 'uuid', 'private_key', 'ssh_key'])

def test_login_password_reset_preserves_vpn_credentials(client, state):
    signed(client)
    with SessionLocal() as db:
        before = db.get(User, state[1]).credential_blob
    result = client.post('/api/members/' + state[1] + '/actions', json={'action': 'reset-password'})
    assert result.status_code == 200
    with SessionLocal() as db:
        user = db.get(User, state[1])
        assert user.credential_blob == before
        assert password_matches(result.json()['initial_password'], user.password_hash)
    assert client.post('/api/auth/login', json={'username': 'member', 'password': PASSWORD}).status_code == 401

def test_password_change_revokes_other_sessions(client):
    signed(client)
    with TestClient(create_app(False, False)) as other:
        signed(other)
        assert client.post('/api/auth/password', json={'current_password': PASSWORD, 'new_password': 'changed-test-password-123'}).status_code == 200
        assert other.get('/api/auth/me').status_code == 401
        assert client.get('/api/auth/me').status_code == 200

def test_audit_export_escapes_spreadsheet_formulas(client):
    signed(client)
    with SessionLocal.begin() as db:
        db.add(Audit(actor='admin', action='创建成员', target='=1+2'))
    response = client.get('/api/audit.csv')
    assert response.status_code == 200 and "'=1+2" in response.text

def test_partial_sync_does_not_publish_or_claim_offline_region_revoked(state):
    with SessionLocal.begin() as db:
        user = db.get(User, state[1])
        user.enabled = False
        task = queue_task(db, 'sync', '测试部分撤销', user_id=user.id)
    def fake_transaction(server, action, data, verify, folder):
        if server.id == 'hk':
            raise RuntimeError('Injected unreachable region')
        receipt = {'digest': fingerprint(data['members']), 'member_count': len(data['members'])}
        verify(receipt)
        return receipt
    with patch('backend.app.remote.transaction', side_effect=fake_transaction), patch('backend.app.remote.probe', return_value={'healthy':True,'team_managed':True,'team_auth_active':True}), patch('backend.app.checks.verify_member', return_value={'verified':True}), patch('backend.app.checks.verify_denied', return_value={}), patch('backend.app.worker.publication') as publication:
        assert worker.sync_task(task) == 'partial'
        publication.assert_called_once()
        assert publication.call_args.kwargs['revoke'] is True
    with SessionLocal() as db:
        states = {row.server_id:row for row in db.scalars(select(AccessState).where(AccessState.user_id == state[1]))}
        assert states['hk'].status == 'pending' and states['hk'].applied_revision == 0
        assert states['sg'].status == 'synced' and states['us'].status == 'synced'

def test_fleet_has_only_its_members_credentials_and_public_rules(state):
    with SessionLocal() as db:
        user = db.get(User, state[1])
        servers = db.scalars(select(Server)).all()
        config = fleet(user, servers)
        assert len(config['proxies']) == 18
        assert SECRET['subscription_token'] not in json.dumps(config)
        assert SECRET['uuid'] not in json.dumps(config)
        assert EXTRA['trojan_password'] not in json.dumps(config)
        assert all('/team-rules/' in provider['url'] for provider in config['rule-providers'].values())

def test_hysteria_priority_keeps_custom_region_order_and_all_backup_nodes(state):
    with SessionLocal() as db:
        user = db.get(User, state[0])
        user.regions = json.dumps(['us', 'sg'])
        config = fleet(user, db.scalars(select(Server)).all())
    nodes = {node['name']: node for node in config['proxies']}
    automatic = next(g for g in config['proxy-groups'] if g['name'] == '地区自动回退')
    assert [nodes[n]['type'] for n in automatic['proxies'][:2]] == ['hysteria2', 'hysteria2']
    assert automatic['proxies'][0].startswith('US') and automatic['proxies'][1].startswith('SG')
    assert set(automatic['proxies']) == set(nodes) and len(automatic['proxies']) == 12
    assert not any(n.startswith('HK') for n in nodes)
    for name in ['美国节点', '新加坡节点']:
        group = next(g for g in config['proxy-groups'] if g['name'] == name)
        assert nodes[group['proxies'][0]]['type'] == 'hysteria2'
        assert len(group['proxies']) == 6

def ready_member(user_id):
    with SessionLocal.begin() as db:
        user = db.get(User, user_id)
        user.published_revision = user.revision
        for access in db.scalars(select(AccessState).where(AccessState.user_id == user_id)):
            access.status = 'synced'
            access.applied_revision = user.revision
            access.applied_enabled = True

def test_download_speed_requires_admin_ready_subscription_and_single_task(client, state):
    assert client.post('/api/speed-tests', json={'region':'all'}).status_code == 401
    signed(client, 'member')
    assert client.get('/api/speed-tests').status_code == 403
    assert client.post('/api/speed-tests', json={'region':'all'}).status_code == 403
    signed(client)
    assert client.post('/api/speed-tests', json={'region':'all'}).status_code == 409
    ready_member(state[0])
    assert client.post('/api/speed-tests', json={'region':'invalid'}).status_code == 422
    assert client.post('/api/speed-tests', json={'region':'hk','url':'http://127.0.0.1/'}).status_code == 422
    result = client.post('/api/speed-tests', json={'region':'hk'})
    assert result.status_code == 202 and result.json()['kind'] == 'speedtest'
    assert result.json()['server_id'] == 'hk'
    assert client.post('/api/speed-tests', json={'region':'us'}).status_code == 409
    assert client.get('/api/speed-tests').json()['active']['id'] == result.json()['id']

def test_download_speed_persists_partial_samples_and_does_not_change_services(client, state):
    signed(client)
    ready_member(state[0])
    result = client.post('/api/speed-tests', json={'region':'us'}).json()
    with SessionLocal() as db:
        task = db.get(Task, result['id'])
    def samples(server, nodes, on_start):
        for i, node in enumerate(nodes):
            on_start(node)
            yield node, {'status':'sampled' if i else 'failed', 'mbps':1.25 if i else None,
                'bytes':1875000 if i else 0, 'seconds':12 if i else None, 'message':'限时采样' if i else '连接失败'}
    with patch('backend.app.speedtest.measure_nodes', side_effect=samples), patch('backend.app.remote.transaction') as remote_change:
        assert worker.speedtest_task(task) == 'partial'
        remote_change.assert_not_called()
    body = client.get('/api/speed-tests').json()
    assert len(body['samples']) == 6
    assert {sample['server_id'] for sample in body['samples']} == {'us'}
    assert sum(sample['mbps'] is None for sample in body['samples']) == 1
    assert sum(sample['mbps'] is not None for sample in body['samples']) == 5
    assert not any(key in json.dumps(body) for key in ['password','uuid','credential_blob','token_blob'])
    # Repeated samples replace the previous value, rather than mixing sessions.
    with patch('backend.app.speedtest.measure_nodes', side_effect=samples):
        worker.speedtest_task(task)
    with SessionLocal() as db:
        assert len(db.scalars(select(NodeSpeed)).all()) == 6

def test_republish_verifies_before_publishing_and_does_not_sync_credentials(state):
    ready_member(state[0])
    with SessionLocal.begin() as db:
        task = queue_task(db, 'republish', '更新策略', user_id=state[0])
    with patch('backend.app.checks.verify_fleet', side_effect=RuntimeError('failed')), patch('backend.app.worker.publication') as publish:
        with pytest.raises(RuntimeError):
            worker.republish_task(task)
        publish.assert_not_called()
    with patch('backend.app.checks.verify_fleet', return_value={'verified':True}), patch('backend.app.worker.publication') as publish:
        assert worker.republish_task(task) == 'succeeded'
        publish.assert_called_once()

def test_fixed_exit_contains_only_that_country_and_keeps_credentials(state):
    with SessionLocal() as db:
        user = db.get(User, state[0])
        user.exit_region = 'us'
        config = fleet(user, db.scalars(select(Server)).all())
        us = db.get(Server, 'us')
        assert len(config['proxies']) == 6
        assert {node['server'] for node in config['proxies']} == {us.ip}
        names = {node['name'] for node in config['proxies']}
        assert all(name in names or name in {'地区自动回退', '美国节点'}
            for group in config['proxy-groups'] for name in group['proxies'])
        assert all(group['name'] not in ['香港节点', '新加坡节点'] for group in config['proxy-groups'])
        assert json.loads(user.regions) == ['hk','sg','us']
        user.regions = '["hk"]'
        with pytest.raises(ValueError, match='未授权'):
            fleet(user, db.scalars(select(Server)).all())

def test_fixed_exit_only_republishes_and_stays_pending_until_publication(client, state):
    signed(client)
    assert client.patch('/api/routing/exit', json={'region':'us'}).status_code == 409
    ready_member(state[0])
    with SessionLocal() as db:
        original = db.get(User, state[0])
        credential, token, version = original.credential_blob, original.token_blob, original.credential_version
    result = client.patch('/api/routing/exit', json={'region':'us'})
    assert result.status_code == 202 and result.json()['kind'] == 'republish'
    assert client.get('/api/routing').json()['exit_region'] == 'us'
    assert not client.get('/api/auth/me').json()['user']['ready']
    with SessionLocal.begin() as db:
        user = db.get(User, state[0])
        assert (user.credential_blob,user.token_blob,user.credential_version) == (credential,token,version)
        assert user.revision == 2 and user.published_revision == 1
        assert all(a.applied_revision == 2 for a in db.scalars(select(AccessState).where(AccessState.user_id==user.id)))
        db.get(Task, result.json()['id']).status = 'succeeded'
    # A future authorization edit cannot silently remove the fixed exit.
    response = client.patch('/api/members/'+state[0],json={'display_name':'测试管理员','regions':['hk'],'note':''})
    assert response.status_code == 409 and '固定出口' in response.json()['detail']

def test_exit_policy_requires_authentication_and_authorized_region(client, state):
    assert client.patch('/api/routing/exit',json={'region':'us'}).status_code == 401
    signed(client)
    ready_member(state[0])
    assert client.patch('/api/routing/exit',json={'region':'elsewhere'}).status_code == 422
    with SessionLocal.begin() as db:
        db.get(User,state[0]).regions = '["us"]'
    assert client.patch('/api/routing/exit',json={'region':'hk'}).status_code == 403

def test_overlay_preserves_owner_and_pinned_protocol_fields():
    settings = Settings(server_ip='203.0.113.20', http_port=20004, socks5_port=20005)
    credential = new_credentials(['hk'])['hk']
    members = validate_members([{'id':'a'*32, 'version':1, 'credential':credential}])
    primary, extra, hy = configurations(SECRET, EXTRA, settings, members)
    assert [c['id'] for c in primary['inbounds'][0]['settings']['clients']] == [SECRET['uuid'], credential['uuid']]
    assert len(extra['inbounds'][0]['settings']['clients']) == 2
    for inbound in extra['inbounds'][1:]:
        key = 'clients' if inbound['protocol'] == 'trojan' else 'accounts'
        assert len(inbound['settings'][key]) == 2
        assert 'users' not in inbound['settings']
    assert hy['auth']['type'] == 'http' and hy['auth']['http']['url'].startswith('http://127.0.0.1:')

def test_local_auth_preserves_owner_and_revokes_member():
    users = {'legacy-owner': hashlib.sha256(b'owner-original').hexdigest(), 'member-a': hashlib.sha256(b'member-secret').hexdigest()}
    assert authenticate('owner-original', users) == 'legacy-owner'
    assert authenticate('member-secret', users) == 'member-a'
    assert authenticate('wrong', users) == ''
    del users['member-a']
    assert authenticate('member-secret', users) == ''
    assert authenticate('owner-original', users) == 'legacy-owner'

def test_legacy_deploy_cannot_overwrite_team_members(tmp_path):
    import server_agent
    (tmp_path / 'team-managed').write_text('managed')
    with patch.object(server_agent, 'BASE', tmp_path):
        for action in ['deploy', 'add-nodes', 'publish']:
            with pytest.raises(RuntimeError, match='Team credentials'):
                server_agent.run_action(action, Settings(server_ip='203.0.113.20'))

def test_publication_permissions_work_under_private_umask(tmp_path):
    import team_agent
    class FakeTransaction:
        def __init__(self, **kwargs): pass
        def __enter__(self): return self
        def __exit__(self, *args): return False
    content = json.dumps({'proxies': [{'name':'test-only'}]})
    payload = {'user_id': 'a'*32, 'token': 'b'*48, 'content': content, 'digest': hashlib.sha256(content.encode()).hexdigest()}
    previous = os.umask(0o077)
    try:
        with patch.object(team_agent, 'TEAM_SUB', tmp_path/'public'), patch.object(team_agent, 'MANIFEST', tmp_path/'manifest.json'), patch.object(team_agent, 'Transaction', FakeTransaction), patch.object(team_agent, 'commit_handshake'), patch('os.chown'), patch('os.fchown'), patch('grp.getgrnam', return_value=SimpleNamespace(gr_gid=os.getgid())):
            team_agent.publication(payload)
        assert (tmp_path/'public').stat().st_mode & 0o777 == 0o750
        assert (tmp_path/'public'/payload['token']).stat().st_mode & 0o777 == 0o750
        assert (tmp_path/'public'/payload['token']/'config.yaml').stat().st_mode & 0o777 == 0o640
    finally:
        os.umask(previous)
