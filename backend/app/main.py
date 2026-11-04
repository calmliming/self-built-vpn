import csv
from contextlib import asynccontextmanager
import hmac
import io
import json
import os
import secrets
import threading
import time
import subprocess
import sys
from typing import Literal

from fastapi import FastAPI, Depends, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select, delete, func
from sqlalchemy.orm import Session as DatabaseSession
from sqlalchemy.exc import IntegrityError
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .config import COOKIE, FRONTEND, STATE, RUNTIME
from .db import SessionLocal, migrate
from .models import User, Session, Server, AccessState, Task, Audit, NodeSpeed, now
from .security import digest, password_matches, password_hash, seal, unseal, new_credentials
from .services import bootstrap, create_member, queue_task, task_data, audit
from .subscriptions import subscription_url, REGIONS

class Input(BaseModel):
    model_config = ConfigDict(extra='forbid')

class Login(Input):
    username: str = Field(min_length=1, max_length=40)
    password: str = Field(min_length=1, max_length=128)

class Launch(Input):
    code: str = Field(min_length=32, max_length=100)

class NewMember(Input):
    username: str = Field(min_length=2, max_length=40, pattern=r'^[a-z0-9][a-z0-9_.-]+$')
    display_name: str = Field(min_length=1, max_length=60)
    role: Literal['admin', 'member'] = 'member'
    password: str | None = Field(default=None, min_length=12, max_length=128)
    regions: list[Literal['hk', 'sg', 'us']] = Field(default=['hk', 'sg', 'us'], min_length=1, max_length=3)
    note: str = Field(default='', max_length=300)

class EditMember(Input):
    display_name: str = Field(min_length=1, max_length=60)
    regions: list[Literal['hk', 'sg', 'us']] = Field(min_length=1, max_length=3)
    note: str = Field(default='', max_length=300)

class ChangePassword(Input):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=12, max_length=128)

class MemberAction(Input):
    action: Literal['enable', 'disable', 'reset-link', 'reset-all', 'retry', 'delete', 'reset-password']

class SpeedTest(Input):
    region: Literal['all', 'hk', 'sg', 'us'] = 'all'

class ExitPolicy(Input):
    region: Literal['hk', 'sg', 'us'] | None = None

def database():
    with SessionLocal() as db:
        yield db

def user_data(db, user):
    us = db.get(Server, 'us')
    access = db.scalars(select(AccessState).where(AccessState.user_id == user.id)).all()
    synced = all(s.applied_revision == user.revision and s.status == 'synced' for s in access) and len(access) == 3
    ready = user.enabled and not user.deleted and synced and user.published_revision == user.revision
    return {'id': user.id, 'username': user.username, 'display_name': user.display_name, 'role': user.role,
        'enabled': user.enabled, 'regions': json.loads(user.regions), 'exit_region': user.exit_region, 'revision': user.revision,
        'credential_version': user.credential_version, 'created_at': user.created_at, 'last_login': user.last_login,
        'note': user.note, 'ready': ready, 'sync_complete': synced,
        'subscription_url': subscription_url(user, us) if ready and us else None,
        'sync': [{'server_id': s.server_id, 'status': 'synced' if s.applied_revision == user.revision and s.status == 'synced' else 'pending',
            'applied_enabled': s.applied_enabled, 'error': s.error, 'updated_at': s.updated_at} for s in access]}

def server_data(server):
    metrics = json.loads(server.metrics)
    return {'id': server.id, 'name': server.name, 'region': server.region, 'country': server.country, 'ip': server.ip,
        'health': server.health, 'checked_at': server.checked_at, 'error': server.error, 'metrics': metrics,
        'monthly_price': server.monthly_price, 'node_count': len(unseal(server.packet_blob)['configuration']['proxies']) if server.packet_blob else 0}

def busy(db, user_id):
    if db.scalar(select(Task.id).where(Task.user_id == user_id, Task.status.in_(['queued', 'running'])).limit(1)):
        raise HTTPException(409, '该成员有进行中的任务，请等待任务结束')

def create_app(bootstrap_state=True, run_worker=True):
    launch = {'hash': '', 'expires': 0}
    launch_lock = threading.Lock()
    attempts = {}
    rate_lock = threading.Lock()

    @asynccontextmanager
    async def lifespan(app):
        migrate()
        if bootstrap_state:
            bootstrap()
            code = secrets.token_urlsafe(36)
            launch.update(hash=digest(code), expires=time.time() + 3600)
            path = STATE / 'preview-access.json'
            path.write_text(json.dumps({'code': code}))
            path.chmod(0o600)
        worker_process = None
        worker_log = None
        if run_worker and os.environ.get('SELF_VPN_WORKER_EXTERNAL') != '1':
            worker_log = (RUNTIME / 'worker.log').open('a')
            (RUNTIME / 'worker.log').chmod(0o600)
            worker_process = subprocess.Popen([sys.executable, '-m', 'backend.app.worker'], stdout=worker_log, stderr=subprocess.STDOUT)
        yield
        if worker_process:
            worker_process.terminate()
            try:
                worker_process.wait(timeout=300)
            except subprocess.TimeoutExpired:
                worker_process.kill()
                worker_process.wait()
            worker_log.close()

    app = FastAPI(title='Self VPN Team API', docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=['127.0.0.1', 'localhost', 'testserver'])

    @app.exception_handler(IntegrityError)
    async def concurrent_write(request, error):
        return JSONResponse({'detail': '该账号或同步任务已存在，请刷新后重试'}, status_code=409)

    @app.middleware('http')
    async def browser_security(request, call_next):
        if request.method in ['POST', 'PATCH', 'DELETE', 'PUT']:
            origin = request.headers.get('origin')
            expected = str(request.base_url).rstrip('/')
            if origin and origin != expected:
                return JSONResponse({'detail': '请求来源校验失败'}, status_code=403)
        response = await call_next(request)
        response.headers['Cache-Control'] = 'no-store' if request.url.path.startswith('/api') else 'no-cache'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        return response

    def current(request: Request, db: DatabaseSession = Depends(database)):
        token = request.cookies.get(COOKIE, '')
        session = db.get(Session, digest(token)) if token else None
        user = db.get(User, session.user_id) if session else None
        if not session or session.expires_at < time.time() or not user or not user.enabled or user.deleted:
            raise HTTPException(401, '请登录管理后台')
        if request.method not in ['GET', 'HEAD'] and not hmac.compare_digest(request.headers.get('x-csrf-token', ''), session.csrf):
            raise HTTPException(403, '会话校验失败，请刷新页面')
        request.state.session = session
        return user

    def admin(user: User = Depends(current)):
        if user.role != 'admin':
            raise HTTPException(403, '此操作需要管理员权限')
        return user

    def establish(db, user, response, request):
        token = secrets.token_urlsafe(36)
        session = Session(id=digest(token), user_id=user.id, csrf=secrets.token_urlsafe(24), expires_at=time.time() + 8 * 3600)
        db.add(session)
        user.last_login = now()
        audit(db, user.username, '登录后台', user.display_name)
        db.commit()
        response.set_cookie(COOKIE, token, max_age=8 * 3600, httponly=True, samesite='strict', secure=request.url.scheme == 'https', path='/')
        return {'user': user_data(db, user), 'csrf': session.csrf}

    @app.get('/api/health')
    def health():
        return {'ok': True}

    @app.post('/api/auth/login')
    def login(body: Login, response: Response, request: Request, db: DatabaseSession = Depends(database)):
        address = request.client.host if request.client else 'unknown'
        with rate_lock:
            recent = [stamp for stamp in attempts.get(address, []) if stamp > time.time() - 60]
            if len(recent) >= 10:
                raise HTTPException(429, '尝试次数过多，请稍后再试')
            attempts[address] = recent + [time.time()]
        user = db.scalar(select(User).where(User.username == body.username))
        if not user or user.deleted or not user.enabled or not password_matches(body.password, user.password_hash):
            raise HTTPException(401, '账号或密码不正确')
        with rate_lock:
            attempts.pop(address, None)
        return establish(db, user, response, request)

    @app.post('/api/auth/launch')
    def launch_login(body: Launch, request: Request, response: Response, db: DatabaseSession = Depends(database)):
        with launch_lock:
            if launch['expires'] < time.time() or not hmac.compare_digest(digest(body.code), launch['hash']):
                raise HTTPException(401, '预览登录已使用或过期，请使用账号密码登录')
            launch.update(hash='', expires=0)
        user = db.scalar(select(User).where(User.role == 'admin', User.enabled == True, User.deleted == False))
        return establish(db, user, response, request)

    @app.get('/api/auth/me')
    def me(request: Request, user: User = Depends(current), db: DatabaseSession = Depends(database)):
        return {'user': user_data(db, user), 'csrf': request.state.session.csrf}

    @app.post('/api/auth/logout')
    def logout(request: Request, response: Response, user: User = Depends(current), db: DatabaseSession = Depends(database)):
        db.delete(request.state.session)
        db.commit()
        response.delete_cookie(COOKIE, path='/')
        return {'ok': True}

    @app.post('/api/auth/password')
    def password(body: ChangePassword, request: Request, user: User = Depends(current), db: DatabaseSession = Depends(database)):
        if not password_matches(body.current_password, user.password_hash):
            raise HTTPException(400, '当前密码不正确')
        user.password_hash = password_hash(body.new_password)
        db.execute(delete(Session).where(Session.user_id == user.id, Session.id != request.state.session.id))
        audit(db, user.username, '修改登录密码', user.display_name)
        db.commit()
        return {'ok': True}

    @app.get('/api/dashboard')
    def dashboard(user: User = Depends(current), db: DatabaseSession = Depends(database)):
        servers = db.scalars(select(Server)).all()
        if user.role != 'admin':
            servers = [s for s in servers if s.id in json.loads(user.regions)]
        tasks_query = select(Task).order_by(Task.created_at.desc()).limit(20)
        if user.role != 'admin':
            tasks_query = select(Task).where(Task.user_id == user.id).order_by(Task.created_at.desc()).limit(20)
        return {'servers': [server_data(s) for s in servers], 'me': user_data(db, user),
            'member_count': db.scalar(select(func.count()).select_from(User).where(User.deleted == False)) if user.role == 'admin' else 1,
            'tasks': [task_data(t) for t in db.scalars(tasks_query).all()],
            'base_cost': sum(s.monthly_price for s in servers), 'checked_at': now()}

    @app.get('/api/servers')
    def servers(user: User = Depends(admin), db: DatabaseSession = Depends(database)):
        return [server_data(s) for s in db.scalars(select(Server)).all()]

    @app.post('/api/servers/{code}/probe')
    def probe_server(code: str, user: User = Depends(admin), db: DatabaseSession = Depends(database)):
        if code != 'all' and not db.get(Server, code):
            raise HTTPException(404, '服务器不存在')
        task = queue_task(db, 'probe', '检查全部服务器' if code == 'all' else '检查' + REGIONS[code], actor_id=user.id, server_id=None if code == 'all' else code)
        audit(db, user.username, '服务器诊断', code)
        db.commit()
        return task_data(task)

    @app.post('/api/servers/{code}/verify')
    def verify_server(code: str, user: User = Depends(admin), db: DatabaseSession = Depends(database)):
        if code != 'all' and not db.get(Server, code):
            raise HTTPException(404, '服务器不存在')
        if not user_data(db, user)['ready']:
            raise HTTPException(409, '请等待自己的订阅同步完成后再验收')
        task = queue_task(db, 'verify', '验证全部入口' if code == 'all' else '验证' + REGIONS[code] + '入口', actor_id=user.id, server_id=None if code == 'all' else code)
        audit(db, user.username, '公网入口验收', code)
        db.commit()
        return task_data(task)

    @app.get('/api/nodes')
    def nodes(user: User = Depends(current), db: DatabaseSession = Depends(database)):
        result = []
        for server in db.scalars(select(Server)).all():
            if server.id not in json.loads(user.regions) or not server.packet_blob:
                continue
            for node in unseal(server.packet_blob)['configuration']['proxies']:
                result.append({'name': node['name'], 'type': node['type'], 'server_id': server.id,
                    'server': server.ip, 'port': node['port'], 'transport': 'UDP' if node['type'] == 'hysteria2' else 'TCP', 'health': server.health})
        return result

    @app.get('/api/members')
    def members(user: User = Depends(current), db: DatabaseSession = Depends(database)):
        query = select(User).where(User.deleted == False).order_by(User.created_at)
        if user.role != 'admin':
            query = query.where(User.id == user.id)
        return [user_data(db, member) for member in db.scalars(query).all()]

    @app.get('/api/speed-tests')
    def speed_tests(user: User = Depends(admin), db: DatabaseSession = Depends(database)):
        from .speedtest import PAYLOAD_BYTES, TIMEOUT_SECONDS
        active = db.scalar(select(Task).where(Task.kind == 'speedtest', Task.status.in_(['queued', 'running'])).limit(1))
        samples = db.scalars(select(NodeSpeed).where(NodeSpeed.user_id == user.id,
            NodeSpeed.server_id.in_(json.loads(user.regions)))).all()
        return {'active': task_data(active) if active else None,
            'samples': [json.loads(sample.result) for sample in samples],
            'payload_bytes': PAYLOAD_BYTES, 'timeout_seconds': TIMEOUT_SECONDS,
            'source': '管理后台所在设备', 'target': 'Cloudflare'}

    @app.post('/api/speed-tests', status_code=202)
    def start_speed_test(body: SpeedTest, user: User = Depends(admin), db: DatabaseSession = Depends(database)):
        if body.region != 'all' and body.region not in json.loads(user.regions):
            raise HTTPException(403, '只能测速自己的授权地区')
        if not user_data(db, user)['ready']:
            raise HTTPException(409, '请等待自己的订阅同步完成后再测速')
        if db.scalar(select(Task.id).where(Task.kind == 'speedtest', Task.status.in_(['queued', 'running'])).limit(1)):
            raise HTTPException(409, '已有下载测速任务，请等待完成')
        busy(db, user.id)
        label = '全部地区' if body.region == 'all' else REGIONS[body.region]
        task = queue_task(db, 'speedtest', label + '实际下载测速', actor_id=user.id, user_id=user.id,
                          server_id=None if body.region == 'all' else body.region)
        audit(db, user.username, '实际下载测速', label)
        db.commit()
        return task_data(task)

    @app.post('/api/members', status_code=201)
    def add_member(body: NewMember, user: User = Depends(admin), db: DatabaseSession = Depends(database)):
        if len(set(body.regions)) != len(body.regions):
            raise HTTPException(422, '地区不能重复')
        if db.scalar(select(User.id).where(User.username == body.username)):
            raise HTTPException(409, '账号已存在，请换一个账号名称')
        if db.scalar(select(func.count()).select_from(User)) >= 200:
            raise HTTPException(409, '当前版本最多支持 200 个成员记录')
        member, initial_password = create_member(db, **body.model_dump())
        task = queue_task(db, 'sync', '创建成员并同步凭据', actor_id=user.id, user_id=member.id)
        audit(db, user.username, '创建成员', member.display_name)
        db.commit()
        return {'member': user_data(db, member), 'initial_password': initial_password, 'task': task_data(task)}

    @app.patch('/api/members/{member_id}')
    def edit_member(member_id: str, body: EditMember, user: User = Depends(admin), db: DatabaseSession = Depends(database)):
        member = db.get(User, member_id)
        if not member or member.deleted:
            raise HTTPException(404, '成员不存在')
        busy(db, member.id)
        if len(set(body.regions)) != len(body.regions):
            raise HTTPException(422, '地区不能重复')
        if member.exit_region and member.exit_region not in body.regions:
            raise HTTPException(409, '请先调整该成员的固定出口，再移除对应地区授权')
        member.display_name, member.regions, member.note = body.display_name, json.dumps(body.regions), body.note
        member.revision += 1
        task = queue_task(db, 'sync', '更新成员授权地区', actor_id=user.id, user_id=member.id)
        audit(db, user.username, '编辑成员', member.display_name)
        db.commit()
        return task_data(task)

    @app.post('/api/members/{member_id}/actions')
    def member_action(member_id: str, body: MemberAction, user: User = Depends(current), db: DatabaseSession = Depends(database)):
        member = db.get(User, member_id)
        if not member or member.deleted:
            raise HTTPException(404, '成员不存在')
        if user.role != 'admin' and (member.id != user.id or body.action not in ['reset-link', 'reset-all', 'retry']):
            raise HTTPException(403, '无权操作此成员')
        if member.id == user.id and body.action in ['disable', 'delete', 'reset-password']:
            raise HTTPException(400, '自己的账号请使用修改密码；停用和删除需要由其他管理员操作')
        busy(db, member.id)
        if body.action == 'reset-password':
            password = secrets.token_urlsafe(14)
            member.password_hash = password_hash(password)
            db.execute(delete(Session).where(Session.user_id == member.id))
            audit(db, user.username, '重置成员登录密码', member.display_name)
            db.commit()
            return {'initial_password': password}
        context = None
        if body.action in ['reset-all', 'reset-link']:
            context = {'previous_token': unseal(member.token_blob)}
            if body.action == 'reset-all':
                context['previous_credentials'] = unseal(member.credential_blob)
                member.credential_blob = seal(new_credentials(['hk', 'sg', 'us']))
                member.credential_version += 1
            token = secrets.token_urlsafe(36)
            member.token_blob, member.token_digest = seal(token), digest(token)
        if body.action in ['disable', 'delete']:
            if member.role == 'admin' and db.scalar(select(func.count()).select_from(User).where(User.role == 'admin', User.enabled == True, User.deleted == False)) <= 1:
                raise HTTPException(400, '至少保留一位启用的管理员')
            member.enabled = False
            member.deleted = body.action == 'delete'
            db.execute(delete(Session).where(Session.user_id == member.id))
        elif body.action == 'enable':
            member.enabled = True
        if body.action != 'retry':
            member.revision += 1
        title = {'enable': '启用成员', 'disable': '停用成员并撤销凭据', 'delete': '删除成员并撤销凭据', 'reset-link': '重置订阅链接', 'reset-all': '轮换全部凭据', 'retry': '重试成员同步'}[body.action]
        task = queue_task(db, 'sync', title, actor_id=user.id, user_id=member.id)
        if context:
            task.context_blob = seal(context)
        audit(db, user.username, title, member.display_name)
        db.commit()
        return task_data(task)

    @app.get('/api/tasks')
    def tasks(user: User = Depends(current), db: DatabaseSession = Depends(database)):
        query = select(Task).order_by(Task.created_at.desc()).limit(100)
        if user.role != 'admin':
            query = select(Task).where(Task.user_id == user.id).order_by(Task.created_at.desc()).limit(100)
        return [task_data(task) for task in db.scalars(query).all()]

    @app.get('/api/tasks/{task_id}')
    def task_detail(task_id: str, user: User = Depends(current), db: DatabaseSession = Depends(database)):
        task = db.get(Task, task_id)
        if not task or (user.role != 'admin' and task.user_id != user.id):
            raise HTTPException(404, '任务不存在')
        return task_data(task)

    @app.post('/api/tasks/{task_id}/retry')
    def retry_task(task_id: str, user: User = Depends(admin), db: DatabaseSession = Depends(database)):
        old = db.get(Task, task_id)
        if not old or old.status not in ['failed', 'partial']:
            raise HTTPException(409, '仅失败或部分完成的任务可重试')
        if old.kind == 'speedtest' and (old.user_id != user.id or not user_data(db, user)['ready']):
            raise HTTPException(409, '请从节点管理为自己的有效订阅重新发起测速')
        if old.user_id:
            busy(db, old.user_id)
        task = queue_task(db, old.kind, '重试：' + old.title, actor_id=user.id, user_id=old.user_id, server_id=old.server_id)
        task.context_blob = old.context_blob
        audit(db, user.username, '重试任务', old.title)
        db.commit()
        return task_data(task)

    @app.get('/api/audit')
    def audit_records(user: User = Depends(admin), db: DatabaseSession = Depends(database)):
        return [{key: getattr(row, key) for key in ['id', 'actor', 'action', 'target', 'created_at']} for row in db.scalars(select(Audit).order_by(Audit.id.desc()).limit(200)).all()]

    @app.get('/api/audit.csv')
    def audit_export(user: User = Depends(admin), db: DatabaseSession = Depends(database)):
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['时间', '操作人', '操作', '对象'])
        for row in db.scalars(select(Audit).order_by(Audit.id.desc()).limit(10000)).all():
            values = [row.created_at, row.actor, row.action, row.target]
            writer.writerow(["'" + value if value.startswith(('=', '+', '-', '@', '\t', '\r')) else value for value in values])
        return Response('\ufeff' + output.getvalue(), media_type='text/csv; charset=utf-8', headers={'Content-Disposition': 'attachment; filename="self-vpn-audit.csv"'})

    @app.get('/api/routing')
    def routing(user: User = Depends(current), db: DatabaseSession = Depends(database)):
        us = db.get(Server, 'us')
        return {'regions': json.loads(user.regions), 'exit_region': user.exit_region, 'default_group': '地区自动回退', 'protocol_priority': 'hysteria2-first', 'domestic': 'DIRECT',
            'private_networks': 'DIRECT', 'other': '代理选择',
            'providers': [{'name': name, 'url': f'https://{us.ip}/team-rules/{name}.mrs', 'interval': 86400} for name in ['cn-domain', 'cn-ip']]}

    @app.patch('/api/routing/exit', status_code=202)
    def change_exit(body: ExitPolicy, user: User = Depends(current), db: DatabaseSession = Depends(database)):
        busy(db, user.id)
        if body.region and body.region not in json.loads(user.regions):
            raise HTTPException(403, '出口地区未授权')
        if body.region == user.exit_region:
            raise HTTPException(409, '出口策略未变化')
        if not user_data(db, user)['ready']:
            raise HTTPException(409, '请先完成当前订阅同步')
        user.exit_region = body.region
        user.revision += 1
        # Credentials and access did not change; only the client profile is new.
        for access in db.scalars(select(AccessState).where(AccessState.user_id == user.id)):
            access.applied_revision = user.revision
        label = '固定' + REGIONS[body.region] + '出口' if body.region else '恢复地区自动回退'
        task = queue_task(db, 'republish', label, actor_id=user.id, user_id=user.id)
        audit(db, user.username, '更新出口策略', label)
        db.commit()
        return task_data(task)

    @app.get('/api/settings')
    def settings(user: User = Depends(current)):
        return {'stack': ['React', 'TypeScript', 'Vite', 'FastAPI', 'SQLite', 'SQLAlchemy', 'Alembic'],
            'session_hours': 8, 'health_interval_seconds': 120, 'regions': REGIONS,
            'credential_policy': '每人、每地区独立凭据', 'mode': '本机管理后台 · SSH 连接三台 VPS',
            'subscription_hosting': '美国 VPS HTTPS · 独立订阅公开可下载'}

    if FRONTEND.exists():
        app.mount('/assets', StaticFiles(directory=FRONTEND / 'assets'), name='assets')
        @app.get('/')
        def index():
            return FileResponse(FRONTEND / 'index.html')

    return app

app = create_app()
