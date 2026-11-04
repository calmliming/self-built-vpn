"""A durable single executor; each VPS change waits for external acceptance."""
import fcntl
import json
import logging
from pathlib import Path
import threading
import time
import traceback
import hashlib
from types import SimpleNamespace
import signal
from sqlalchemy import select
from .config import RUNTIME
from .db import SessionLocal
from .models import Task, User, Server, AccessState, NodeSpeed, now
from .security import seal, unseal
from .services import queue_task
from . import remote
from .subscriptions import fleet, subscription_url

log = logging.getLogger('self-vpn.worker')

def task_event(task_id, step, status, message, **values):
    with SessionLocal.begin() as db:
        task = db.get(Task, task_id)
        events = json.loads(task.details)
        events.append({'step': step, 'status': status, 'message': message, 'at': now(), **values})
        task.details = json.dumps(events, ensure_ascii=False)

def update_health(server_id, report=None, error=None):
    with SessionLocal.begin() as db:
        server = db.get(Server, server_id)
        server.checked_at = now()
        server.error = error
        server.health = 'offline' if error else ('online' if report['healthy'] and (not report['team_managed'] or report['team_auth_active']) else 'degraded')
        if report:
            server.metrics = json.dumps(report)

def publication(user, servers, task_id, revoke=False, context=None):
    from verification import https_request
    us = next(s for s in servers if s.id == 'us')
    url = subscription_url(user, us)
    content = json.dumps(fleet(user, servers), ensure_ascii=False, indent=2) if not revoke else None
    data = {'user_id': user.id, 'token': None if revoke else unseal(user.token_blob)}
    if content:
        data.update(content=content, digest=hashlib.sha256(content.encode()).hexdigest())
    folder = RUNTIME / 'tasks' / task_id / 'publication'
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    task_event(task_id, 'subscription', 'running', '撤销公开订阅' if revoke else '发布并核对 HTTPS 订阅')
    def verify(receipt):
        if not revoke:
            metrics, body = https_request(url, folder, 'published', interface=remote.settings_for(us).verification_interface)
            if metrics['http'] != 200 or body != content.encode():
                raise RuntimeError('订阅 HTTPS 下载或内容校验失败')
            if context and context.get('previous_token'):
                old_url = f'https://{us.ip}/team-sub/{context["previous_token"]}/config.yaml'
                old_metrics, _ = https_request(old_url, folder, 'previous-link', interface=remote.settings_for(us).verification_interface)
                if old_metrics['http'] != 404:
                    raise RuntimeError('旧订阅链接未撤销')
    remote.transaction(us, 'publication', data, verify, folder)
    with SessionLocal.begin() as db:
        current = db.get(User, user.id)
        current.published_revision = 0 if revoke else user.revision
    task_event(task_id, 'subscription', 'succeeded', '公开订阅已撤销' if revoke else 'HTTPS 下载与内容校验通过')

def sync_task(task):
    from .checks import verify_member, verify_denied
    with SessionLocal() as db:
        servers = db.scalars(select(Server)).all()
        users = db.scalars(select(User)).all()
        user = db.get(User, task.user_id)
    for server in servers:
        if not server.packet_blob:
            packet = remote.export(server)
            server.packet_blob = seal(packet)
            with SessionLocal.begin() as db:
                db.get(Server, server.id).packet_blob = server.packet_blob
    us = next(s for s in servers if s.id == 'us')
    disabled = not user.enabled or user.deleted
    context = unseal(task.context_blob) if task.context_blob else {}
    if disabled:
        publication(user, servers, task.id, revoke=True)
    successful = 0
    for server in sorted(servers, key=lambda s: ['us', 'hk', 'sg'].index(s.id)):
        members = [{'id': u.id, 'version': u.credential_version, 'credential': unseal(u.credential_blob)[server.id]}
                   for u in users if u.enabled and not u.deleted and server.id in json.loads(u.regions)]
        task_event(task.id, server.id, 'running', '准备配置，等待公网认证验收')
        try:
            folder = RUNTIME / 'tasks' / task.id / server.id
            def verify(receipt):
                from team_agent import fingerprint
                if receipt['digest'] != fingerprint(members):
                    raise RuntimeError('服务器成员配置摘要不匹配')
                control = user if not disabled and server.id in json.loads(user.regions) else next((u for u in users if u.enabled and not u.deleted and u.id != user.id and server.id in json.loads(u.regions)), None)
                if control:
                    report = verify_member(control, server, us, folder)
                    if not report['verified']:
                        raise RuntimeError('公网节点验收失败')
                if disabled or server.id not in json.loads(user.regions):
                    verify_denied(user, server, folder)
                elif context.get('previous_credentials'):
                    old_user = SimpleNamespace(credential_blob=seal(context['previous_credentials']))
                    verify_denied(old_user, server, folder)
            receipt = remote.transaction(server, 'sync', {'members': members}, verify, folder)
            with SessionLocal.begin() as db:
                for member in users:
                    access = db.scalar(select(AccessState).where(AccessState.user_id == member.id, AccessState.server_id == server.id))
                    if not access:
                        access = AccessState(user_id=member.id, server_id=server.id)
                        db.add(access)
                    access.applied_revision = member.revision
                    access.applied_enabled = member.enabled and not member.deleted and server.id in json.loads(member.regions)
                    access.status, access.error, access.updated_at = 'synced', None, now()
            successful += 1
            task_event(task.id, server.id, 'succeeded', '旧凭据拒绝、其他成员连接正常' if disabled else '六个入口认证通过，配置已提交', member_count=receipt['member_count'])
            try:
                update_health(server.id, remote.probe(server))
            except Exception:
                pass
        except Exception as error:
            folder = RUNTIME / 'tasks' / task.id / server.id
            folder.mkdir(parents=True, mode=0o700, exist_ok=True)
            (folder / 'error.log').write_text(traceback.format_exc())
            (folder / 'error.log').chmod(0o600)
            with SessionLocal.begin() as db:
                access = db.scalar(select(AccessState).where(AccessState.user_id == user.id, AccessState.server_id == server.id))
                access.status, access.error = 'pending', '未完成同步，重试将自动核对并恢复'
            task_event(task.id, server.id, 'failed', '验收或连接未通过，保留待同步状态；详情已保存在私人任务日志')
            log.warning('Task %s server %s failed: %s', task.id, server.id, type(error).__name__)
    if successful == len(servers):
        if not disabled:
            publication(user, servers, task.id, context=context)
        return 'succeeded'
    return 'partial' if successful else 'failed'

def probe_task(task):
    with SessionLocal() as db:
        servers = db.scalars(select(Server).where(Server.id == task.server_id) if task.server_id else select(Server)).all()
    passed = 0
    for server in servers:
        task_event(task.id, server.id, 'running', '正在读取服务、证书与资源状态')
        try:
            report = remote.probe(server)
            update_health(server.id, report)
            task_event(task.id, server.id, 'succeeded' if report['healthy'] else 'failed', '诊断完成', checks=report['checks'])
            passed += int(report['healthy'])
        except Exception:
            update_health(server.id, error='SSH 连接或诊断失败')
            task_event(task.id, server.id, 'failed', 'SSH 连接或诊断失败')
    return 'succeeded' if passed == len(servers) else ('partial' if passed else 'failed')

def verify_task(task):
    from .checks import verify_member
    with SessionLocal() as db:
        servers = db.scalars(select(Server)).all()
        user = db.get(User, task.actor_id)
    us = next(s for s in servers if s.id == 'us')
    passed, count = 0, 0
    for server in servers:
        if task.server_id and server.id != task.server_id:
            continue
        if server.id not in json.loads(user.regions):
            continue
        count += 1
        task_event(task.id, server.id, 'running', '使用独立客户端验证六个入口')
        try:
            verify_member(user, server, us, RUNTIME / 'tasks' / task.id / server.id)
            passed += 1
            task_event(task.id, server.id, 'succeeded', '六个入口、DNS、国内直连均通过')
        except Exception:
            task_event(task.id, server.id, 'failed', '公网验收失败，请查看该地区状态')
    return 'succeeded' if passed == count and count else ('partial' if passed else 'failed')

def speedtest_task(task):
    from .speedtest import measure_nodes
    from .subscriptions import member_nodes
    with SessionLocal() as db:
        user = db.get(User, task.user_id)
        servers = db.scalars(select(Server)).all()
    if not user or not user.enabled or user.deleted:
        raise RuntimeError('测速账号已停用')
    regions = json.loads(user.regions)
    credentials = unseal(user.credential_blob)
    passed, total = 0, 0
    def record(server, node, sample):
        nonlocal passed, total
        stamp = now()
        measured = sample['mbps'] is not None
        result = {**sample, 'server_id': server.id, 'node_name': node['name'], 'protocol': node['type'], 'tested_at': stamp}
        with SessionLocal.begin() as db:
            db.merge(NodeSpeed(user_id=user.id, server_id=server.id, node_name=node['name'],
                task_id=task.id, tested_at=stamp, result=json.dumps(result, ensure_ascii=False)))
        message = f"{node['name']} · {sample['mbps']:.2f} Mbps · {sample['message']}" if measured else f"{node['name']} · {sample['message']}"
        task_event(task.id, server.id, 'succeeded' if measured else 'failed', message, speed=result)
        total += 1
        passed += int(measured)
    for server in sorted(servers, key=lambda item: regions.index(item.id) if item.id in regions else 99):
        if server.id not in regions or (task.server_id and server.id != task.server_id):
            continue
        nodes = member_nodes(server, credentials[server.id])
        completed = set()
        def started(node):
            task_event(task.id, server.id, 'running', '正在下载测速：' + node['name'], node_name=node['name'])
        try:
            for node, sample in measure_nodes(server, nodes, started):
                record(server, node, sample)
                completed.add(node['name'])
        except Exception:
            log.warning('Speed test failed for region %s', server.id)
            for node in nodes:
                if node['name'] not in completed:
                    record(server, node, {'status': 'failed', 'mbps': None, 'bytes': 0, 'seconds': None,
                                          'message': '测速客户端或连接异常，请稍后重测'})
    task_event(task.id, 'speedtest', 'succeeded' if total and passed == total else 'failed', f'完成 {total} 个入口采样，{passed} 个取得下载速率')
    return 'succeeded' if total and passed == total else 'partial' if passed else 'failed'

def republish_task(task):
    """Only refresh the subscription; keep existing authentication services running."""
    with SessionLocal() as db:
        user = db.get(User, task.user_id)
        servers = db.scalars(select(Server)).all()
        access = db.scalars(select(AccessState).where(AccessState.user_id == task.user_id)).all()
    if (not user or not user.enabled or user.deleted or len(access) != len(servers)
            or any(a.status != 'synced' or a.applied_revision != user.revision for a in access)):
        raise RuntimeError('成员尚未完成同步，不能刷新订阅')
    from .checks import verify_fleet
    report = verify_fleet(fleet(user, servers), servers, RUNTIME / 'tasks' / task.id / 'acceptance')
    if not report.get('verified'):
        raise RuntimeError('订阅策略验收未通过')
    publication(user, servers, task.id)
    return 'succeeded'

class Worker:
    def __init__(self):
        self.stop_event = threading.Event()
        self.thread = None
        self.lock = None

    def start(self):
        self.lock = (RUNTIME / '.worker.lock').open('a')
        fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with SessionLocal.begin() as db:
            for task in db.scalars(select(Task).where(Task.status == 'running')).all():
                task.status = 'queued'
                task.error = '执行器重启，将重新核对任务状态'
        self.thread = threading.Thread(target=self.loop, daemon=True)
        self.thread.start()

    def loop(self):
        last_probe = time.monotonic()
        while not self.stop_event.is_set():
            task = None
            try:
                with SessionLocal.begin() as db:
                    task = db.scalar(select(Task).where(Task.status == 'queued').order_by(Task.created_at, Task.id).limit(1))
                    if task:
                        task.status, task.error = 'running', None
                if task:
                    status = {'sync': sync_task, 'probe': probe_task, 'verify': verify_task,
                              'speedtest': speedtest_task, 'republish': republish_task}[task.kind](task)
                    with SessionLocal.begin() as db:
                        current = db.get(Task, task.id)
                        current.status, current.finished_at = status, now()
                elif time.monotonic() - last_probe > 120:
                    with SessionLocal.begin() as db:
                        queue_task(db, 'probe', '定时服务器状态检查')
                    last_probe = time.monotonic()
            except Exception as error:
                log.warning('Worker task failed: %s', type(error).__name__)
                if task:
                    folder = RUNTIME / 'tasks' / task.id
                    folder.mkdir(parents=True, mode=0o700, exist_ok=True)
                    (folder / 'error.log').write_text(traceback.format_exc())
                    (folder / 'error.log').chmod(0o600)
                    with SessionLocal.begin() as db:
                        current = db.get(Task, task.id)
                        current.status, current.error, current.finished_at = 'failed', '任务未完成，请重试；服务器中断状态会在重试时恢复', now()
            self.stop_event.wait(1)

    def stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=2)
        if self.lock and not self.thread.is_alive():
            self.lock.close()

if __name__ == '__main__':
    worker = Worker()
    worker.start()
    def finish(number, frame):
        worker.stop_event.set()
    for number in [signal.SIGTERM, signal.SIGINT]:
        signal.signal(number, finish)
    while worker.thread.is_alive():
        worker.thread.join(timeout=1)
    worker.lock.close()
