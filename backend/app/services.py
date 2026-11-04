import json
import secrets
from sqlalchemy import select
from .config import STATE, INVENTORY
from .db import SessionLocal
from .models import User, Server, AccessState, Task, Audit
from .security import identity, new_credentials, seal, password_hash, digest

def queue_task(db, kind, title, actor_id=None, user_id=None, server_id=None):
    task = Task(kind=kind, title=title, actor_id=actor_id, user_id=user_id, server_id=server_id)
    db.add(task)
    db.flush()
    return task

def audit(db, actor, action, target):
    db.add(Audit(actor=actor, action=action, target=target))

def create_member(db, username, display_name, role='member', password=None, regions=None, note=''):
    token = secrets.token_urlsafe(36)
    initial_password = password or secrets.token_urlsafe(14)
    codes = [s.id for s in db.scalars(select(Server)).all()]
    user = User(id=identity(), username=username, display_name=display_name, role=role,
        password_hash=password_hash(initial_password), regions=json.dumps(regions or ['hk', 'sg', 'us']),
        credential_blob=seal(new_credentials(codes)), token_blob=seal(token), token_digest=digest(token), note=note)
    db.add(user)
    db.flush()
    for code in codes:
        db.add(AccessState(user_id=user.id, server_id=code))
    return user, initial_password

def bootstrap():
    with SessionLocal.begin() as db:
        if not db.scalar(select(Server.id).limit(1)):
            inventory = json.loads((INVENTORY / 'inventory.json').read_text())
            for code in ['hk', 'sg', 'us']:
                item = inventory['servers'][code]
                db.add(Server(id=code, name=item['label'], region=item['region'], country=item['country'],
                    ip=item['public_ip'], config_path=str(INVENTORY / (code + '.env')), monthly_price=item['monthly_price_usd']))
        if not db.scalar(select(User.id).limit(1)):
            db.flush()
            user, password = create_member(db, 'admin', '管理员', 'admin')
            user.include_legacy_traffic = True
            path = STATE / '管理员登录.txt'
            path.write_text('Self VPN 管理后台\n账号：admin\n密码：' + password + '\n请登录后在系统设置中修改密码。\n此文件与 master.key、panel.db 均属于私人数据。\n', encoding='utf-8')
            path.chmod(0o600)
            queue_task(db, 'sync', '初始化我的独立订阅', actor_id=user.id, user_id=user.id)
            queue_task(db, 'probe', '连接三台服务器', actor_id=user.id)

def task_data(task):
    return {key: getattr(task, key) for key in ['id', 'kind', 'title', 'user_id', 'server_id', 'status', 'error', 'created_at', 'finished_at']} | {'details': json.loads(task.details)}
