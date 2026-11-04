from datetime import datetime, timezone
from sqlalchemy import String, Text, Integer, BigInteger, Boolean, Float, ForeignKey, UniqueConstraint, Index, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from .security import identity

def now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')

class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = 'users'
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=identity)
    username: Mapped[str] = mapped_column(String(40), unique=True)
    display_name: Mapped[str] = mapped_column(String(60))
    role: Mapped[str] = mapped_column(String(16), default='member')
    password_hash: Mapped[str] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    deleted: Mapped[bool] = mapped_column(Boolean, default=False)
    regions: Mapped[str] = mapped_column(Text, default='["hk","sg","us"]')
    exit_region: Mapped[str | None] = mapped_column(String(8), nullable=True)
    traffic_limit_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True, default=500 * 1024**3)
    traffic_period: Mapped[str] = mapped_column(String(16), default='month')
    traffic_enforced: Mapped[bool] = mapped_column(Boolean, default=True)
    include_legacy_traffic: Mapped[bool] = mapped_column(Boolean, default=False)
    credential_blob: Mapped[str] = mapped_column(Text)
    token_blob: Mapped[str] = mapped_column(Text)
    token_digest: Mapped[str] = mapped_column(String(64), unique=True)
    revision: Mapped[int] = mapped_column(Integer, default=1)
    credential_version: Mapped[int] = mapped_column(Integer, default=1)
    published_revision: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[str] = mapped_column(String(40), default=now)
    last_login: Mapped[str | None] = mapped_column(String(40), nullable=True)
    note: Mapped[str] = mapped_column(Text, default='')

class Session(Base):
    __tablename__ = 'sessions'
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey('users.id', ondelete='CASCADE'))
    csrf: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[float] = mapped_column(Float)

class Server(Base):
    __tablename__ = 'servers'
    id: Mapped[str] = mapped_column(String(8), primary_key=True)
    name: Mapped[str] = mapped_column(String(60))
    region: Mapped[str] = mapped_column(String(40))
    country: Mapped[str] = mapped_column(String(4))
    ip: Mapped[str] = mapped_column(String(40))
    config_path: Mapped[str] = mapped_column(Text)
    packet_blob: Mapped[str | None] = mapped_column(Text, nullable=True)
    health: Mapped[str] = mapped_column(String(16), default='unknown')
    metrics: Mapped[str] = mapped_column(Text, default='{}')
    checked_at: Mapped[str | None] = mapped_column(String(40), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    monthly_price: Mapped[float] = mapped_column(Float, default=12)

class AccessState(Base):
    __tablename__ = 'access_states'
    __table_args__ = (UniqueConstraint('user_id', 'server_id'),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey('users.id'))
    server_id: Mapped[str] = mapped_column(ForeignKey('servers.id'))
    applied_revision: Mapped[int] = mapped_column(Integer, default=0)
    applied_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(20), default='pending')
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    updated_at: Mapped[str | None] = mapped_column(String(40), nullable=True)

class Task(Base):
    __tablename__ = 'tasks'
    __table_args__ = (
        Index('uq_active_member_sync', 'user_id', unique=True, sqlite_where=text("kind = 'sync' AND status IN ('queued', 'running')")),
        Index('uq_active_speedtest', 'kind', unique=True, sqlite_where=text("kind = 'speedtest' AND status IN ('queued', 'running')")),
        Index('uq_active_traffic', 'kind', unique=True, sqlite_where=text("kind = 'traffic' AND status IN ('queued', 'running')")),
    )
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=identity)
    kind: Mapped[str] = mapped_column(String(24))
    title: Mapped[str] = mapped_column(String(120))
    user_id: Mapped[str | None] = mapped_column(ForeignKey('users.id'), nullable=True)
    server_id: Mapped[str | None] = mapped_column(ForeignKey('servers.id'), nullable=True)
    actor_id: Mapped[str | None] = mapped_column(ForeignKey('users.id'), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default='queued')
    details: Mapped[str] = mapped_column(Text, default='[]')
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    context_blob: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[str] = mapped_column(String(40), default=now)
    finished_at: Mapped[str | None] = mapped_column(String(40), nullable=True)

class NodeSpeed(Base):
    __tablename__ = 'node_speeds'
    user_id: Mapped[str] = mapped_column(ForeignKey('users.id'), primary_key=True)
    server_id: Mapped[str] = mapped_column(ForeignKey('servers.id'), primary_key=True)
    node_name: Mapped[str] = mapped_column(String(100), primary_key=True)
    task_id: Mapped[str] = mapped_column(ForeignKey('tasks.id'))
    tested_at: Mapped[str] = mapped_column(String(40))
    result: Mapped[str] = mapped_column(Text)

class TrafficSnapshot(Base):
    __tablename__ = 'traffic_snapshots'
    server_id: Mapped[str] = mapped_column(ForeignKey('servers.id'), primary_key=True)
    data: Mapped[str] = mapped_column(Text, default='{}')
    collected_at: Mapped[str | None] = mapped_column(String(40), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

class Audit(Base):
    __tablename__ = 'audit'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor: Mapped[str] = mapped_column(String(60))
    action: Mapped[str] = mapped_column(String(80))
    target: Mapped[str] = mapped_column(String(120))
    created_at: Mapped[str] = mapped_column(String(40), default=now)
