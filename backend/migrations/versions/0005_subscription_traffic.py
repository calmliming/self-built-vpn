"""Subscription display quotas and persisted per-server traffic snapshots."""
from alembic import op
import sqlalchemy as sa

revision = '0005'
down_revision = '0004'
branch_labels = None
depends_on = None

def upgrade():
    op.add_column('users', sa.Column('traffic_limit_bytes', sa.BigInteger(), nullable=True, server_default=str(500 * 1000**3)))
    op.add_column('users', sa.Column('traffic_period', sa.String(16), nullable=False, server_default='month'))
    op.add_column('users', sa.Column('include_legacy_traffic', sa.Boolean(), nullable=False, server_default=sa.false()))
    op.execute("UPDATE users SET include_legacy_traffic = 1 WHERE username = 'admin'")
    op.create_table('traffic_snapshots',
        sa.Column('server_id', sa.String(8), sa.ForeignKey('servers.id'), primary_key=True),
        sa.Column('data', sa.Text(), nullable=False),
        sa.Column('collected_at', sa.String(40), nullable=True),
        sa.Column('error', sa.Text(), nullable=True))
    op.create_index('uq_active_traffic', 'tasks', ['kind'], unique=True,
                    sqlite_where=sa.text("kind = 'traffic' AND status IN ('queued', 'running')"))

def downgrade():
    op.drop_index('uq_active_traffic', table_name='tasks')
    op.drop_table('traffic_snapshots')
    op.drop_column('users', 'include_legacy_traffic')
    op.drop_column('users', 'traffic_period')
    op.drop_column('users', 'traffic_limit_bytes')
