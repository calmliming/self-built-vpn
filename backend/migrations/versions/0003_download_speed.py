"""Persist the latest node samples and serialize bandwidth measurements."""
from alembic import op
import sqlalchemy as sa

revision = '0003'
down_revision = '0002'
branch_labels = None
depends_on = None

def upgrade():
    op.create_table('node_speeds',
        sa.Column('user_id', sa.String(32), sa.ForeignKey('users.id'), primary_key=True),
        sa.Column('server_id', sa.String(8), sa.ForeignKey('servers.id'), primary_key=True),
        sa.Column('node_name', sa.String(100), primary_key=True),
        sa.Column('task_id', sa.String(32), sa.ForeignKey('tasks.id'), nullable=False),
        sa.Column('tested_at', sa.String(40), nullable=False),
        sa.Column('result', sa.Text(), nullable=False))
    op.create_index('uq_active_speedtest', 'tasks', ['kind'], unique=True,
        sqlite_where=sa.text("kind = 'speedtest' AND status IN ('queued', 'running')"))

def downgrade():
    op.drop_index('uq_active_speedtest', table_name='tasks')
    op.drop_table('node_speeds')
