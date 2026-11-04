"""Serialize member mutations even when two requests arrive together."""
from alembic import op
from sqlalchemy import inspect, text

revision = '0002'
down_revision = '0001'
branch_labels = None
depends_on = None

def upgrade():
    indexes = {index['name'] for index in inspect(op.get_bind()).get_indexes('tasks')}
    if 'uq_active_member_sync' not in indexes:
        op.create_index('uq_active_member_sync', 'tasks', ['user_id'], unique=True, sqlite_where=text("kind = 'sync' AND status IN ('queued', 'running')"))

def downgrade():
    op.drop_index('uq_active_member_sync', table_name='tasks')
