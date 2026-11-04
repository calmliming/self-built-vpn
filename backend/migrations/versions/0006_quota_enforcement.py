"""Enable member-bound, server-side traffic quota enforcement."""
from alembic import op
import sqlalchemy as sa

revision = '0006'
down_revision = '0005'
branch_labels = None
depends_on = None

def upgrade():
    op.add_column('users', sa.Column('traffic_enforced', sa.Boolean(), nullable=False, server_default=sa.true()))

def downgrade():
    op.drop_column('users', 'traffic_enforced')
