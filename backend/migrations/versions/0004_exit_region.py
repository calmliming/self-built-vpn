"""Keep a member's automatic traffic in a chosen exit region."""
from alembic import op
import sqlalchemy as sa

revision = '0004'
down_revision = '0003'
branch_labels = None
depends_on = None

def upgrade():
    op.add_column('users', sa.Column('exit_region', sa.String(8), nullable=True))

def downgrade():
    op.drop_column('users', 'exit_region')
