"""Store settings shared across the management panel."""
from alembic import op
import sqlalchemy as sa

revision = '0007'
down_revision = '0006'
branch_labels = None
depends_on = None

def upgrade():
    op.create_table('panel_settings',
        sa.Column('key', sa.String(40), primary_key=True),
        sa.Column('value', sa.String(60), nullable=False),
    )

def downgrade():
    op.drop_table('panel_settings')
