"""Initial frozen team schema; future model changes require new migrations."""
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

SCHEMA = ['CREATE TABLE audit (\n\tid INTEGER NOT NULL, \n\tactor VARCHAR(60) NOT NULL, \n\taction VARCHAR(80) NOT NULL, \n\ttarget VARCHAR(120) NOT NULL, \n\tcreated_at VARCHAR(40) NOT NULL, \n\tPRIMARY KEY (id)\n)', 'CREATE TABLE servers (\n\tid VARCHAR(8) NOT NULL, \n\tname VARCHAR(60) NOT NULL, \n\tregion VARCHAR(40) NOT NULL, \n\tcountry VARCHAR(4) NOT NULL, \n\tip VARCHAR(40) NOT NULL, \n\tconfig_path TEXT NOT NULL, \n\tpacket_blob TEXT, \n\thealth VARCHAR(16) NOT NULL, \n\tmetrics TEXT NOT NULL, \n\tchecked_at VARCHAR(40), \n\terror TEXT, \n\tmonthly_price FLOAT NOT NULL, \n\tPRIMARY KEY (id)\n)', 'CREATE TABLE users (\n\tid VARCHAR(32) NOT NULL, \n\tusername VARCHAR(40) NOT NULL, \n\tdisplay_name VARCHAR(60) NOT NULL, \n\trole VARCHAR(16) NOT NULL, \n\tpassword_hash TEXT NOT NULL, \n\tenabled BOOLEAN NOT NULL, \n\tdeleted BOOLEAN NOT NULL, \n\tregions TEXT NOT NULL, \n\tcredential_blob TEXT NOT NULL, \n\ttoken_blob TEXT NOT NULL, \n\ttoken_digest VARCHAR(64) NOT NULL, \n\trevision INTEGER NOT NULL, \n\tcredential_version INTEGER NOT NULL, \n\tpublished_revision INTEGER NOT NULL, \n\tcreated_at VARCHAR(40) NOT NULL, \n\tlast_login VARCHAR(40), \n\tnote TEXT NOT NULL, \n\tPRIMARY KEY (id), \n\tUNIQUE (username), \n\tUNIQUE (token_digest)\n)', 'CREATE TABLE access_states (\n\tid INTEGER NOT NULL, \n\tuser_id VARCHAR(32) NOT NULL, \n\tserver_id VARCHAR(8) NOT NULL, \n\tapplied_revision INTEGER NOT NULL, \n\tapplied_enabled BOOLEAN NOT NULL, \n\tstatus VARCHAR(20) NOT NULL, \n\terror TEXT, \n\tupdated_at VARCHAR(40), \n\tPRIMARY KEY (id), \n\tUNIQUE (user_id, server_id), \n\tFOREIGN KEY(user_id) REFERENCES users (id), \n\tFOREIGN KEY(server_id) REFERENCES servers (id)\n)', 'CREATE TABLE sessions (\n\tid VARCHAR(64) NOT NULL, \n\tuser_id VARCHAR(32) NOT NULL, \n\tcsrf VARCHAR(64) NOT NULL, \n\texpires_at FLOAT NOT NULL, \n\tPRIMARY KEY (id), \n\tFOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE\n)', 'CREATE TABLE tasks (\n\tid VARCHAR(32) NOT NULL, \n\tkind VARCHAR(24) NOT NULL, \n\ttitle VARCHAR(120) NOT NULL, \n\tuser_id VARCHAR(32), \n\tserver_id VARCHAR(8), \n\tactor_id VARCHAR(32), \n\tstatus VARCHAR(20) NOT NULL, \n\tdetails TEXT NOT NULL, \n\terror TEXT, \n\tcontext_blob TEXT, \n\tcreated_at VARCHAR(40) NOT NULL, \n\tfinished_at VARCHAR(40), \n\tPRIMARY KEY (id), \n\tFOREIGN KEY(user_id) REFERENCES users (id), \n\tFOREIGN KEY(server_id) REFERENCES servers (id), \n\tFOREIGN KEY(actor_id) REFERENCES users (id)\n)']

def upgrade():
    for statement in SCHEMA:
        op.execute(statement)

def downgrade():
    op.drop_table('tasks')
    op.drop_table('sessions')
    op.drop_table('access_states')
    op.drop_table('users')
    op.drop_table('servers')
    op.drop_table('audit')
