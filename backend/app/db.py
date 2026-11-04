from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from .config import STATE, prepare_directories

prepare_directories()
engine = create_engine('sqlite:///' + str(STATE / 'panel.db'), connect_args={'check_same_thread': False, 'timeout': 15})
@event.listens_for(engine, 'connect')
def sqlite_setup(connection, record):
    cursor = connection.cursor()
    cursor.execute('PRAGMA foreign_keys=ON')
    cursor.execute('PRAGMA journal_mode=WAL')
    cursor.execute('PRAGMA busy_timeout=15000')
    cursor.close()

SessionLocal = sessionmaker(engine, expire_on_commit=False)

def migrate():
    from alembic.config import Config
    from alembic import command
    from .config import ROOT
    config = Config(str(ROOT / 'alembic.ini'))
    config.set_main_option('script_location', str(ROOT / 'migrations'))
    config.set_main_option('sqlalchemy.url', str(engine.url))
    command.upgrade(config, 'head')
    (STATE / 'panel.db').chmod(0o600)
