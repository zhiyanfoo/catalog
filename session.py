from contextlib import contextmanager

from sqlalchemy import create_engine
from models import Base
from sqlalchemy.orm import sessionmaker

engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)


@contextmanager
def session_scope():
    session = DBSession()
    yield session
    try:
        session.commit()
    finally:
        session.close()
