from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker,DeclarativeBase
from api.app.core.settings import settings

class Base(DeclarativeBase):
    pass

connect_args={"check_same_thread":False} if settings.DATABASE_URL.startswith("sqlite") else {}
engine= create_engine(settings.DATABASE_URL, connect_args=connect_args, future=True)
LocalSession= sessionmaker(bind=engine, autoflush=False, autocommit=False,future=True)

def RetrieveBD():
    db= LocalSession()

    try:
        yield db
    finally:
        db.close()

def init_db():
    Base.metadata.create_all(bind=engine)
    