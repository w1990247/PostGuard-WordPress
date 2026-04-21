from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field 
from typing import Optional


class Settings(BaseSettings):

    model_config= SettingsConfigDict(env_file=".env", extra ="ignore", env_file_encoding="utf-8")

    API_PREFIX: str="/api"

    API_KEYS: str = Field(default="")

    REPLAY_WINDOW_SECONDS: int=120
    RATE_LIMIT_PER_MINUTE:int=60

    DATABASE_URL: str ="sqlite:///./postguard.db"
    AUDIT_LOG_PATH: str="./data/audit_log.jsonl"
    AUDIT_ROOT_HASH_PATH: str= "./data/audit_root_hash.txt"
    AUDIT_BACKUP_DIR: str="./data/audit_backups"
    AUDIT_ROTATE_MAX_BYTES: int= 1_000_000
    AUDIT_BACKUP_COUNT: int=5

    CORRELATION_SECONDS: int= 120
    BURST_WINDOW_SECONDS: int=20
    BURST_THRESHOLD: int=4

    REDIS: bool=True
    REDIS_URL: str="redis://localhost:6379/0"
    REDIS_PREFIX: str="postguard"

    JWT_SECRET: str= Field(default="")
    JWT_ALG: str= "HS256"
    JWT_EXPIRE_MINUTES: int = 120
    BOOTSTRAP_ADMIN_EMAIL: Optional[str] =None
    BOOTSTRAP_ADMIN_PASSWORD: Optional[str]= None
    BOOTSTRAP_ANALYST_EMAIL: Optional[str] =None
    BOOTSTRAP_ANALYST_PASSWORD: Optional[str]= None

    DEFAULT_WATCH_PATHS: str=Field(default="")
    DEFAULT_WATCH_IGNORE_PATHS: str=Field(default="")
    WATCHER_SCOPE_FILE: str="./data/watcher_scope.json"

    SMTP_HOST: str=""
    SMTP_PORT: str=587
    SMTP_USER: str=""
    SMTP_PASS:str=""
    SMTP_FROM:str="postguard@local"
    SMTP_TLS: bool=True

    API_BASE_URL: str="https://localhost"
    PG_INTERNAL_INGEST_URL: str = "http://caddy/api/events/ingest"

    SCORER_POLL_SECONDS: float=1.0
    SCORER_BATCH_SIZE: int=25

    ML_MODEL_PATH: str="./data/ml_model.pkl"



settings=Settings()

def parsed_api_keys()-> dict[str,str]:
    out:dict[str,str]={}
    raw = (settings.API_KEYS or "").strip()

    if not raw:
        return out
    
    for part in raw.split(";"):
        part = part.strip()

        if not part or ":" not in part:
            continue

        keyID,Secret=part.split(":",1)
        out[keyID.strip()]=Secret.strip()
    return out

def parse_csv_list(raw:str|None)-> list[str]:
    if not raw:
        return[]
    return [part.strip() for part in raw.split(",") if part.strip()]
