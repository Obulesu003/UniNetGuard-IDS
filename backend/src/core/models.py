from pydantic_settings import BaseSettings
from functools import lru_cache
import uuid


class Settings(BaseSettings):
    database_url: str = "sqlite+aiosqlite:///./ids.db"
    capture_interface: str = "eth0"
    capture_filter: str = ""
    log_level: str = "INFO"

    class Config:
        env_file = ".env"


@lru_cache
def get_settings() -> Settings:
    return Settings()


def generate_uuid():
    return str(uuid.uuid4())
