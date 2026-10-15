from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """本地模拟服务配置。"""

    app_name: str = "网络安全运营模拟数据 API"
    app_version: str = "0.1.0"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


@lru_cache
def get_settings() -> Settings:
    return Settings()
