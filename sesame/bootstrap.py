from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SESAME_", env_file=".env", env_file_encoding="utf-8", extra="ignore")

    deepseek_api_key: str = ""
    deepseek_api_base: str = ""
    deepseek_model: str = "deepseek-v4-pro"
    deepseek_temperature: float = 0.0
    deepseek_thinking: bool = True  # Enable deep thinking / reasoning mode

    http_timeout: float = 8.0
    max_context_chars: int = 8000
    max_targets: int = 128
    debug: bool = False


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
