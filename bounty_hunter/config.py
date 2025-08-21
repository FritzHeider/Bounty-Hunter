from __future__ import annotations
from pydantic_settings import BaseSettings
from pydantic import Field, field_validator

class Settings(BaseSettings):
    # Networking
    TIMEOUT_S: int = Field(default=15, env="BH_TIMEOUT_S")
    RETRIES: int = Field(default=2, env="BH_RETRY")
    MAX_CONCURRENCY: int = Field(default=40, env="BH_MAX_CONCURRENCY")
    PER_HOST: int = Field(default=5, env="BH_PER_HOST")
    MAX_RESPONSE_SIZE: int = Field(default=1024 * 1024, env="BH_MAX_RESPONSE_SIZE")
    MAX_REDIRECT_DEPTH: int = Field(default=3, env="BH_MAX_REDIRECT_DEPTH")
    JITTER_S: float = Field(default=0.0, env="BH_JITTER_S")
    ALLOWED_HOSTS: list[str] = Field(default_factory=list, env="BH_ALLOWED_HOSTS")

    # LLM
    LLM_PROVIDER: str = "none"  # none|openai
    OPENAI_API_KEY: str | None = None
    OPENAI_MODEL: str = Field(default="gpt-4o-mini")

    # OOB SSRF
    OOB_ENABLED: bool = False
    CANARY_DOMAIN: str | None = Field(default=None)
    CANARY_LABEL_PREFIX: str = Field(default="bh-ssrf")

    # Interactsh (optional)
    INTERACTSH_SERVER: str | None = Field(default=None)
    INTERACTSH_TOKEN: str | None = Field(default=None)
    INTERACTSH_POLL_SECONDS: int = Field(default=8)

    # Fingerprinter DB (optional local file)
    CVE_FAVICON_DB: str | None = Field(default=None)

    @field_validator("ALLOWED_HOSTS", mode="before")
    @classmethod
    def split_hosts(cls, v: str | list[str]) -> list[str]:
        if isinstance(v, str):
            return [h.strip() for h in v.split(",") if h.strip()]
        return v

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}
