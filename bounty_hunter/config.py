from __future__ import annotations
from pydantic_settings import BaseSettings
from pydantic import Field

class Settings(BaseSettings):
    # Networking
    TIMEOUT_S: int = Field(default=15, env="BH_TIMEOUT_S")
    RETRIES: int = Field(default=2, env="BH_RETRY")
    MAX_CONCURRENCY: int = Field(default=40, env="BH_MAX_CONCURRENCY")
    PER_HOST: int = Field(default=5, env="BH_PER_HOST")

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

    # Findings
    CONFIDENCE_THRESHOLD: float = Field(default=0.5, env="BH_CONFIDENCE_THRESHOLD")

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}
