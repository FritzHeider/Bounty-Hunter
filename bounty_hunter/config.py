"""Placeholder config module.
Replace with pydantic BaseSettings-based configuration when implementing.
"""
class Settings:
    TIMEOUT_S = 15
    RETRIES = 1
    MAX_CONCURRENCY = 20
    PER_HOST = 5
    LLM_PROVIDER = "none"
    OPENAI_API_KEY = None
    OPENAI_MODEL = "gpt-4o-mini"
    OOB_ENABLED = False
    CANARY_DOMAIN = None
    CANARY_LABEL_PREFIX = "bh-ssrf"
    INTERACTSH_SERVER = None
    INTERACTSH_TOKEN = None
    INTERACTSH_POLL_SECONDS = 8
    CVE_FAVICON_DB = None
