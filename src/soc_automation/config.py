"""Environment-backed configuration with safe lab defaults."""

from __future__ import annotations

import os
from dataclasses import dataclass


def _bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    api_token: str = os.getenv("AUTOMATION_API_TOKEN", "local-demo-token")
    audit_path: str = os.getenv("AUDIT_LOG_PATH", "data/audit.jsonl")
    cache_path: str = os.getenv("CACHE_PATH", "data/cache.sqlite")
    blocklist_path: str = os.getenv("LAB_BLOCKLIST_PATH", "data/lab-blocklist.txt")
    dry_run: bool = _bool("DRY_RUN", True)
    enrich_public_iocs: bool = _bool("ENRICH_PUBLIC_IOCS", False)
    min_rule_level: int = int(os.getenv("MIN_RULE_LEVEL", "7"))
    allowlist_path: str = os.getenv("ALLOWLIST_PATH", "config/allowlist.example.txt")
    vt_api_key: str = os.getenv("VT_API_KEY", "")
    abuseipdb_api_key: str = os.getenv("ABUSEIPDB_API_KEY", "")
    otx_api_key: str = os.getenv("OTX_API_KEY", "")
    thehive_url: str = os.getenv("THEHIVE_URL", "")
    thehive_api_key: str = os.getenv("THEHIVE_API_KEY", "")
    thehive_org: str = os.getenv("THEHIVE_ORG", "")
    slack_webhook_url: str = os.getenv("SLACK_WEBHOOK_URL", "")
    slack_signing_secret: str = os.getenv("SLACK_SIGNING_SECRET", "")
    telegram_bot_token: str = os.getenv("TELEGRAM_BOT_TOKEN", "")
    telegram_chat_id: str = os.getenv("TELEGRAM_CHAT_ID", "")
    telegram_webhook_secret: str = os.getenv("TELEGRAM_WEBHOOK_SECRET", "")
    request_timeout: float = float(os.getenv("REQUEST_TIMEOUT_SECONDS", "8"))


settings = Settings()
