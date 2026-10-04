"""Configuration loaded from environment variables / .env file."""

import os
from dotenv import load_dotenv

load_dotenv()

# --- Required ---
BOT_TOKEN: str = os.getenv("BOT_TOKEN", "")

# --- Authorization ---
# PUBLIC_ACCESS=true lets ANY Telegram user use the bot.
# When false, only user IDs in ALLOWED_USERS are allowed.
PUBLIC_ACCESS: bool = (
    os.getenv("PUBLIC_ACCESS", "false").strip().lower() in ("1", "true", "yes", "on")
)
# Comma-separated Telegram user IDs allowed to use the bot.
ALLOWED_USERS: set[int] = set()
_raw_users = os.getenv("ALLOWED_USERS", "")
if _raw_users:
    for _u in _raw_users.split(","):
        _u = _u.strip()
        if _u:
            ALLOWED_USERS.add(int(_u))

# --- Blocklist ---
# Comma-separated CIDR ranges that must never be scanned.
BLOCKLIST: list[str] = []
_raw_blocklist = os.getenv("BLOCKLIST", "")
if _raw_blocklist:
    BLOCKLIST = [r.strip() for r in _raw_blocklist.split(",") if r.strip()]

# --- Web app access ---
# Optional access code gating the web app (empty = no restriction).
# The Telegram bot is unaffected by this setting.
ACCESS_CODE: str = os.getenv("ACCESS_CODE", "").strip()

# Optional TOTP second factor (Google Authenticator / Authy).
# When set, login requires the access code AND a 6-digit rotating code.
# Generate with: python setup_2fa.py
TOTP_SECRET: str = os.getenv("TOTP_SECRET", "").strip()

# --- Scan settings ---
SCAN_TIMEOUT: int = int(os.getenv("SCAN_TIMEOUT", "300"))
COOLDOWN_SECONDS: int = int(os.getenv("COOLDOWN_SECONDS", "30"))
MAX_CONCURRENT_SCANS: int = int(os.getenv("MAX_CONCURRENT_SCANS", "2"))

# --- Logging ---
LOG_FILE: str = os.getenv("LOG_FILE", "scan_logs.txt")

# --- Telegram message limit ---
TELEGRAM_MAX_MESSAGE_LENGTH: int = 4096


def validate_config() -> list[str]:
    """Return a list of configuration errors (empty if valid)."""
    errors: list[str] = []
    if not BOT_TOKEN:
        errors.append("BOT_TOKEN is not set.")
    if not ALLOWED_USERS and not PUBLIC_ACCESS:
        errors.append(
            "ALLOWED_USERS is not set (no one will be able to use the bot). "
            "Set PUBLIC_ACCESS=true to open the bot to everyone."
        )
    return errors
