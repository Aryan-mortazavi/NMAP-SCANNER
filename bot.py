"""Telegram bot entry point — nmap scanner bot."""

import asyncio
import io
import logging
import time
from datetime import datetime, timezone

from telegram import Update
from telegram.ext import (
    Application,
    CommandHandler,
    ContextTypes,
)

import config
import scanner
import validators

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Per-user rate limiting state
# ---------------------------------------------------------------------------
# user_id -> timestamp of last scan start
_last_scan_time: dict[int, float] = {}
# user_id -> True if a scan is currently running
_scan_in_progress: dict[int, bool] = {}

# ---------------------------------------------------------------------------
# Authorization helper
# ---------------------------------------------------------------------------

def is_authorized(user_id: int) -> bool:
    """Return True if the user may use the bot (public mode or whitelist)."""
    if config.PUBLIC_ACCESS:
        return True
    return user_id in config.ALLOWED_USERS

# ---------------------------------------------------------------------------
# Message helpers
# ---------------------------------------------------------------------------

async def send_long_text(
    update: Update,
    text: str,
    caption: str = "",
) -> None:
    """Send text as a message, or as a .txt file if it exceeds Telegram's limit."""
    if len(text) <= config.TELEGRAM_MAX_MESSAGE_LENGTH:
        await update.message.reply_text(f"```\n{text}\n```", parse_mode="Markdown")
    else:
        file = io.BytesIO(text.encode("utf-8"))
        file.name = "scan_result.txt"
        await update.message.reply_document(
            document=file,
            caption=caption or "Scan result (too long for a message).",
        )

# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /start."""
    if not is_authorized(update.effective_user.id):
        await update.message.reply_text(
            "Sorry, you are not authorized to use this bot."
        )
        return

    await update.message.reply_text(
        "Welcome to the Nmap Scanner Bot!\n\n"
        "Commands:\n"
        "/scan <ip> — Fast scan (nmap -F -T4)\n"
        "/fullscan <ip> — Service/version detection (nmap -sV -T4 --top-ports 1000)\n"
        "/status — Check if a scan is running for you\n"
        "/help — Show this help message\n\n"
        "⚠️ Only scan systems you own or have explicit authorization to test.",
        parse_mode="Markdown",
    )


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /help."""
    if not is_authorized(update.effective_user.id):
        await update.message.reply_text(
            "Sorry, you are not authorized to use this bot."
        )
        return

    await update.message.reply_text(
        "Available commands:\n\n"
        "/scan <ip> — Fast scan (nmap -F -T4)\n"
        "/fullscan <ip> — Service/version detection (nmap -sV -T4 --top-ports 1000)\n"
        "/status — Check if a scan is running for you\n"
        "/help — Show this help message\n\n"
        "⚠️ Only scan systems you own or have explicit authorization to test.",
        parse_mode="Markdown",
    )


async def status(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /status."""
    if not is_authorized(update.effective_user.id):
        await update.message.reply_text(
            "Sorry, you are not authorized to use this bot."
        )
        return

    user_id = update.effective_user.id
    if _scan_in_progress.get(user_id, False):
        await update.message.reply_text("A scan is currently running for you.")
    else:
        await update.message.reply_text("No scan is currently running for you.")


async def scan(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /scan <ip>."""
    await _handle_scan(update, context, profile="fast")


async def fullscan(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /fullscan <ip>."""
    await _handle_scan(update, context, profile="full")


async def _handle_scan(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    profile: str,
) -> None:
    """Shared logic for /scan and /fullscan."""
    user_id = update.effective_user.id

    # --- Authorization ---
    if not is_authorized(user_id):
        await update.message.reply_text(
            "Sorry, you are not authorized to use this bot."
        )
        return

    # --- Argument check ---
    if not context.args:
        await update.message.reply_text(
            f"Usage: /{profile} <ip_address>"
        )
        return

    ip_str = context.args[0]

    # --- IP validation ---
    try:
        addr = validators.validate_ip(ip_str)
    except ValueError as e:
        await update.message.reply_text(f"Invalid target: {e}")
        return

    # --- Blocklist check ---
    if validators.is_blocked(addr):
        await update.message.reply_text(
            "This target is blocklisted and cannot be scanned."
        )
        return

    # --- Per-user concurrency check ---
    if _scan_in_progress.get(user_id, False):
        await update.message.reply_text(
            "You already have a scan running. Please wait for it to finish."
        )
        return

    # --- Cooldown check ---
    now = time.monotonic()
    last_time = _last_scan_time.get(user_id, 0)
    elapsed = now - last_time
    if elapsed < config.COOLDOWN_SECONDS:
        remaining = int(config.COOLDOWN_SECONDS - elapsed)
        await update.message.reply_text(
            f"Please wait {remaining} more seconds before starting another scan."
        )
        return

    # --- Start scan ---
    _scan_in_progress[user_id] = True
    _last_scan_time[user_id] = now

    # Log the scan request
    scanner.log_scan(user_id, ip_str, profile)

    # Acknowledge immediately
    status_msg = await update.message.reply_text("Scanning...")

    try:
        output = await scanner.run_scan(ip_str, profile)
        if not output:
            output = "(No output from nmap)"
        await send_long_text(update, output, caption=f"Scan result for {ip_str}")
    except scanner.ScanError as e:
        await update.message.reply_text(f"Scan failed: {e}")
    except Exception as e:
        logger.exception("Unexpected error during scan")
        await update.message.reply_text(
            "An unexpected error occurred. Please try again later."
        )
    finally:
        _scan_in_progress[user_id] = False
        # Delete the "Scanning..." message
        try:
            await status_msg.delete()
        except Exception:
            pass

# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """Start the bot."""
    errors = config.validate_config()
    if errors:
        for err in errors:
            logger.error("Config error: %s", err)
        raise SystemExit(1)

    app = Application.builder().token(config.BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("scan", scan))
    app.add_handler(CommandHandler("fullscan", fullscan))
    app.add_handler(CommandHandler("status", status))

    if config.PUBLIC_ACCESS:
        logger.info("Bot started in PUBLIC mode — any user may use it.")
    else:
        logger.info("Bot started. Allowed users: %s", config.ALLOWED_USERS)
    # bootstrap_retries: retry on transient network failures at startup
    app.run_polling(bootstrap_retries=10)


if __name__ == "__main__":
    main()
