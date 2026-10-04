"""Nmap execution via asyncio subprocess (never shell=True)."""

import asyncio
import logging
from collections.abc import Callable
from datetime import datetime, timezone

import config

logger = logging.getLogger(__name__)

# --- Fixed scan profiles (users cannot pass custom arguments) ---
SCAN_PROFILES: dict[str, list[str]] = {
    "fast": ["-F", "-T4"],
    "full": ["-sV", "-T4", "--top-ports", "1000"],
}

# Global concurrency limit
_semaphore = asyncio.Semaphore(config.MAX_CONCURRENT_SCANS)


class ScanError(Exception):
    """Raised when a scan fails for any reason."""


async def run_scan(
    ip: str,
    profile: str,
    on_start: Callable[[], None] | None = None,
) -> str:
    """Run nmap against ip using the given profile.

    on_start: optional callback fired once the concurrency slot is acquired
    (lets callers distinguish "queued" from actually "scanning").

    Returns the combined stdout+stderr output as a string.
    Raises ScanError on failure or timeout.
    """
    if profile not in SCAN_PROFILES:
        raise ScanError(f"Unknown scan profile: '{profile}'.")

    args = ["nmap", *SCAN_PROFILES[profile], ip]
    logger.info("Starting scan: %s (profile=%s)", ip, profile)

    async with _semaphore:
        if on_start is not None:
            on_start()
        try:
            process = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            raise ScanError("nmap is not installed or not found in PATH.")

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=config.SCAN_TIMEOUT,
            )
        except asyncio.TimeoutError:
            process.kill()
            await process.communicate()
            raise ScanError(
                f"Scan timed out after {config.SCAN_TIMEOUT} seconds and was killed."
            )

    output = (stdout + stderr).decode("utf-8", errors="replace").strip()

    if process.returncode != 0 and not output:
        raise ScanError(f"nmap exited with code {process.returncode}.")

    return output


def log_scan(user_id: int, target: str, profile: str) -> None:
    """Log a scan request to the log file. Never logs the bot token."""
    timestamp = datetime.now(timezone.utc).isoformat()
    log_line = f"[{timestamp}] user_id={user_id} target={target} profile={profile}\n"
    try:
        with open(config.LOG_FILE, "a", encoding="utf-8") as f:
            f.write(log_line)
    except OSError as e:
        logger.error("Failed to write to log file: %s", e)
