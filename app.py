"""FastAPI web app — nmap scanner dashboard (dark cyber UI)."""

import asyncio
import base64
import io
import logging
import os
import random
import secrets
import time
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from PIL import Image, ImageDraw, ImageFont
from pydantic import BaseModel, Field
import pyotp

import config
import scanner
import validators

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(title="Nmap Scanner", docs_url="/docs")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


# ---------------------------------------------------------------------------
# API models
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=64)
    profile: str = "fast"


class LoginRequest(BaseModel):
    code: str = Field(..., min_length=1, max_length=128)
    totp: str = Field(default="", max_length=16)
    captcha_id: str = Field(default="", max_length=64)
    captcha: str = Field(default="", max_length=16)


# ---------------------------------------------------------------------------
# Access-code protection (optional, configured via ACCESS_CODE)
# ---------------------------------------------------------------------------

ACCESS_COOKIE = "access_token"
COOKIE_MAX_AGE = 30 * 24 * 3600  # 30 days
_auth_tokens: dict[str, float] = {}  # token -> unix expiry


def _auth_enabled() -> bool:
    return bool(config.ACCESS_CODE)


def _is_authorized(request: Request) -> bool:
    if not _auth_enabled():
        return True
    token = request.cookies.get(ACCESS_COOKIE)
    if not token:
        return False
    expiry = _auth_tokens.get(token)
    return expiry is not None and expiry > time.time()


def require_access(request: Request) -> None:
    """FastAPI dependency: 401 unless a valid access-code session cookie exists."""
    if not _is_authorized(request):
        raise HTTPException(status_code=401, detail="Access code required.")


def _issue_token() -> str:
    token = secrets.token_urlsafe(32)
    _auth_tokens[token] = time.time() + COOKIE_MAX_AGE
    if len(_auth_tokens) > 1000:  # prune expired
        now = time.time()
        for old, expiry in list(_auth_tokens.items()):
            if expiry < now:
                _auth_tokens.pop(old, None)
    return token


def _totp_ok(code: str) -> bool:
    """Verify a 6-digit TOTP code (window ±1 for clock drift)."""
    if not config.TOTP_SECRET:
        return True
    code = code.strip().replace(" ", "")
    if not (code.isdigit() and len(code) == 6):
        return False
    try:
        return bool(pyotp.TOTP(config.TOTP_SECRET).verify(code, valid_window=1))
    except Exception:
        logger.exception("TOTP verification failed (check TOTP_SECRET)")
        return False


# ---------------------------------------------------------------------------
# Captcha — keeps automated scripts out of the login form
# ---------------------------------------------------------------------------

CAPTCHA_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"  # no 0/O, 1/I/L
CAPTCHA_LEN = 5
CAPTCHA_TTL = 300  # 5 minutes
_captcha_challenges: dict[str, tuple[str, float]] = {}  # id -> (answer, expiry)


def _render_captcha(text: str) -> str:
    """Render distorted captcha text -> base64 PNG."""
    width, height = 190, 64
    img = Image.new("RGB", (width, height), (4, 7, 10))
    draw = ImageDraw.Draw(img)
    font = ImageFont.load_default(size=34)

    # background dot noise
    for _ in range(160):
        x, y = random.randrange(width), random.randrange(height)
        draw.point((x, y), fill=(
            random.randint(8, 55),
            random.randint(25, 85),
            random.randint(35, 95),
        ))

    # characters: per-char color, slight rotation, slight vertical jitter
    x = 8
    for ch in text:
        tile = Image.new("RGBA", (40, 52), (0, 0, 0, 0))
        tdraw = ImageDraw.Draw(tile)
        color = random.choice(
            [(0, 229, 255), (57, 255, 20), (140, 240, 255), (210, 255, 245)]
        )
        tdraw.text((4, 4), ch, font=font, fill=color)
        rotated = tile.rotate(
            random.uniform(-18, 18), resample=Image.BICUBIC, expand=False
        )
        img.paste(rotated, (x, random.randint(0, 8)), rotated)
        x += 34

    # noise lines across the image
    for _ in range(3):
        draw.line(
            [(random.randint(0, width), 0), (random.randint(0, width), height)],
            fill=random.choice([(0, 229, 255), (255, 77, 109), (255, 176, 32)]),
            width=1,
        )

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode("ascii")


def _new_challenge() -> tuple[str, str]:
    """Create a captcha challenge -> (id, base64 image). Answer stays server-side."""
    answer = "".join(secrets.choice(CAPTCHA_ALPHABET) for _ in range(CAPTCHA_LEN))
    cid = secrets.token_urlsafe(24)
    _captcha_challenges[cid] = (answer.lower(), time.time() + CAPTCHA_TTL)
    if len(_captcha_challenges) > 500:  # prune expired
        now = time.time()
        for old, (_, expiry) in list(_captcha_challenges.items()):
            if expiry < now:
                _captcha_challenges.pop(old, None)
    return cid, _render_captcha(answer)


def _captcha_ok(challenge_id: str, answer: str) -> bool:
    """One-time check: the challenge is consumed whether it passes or fails."""
    if not challenge_id:
        return False
    entry = _captcha_challenges.pop(challenge_id, None)
    if not entry:
        return False
    expected, expiry = entry
    if expiry < time.time():
        return False
    return secrets.compare_digest(
        answer.strip().lower().encode("utf-8"),
        expected.encode("utf-8"),
    )


@app.get("/api/captcha")
async def captcha() -> JSONResponse:
    cid, image = _new_challenge()
    return JSONResponse({"id": cid, "image": image})


@app.get("/api/auth")
async def auth_info() -> dict:
    """Which login factors are required (no secrets exposed)."""
    return {"access_code": _auth_enabled(), "totp": bool(config.TOTP_SECRET)}


@app.post("/api/login")
async def login(body: LoginRequest):
    """Step 1: access code. Step 2: authenticator code (when 2FA is enabled)."""
    if not _auth_enabled():
        return {"ok": True, "auth": "disabled"}

    # Step 0 — captcha: prove you're human before any credential is evaluated
    if not _captcha_ok(body.captcha_id, body.captcha):
        return JSONResponse(
            status_code=400,
            content={
                "error": "Captcha incorrect or expired. Try the new image.",
                "captcha": True,
            },
        )

    # Factor 1 — access code (constant-time comparison)
    code_ok = secrets.compare_digest(
        body.code.encode("utf-8"),
        config.ACCESS_CODE.encode("utf-8"),
    )
    if not code_ok:
        await asyncio.sleep(1.5)  # slow down brute-force attempts
        return JSONResponse(status_code=401, content={"error": "Invalid access code."})

    # Factor 2 — TOTP from the authenticator app
    if config.TOTP_SECRET and not _totp_ok(body.totp):
        await asyncio.sleep(1.5)
        return JSONResponse(
            status_code=401,
            content={"error": "Invalid authenticator code."},
        )

    response = JSONResponse({"ok": True, "auth": "ok"})
    response.set_cookie(
        key=ACCESS_COOKIE,
        value=_issue_token(),
        max_age=COOKIE_MAX_AGE,
        httponly=True,
        samesite="lax",
        path="/",
    )
    return response


# ---------------------------------------------------------------------------
# Per-client scan sessions
# ---------------------------------------------------------------------------

class ScanSession:
    """State of the latest scan for one client."""

    def __init__(self) -> None:
        self.state = "idle"  # idle | queued | scanning | done | error
        self.target: str | None = None
        self.profile: str | None = None
        self.result: str | None = None
        self.error: str | None = None
        self.last_finished_at: float = 0.0
        self.task: asyncio.Task | None = None


_sessions: dict[str, ScanSession] = {}
_MAX_SESSIONS = 500


def _client_id(request: Request) -> str:
    """Identify the client by real IP.

    Trusts proxy headers (Cf-Connecting-Ip / X-Forwarded-For) only when the
    immediate peer is loopback — i.e. our local cloudflared tunnel. Direct
    requests from other hosts can't spoof them to evade rate limits.
    """
    peer = request.client.host if request.client else ""
    if peer in ("127.0.0.1", "::1"):
        cf_ip = request.headers.get("cf-connecting-ip")
        if cf_ip:
            return cf_ip.strip()
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return peer or "unknown"


def _prune_sessions() -> None:
    """Drop stale sessions once the table grows too large (public bot safety)."""
    if len(_sessions) <= _MAX_SESSIONS:
        return
    cutoff = time.monotonic() - 3600
    for cid, session in list(_sessions.items()):
        if session.state not in ("queued", "scanning") and session.last_finished_at < cutoff:
            _sessions.pop(cid, None)


async def _run(session: ScanSession, target: str, profile: str) -> None:
    """Execute the scan and record the outcome on the session."""
    try:
        output = await scanner.run_scan(
            target,
            profile,
            on_start=lambda: setattr(session, "state", "scanning"),
        )
        session.result = output or "(No output from nmap)"
        session.state = "done"
    except scanner.ScanError as exc:
        session.error = str(exc)
        session.state = "error"
    except Exception:
        logger.exception("Unexpected scan failure")
        session.error = "An unexpected error occurred. Please try again."
        session.state = "error"
    finally:
        session.last_finished_at = time.monotonic()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/")
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/health")
@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@app.post("/api/scan", dependencies=[Depends(require_access)])
async def start_scan(body: ScanRequest, request: Request):
    # Fixed profiles only — users never pass custom nmap arguments.
    if body.profile not in scanner.SCAN_PROFILES:
        return JSONResponse(
            status_code=400,
            content={"error": f"Unknown profile: '{body.profile}'."},
        )

    # Strict IP validation (rejects hostnames, CIDR, extra characters).
    try:
        addr = validators.validate_ip(body.target)
    except ValueError as exc:
        return JSONResponse(status_code=400, content={"error": str(exc)})

    if validators.is_blocked(addr):
        return JSONResponse(
            status_code=403,
            content={"error": "This target is blocklisted and cannot be scanned."},
        )

    cid = _client_id(request)
    _prune_sessions()
    session = _sessions.setdefault(cid, ScanSession())

    if session.state in ("queued", "scanning"):
        return JSONResponse(
            status_code=429,
            content={"error": "A scan is already running. Please wait for it to finish."},
        )

    now = time.monotonic()
    remaining = config.COOLDOWN_SECONDS - (now - session.last_finished_at)
    if remaining > 0:
        return JSONResponse(
            status_code=429,
            content={
                "error": f"Please wait {int(remaining) + 1} more seconds before starting another scan.",
                "cooldown": remaining,
            },
        )

    target = str(addr)
    session.state = "queued"
    session.target = target
    session.profile = body.profile
    session.result = None
    session.error = None

    scanner.log_scan(cid, target, body.profile)
    session.task = asyncio.create_task(_run(session, target, body.profile))
    return {"status": "queued", "target": target, "profile": body.profile}


@app.get("/api/status", dependencies=[Depends(require_access)])
async def status(request: Request):
    cid = _client_id(request)
    session = _sessions.get(cid)
    cooldown = 0.0
    if session and session.last_finished_at:
        cooldown = max(0.0, config.COOLDOWN_SECONDS - (time.monotonic() - session.last_finished_at))

    if not session:
        return {"state": "idle", "cooldown": 0}

    return {
        "state": session.state,
        "target": session.target,
        "profile": session.profile,
        "result": session.result if session.state == "done" else None,
        "error": session.error,
        "cooldown": round(cooldown, 1),
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "8000"))
    if _auth_enabled():
        logger.info("Web app access control ENABLED (ACCESS_CODE is set)")
    else:
        logger.info("Web app access control disabled (no ACCESS_CODE)")
    uvicorn.run(app, host=host, port=port)
