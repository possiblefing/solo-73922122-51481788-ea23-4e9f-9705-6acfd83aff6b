"""FastAPI login service with challenge/response proof-of-possession.

Threading / disconnect guarantees
---------------------------------
The login endpoint is a *synchronous* ``def``. Starlette runs sync endpoints
in a worker thread with no ``await`` point between slot acquisition and
settlement, so an HTTP client disconnecting mid-request cannot cancel the
handler: the argon2 verification always runs and the slot is always settled
(released, error counted or session issued) before anything is sent back.

No global lock serializes verifications; worker threads run argon2 fully in
parallel and coordinate only through short SQLite write transactions.

Proof-of-possession model
-------------------------
A session cookie alone is not enough. At login the browser registers a P-256
public key whose private half is a non-extractable Web Crypto key in
IndexedDB. Every state-bearing or identity request (``GET /api/me``,
``POST /api/logout``) must first fetch a random 60-second challenge bound to
the session and to a specific purpose, then send an ECDSA-SHA256 signature
over ``challenge || HTTP method || path`` in the ``X-Auth-Challenge`` /
``X-Auth-Signature`` headers. The ECDSA verification runs **outside** any
database write lock; challenge consumption is an atomic
``BEGIN IMMEDIATE`` transaction that also re-checks the session, so a copied
cookie or a replayed signature is rejected and concurrent replays of one
challenge can succeed at most once across both web processes.
"""
from __future__ import annotations

import logging
import math
import time
from pathlib import Path
from typing import Any

import anyio
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from . import db
from .config import settings
from .security import (
    build_signing_message,
    compare_tokens,
    hash_password,
    new_session_token,
    public_key_to_hex,
    verify_ecdsa_signature,
    verify_password,
)

COOKIE_NAME = "session"
CHALLENGE_HEADER = "X-Auth-Challenge"
SIGNATURE_HEADER = "X-Auth-Signature"

# Challenge purposes. Each purpose names exactly one (method, path) pair, so a
# challenge minted for one endpoint can never be replayed against another.
PURPOSE_ME = "me"
PURPOSE_LOGOUT = "logout"
PURPOSE_DEMO_TOKEN = "demo_token"
PURPOSE_TARGETS = {
    PURPOSE_ME: ("GET", "/api/me"),
    PURPOSE_LOGOUT: ("POST", "/api/logout"),
    PURPOSE_DEMO_TOKEN: ("GET", "/api/demo/session-token"),
}

logger = logging.getLogger("login_guard")

# A throwaway hash used to give unknown-username requests comparable timing
# to real ones (user-enumeration hardening). Generated once at import time.
_DUMMY_HASH = hash_password("not-a-real-password")


class LoginBody(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)
    # Raw P-256 public key, base64url (Web Crypto 'raw' / jwk export).
    public_key: str = Field(min_length=1, max_length=256)
    delay: float = Field(default=0.0, ge=0.0, le=60.0)


class ChallengeBody(BaseModel):
    purpose: str = Field(min_length=1, max_length=32)


app = FastAPI(title="Guessing-budget + PoP login demo", version="2.0.0")


@app.on_event("startup")
def _startup() -> None:
    # Allow enough worker threads for overlapping delayed verifications.
    anyio.to_thread.current_default_thread_limiter().total_tokens = 64
    db.init_db()


@app.middleware("http")
async def _add_process_header(request: Request, call_next):
    started = time.time()
    try:
        response = await call_next(request)
    except Exception:
        raise
    response.headers["X-Served-By"] = settings.process_name
    response.headers["X-Process-Time-ms"] = f"{(time.time() - started) * 1000:.1f}"
    return response


def _stats_payload() -> dict[str, Any]:
    return {
        "now": time.time(),
        "window_seconds": settings.error_window_seconds,
        "max_slots": settings.max_slots,
        "challenge_ttl_seconds": settings.challenge_ttl_seconds,
        "accounts": db.account_stats(),
    }


def _set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        max_age=settings.session_ttl_seconds,
        httponly=True,
        samesite="lax",
        secure=False,  # plain HTTP on localhost; enable behind TLS
        path="/",
    )


def _bound_session_or_401(request: Request):
    """Resolve a live, key-bound session from the cookie, else 401."""
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        raise HTTPException(status_code=401, detail="not authenticated")
    row = db.get_session(token)
    if row is None or not compare_tokens(row["token"], token):
        # Covers missing, expired and legacy *unbound* sessions alike: an old
        # cookie issued before key binding has no row the PoP layer accepts.
        raise HTTPException(
            status_code=401,
            detail="session invalid, expired or not key-bound; please log in again",
        )
    return token, row


def _authorize_signed(request: Request, purpose: str):
    """Full challenge/response gate for /api/me and /api/logout.

    The challenge id and the raw ECDSA signature travel in request headers
    (``X-Auth-Challenge`` / ``X-Auth-Signature``), which keeps the protected
    endpoints on their natural HTTP methods -- GET for identity, POST for
    logout -- and makes the signed (method, path) pair identical to the
    actual request line.

    Order of operations matters:

    1. Resolve the cookie to a live, key-bound session.
    2. Look up the challenge with a plain read (no write lock).
    3. Validate challenge ownership/purpose/expiry and verify the ECDSA
       signature **without holding any database write lock**.
    4. Only after the signature is valid do we open the short write
       transaction that atomically re-checks everything, consumes the
       challenge and, for logout, revokes the session.

    Any failure returns 401 and never marks the challenge consumed, so a
    client can retry with a corrected signature until it expires.
    """
    token, _session = _bound_session_or_401(request)
    method, path = PURPOSE_TARGETS[purpose]

    challenge_id = request.headers.get(CHALLENGE_HEADER, "").strip()
    signature = request.headers.get(SIGNATURE_HEADER, "").strip()
    if not challenge_id or not signature:
        raise HTTPException(
            status_code=401,
            detail=f"missing {CHALLENGE_HEADER}/{SIGNATURE_HEADER} headers;"
                   " fetch a challenge from /api/challenge first",
        )

    challenge = db.get_challenge(challenge_id)
    if challenge is None:
        raise HTTPException(status_code=401, detail="unknown challenge")
    now = time.time()
    if (
        challenge["consumed_at"] is not None
        or challenge["expires_at"] <= now
        or challenge["session_token"] != token
        or challenge["purpose"] != purpose
        or challenge["method"] != method
        or challenge["path"] != path
    ):
        # Do not consume: an expired/foreign/used challenge is simply refused.
        raise HTTPException(status_code=401, detail="challenge invalid or expired")

    # Re-read the live session to get the bound public key for verification.
    session = db.get_session(token)
    if session is None:
        raise HTTPException(status_code=401, detail="session no longer valid")

    message = build_signing_message(challenge_id, method, path)
    if not verify_ecdsa_signature(session["public_key"], signature, message):
        # Signature failure must NOT consume the challenge.
        raise HTTPException(status_code=401, detail="signature verification failed")

    # Atomic consume (+ optional session revocation). This is the only write,
    # and it re-validates every condition under the WAL write lock, which is
    # what makes concurrent replays single-use across both processes.
    authorized = db.consume_challenge(
        challenge_id=challenge_id,
        session_token=token,
        purpose=purpose,
        method=method,
        path=path,
        revoke_session=(purpose == PURPOSE_LOGOUT),
    )
    if authorized is None:
        raise HTTPException(
            status_code=401,
            detail="challenge already used or session revoked",
        )
    return authorized


@app.get("/", response_class=HTMLResponse)
def index() -> HTMLResponse:
    html_path = Path(__file__).with_name("static").joinpath("index.html")
    return HTMLResponse(html_path.read_text(encoding="utf-8"))


@app.get("/api/stats")
def stats() -> JSONResponse:
    return JSONResponse(_stats_payload())


@app.post("/api/challenge")
def challenge(request: Request, body: ChallengeBody) -> JSONResponse:
    """Issue a random, session-bound, purpose-specific challenge (60s TTL).

    Requires a valid key-bound session cookie. Issuance only inserts a new
    row; outstanding challenges of other tabs are never overwritten.
    """
    if body.purpose not in PURPOSE_TARGETS:
        raise HTTPException(status_code=400, detail="unknown challenge purpose")
    token, _session = _bound_session_or_401(request)
    method, path = PURPOSE_TARGETS[body.purpose]
    payload = db.create_challenge(
        session_token=token,
        purpose=body.purpose,
        method=method,
        path=path,
        ttl_seconds=settings.challenge_ttl_seconds,
    )
    return JSONResponse(payload)


@app.get("/api/me")
def me(request: Request) -> JSONResponse:
    """Identity endpoint guarded by a consumed, signature-bearing challenge.

    A plain GET carrying only the cookie (no ``X-Auth-*`` headers) fails at
    the authorization gate with 401 -- which is exactly what a copied-cookie
    attacker in a keyless browser gets.
    """
    row = _authorize_signed(request, PURPOSE_ME)
    return JSONResponse(
        {
            "authenticated": True,
            "username": row["username"],
            "account_id": row["account_id"],
            "expires_at": row["expires_at"],
            "served_by": settings.process_name,
        }
    )


@app.post("/api/logout")
def logout(request: Request) -> Response:
    """Revoke the session atomically with consuming the logout challenge."""
    _authorize_signed(request, PURPOSE_LOGOUT)
    response = Response(status_code=204)
    response.delete_cookie(COOKIE_NAME, path="/")
    return response


@app.get("/api/demo/session-token")
def demo_session_token(request: Request) -> JSONResponse:
    """Demo helper: reveal the current cookie value for the copy-cookie test.

    The normal browser never needs the raw token (the cookie is HttpOnly).
    This endpoint exists solely so the UI can show the exact ``Cookie:``
    header to paste into a second, keyless browser context and prove that the
    copied cookie by itself is rejected. It has its own challenge purpose, so
    a ``me`` challenge cannot be replayed against it.
    """
    row = _authorize_signed(request, PURPOSE_DEMO_TOKEN)
    return JSONResponse(
        {
            "cookie_name": COOKIE_NAME,
            "cookie_value": row["token"],
            "username": row["username"],
            "note": "把该值作为 Cookie 粘贴到没有私钥的另一个浏览器，"
                    "/api/me 与 /api/logout 都会被拒绝。",
        }
    )


@app.post("/api/login")
def login(body: LoginBody) -> JSONResponse:
    delay = min(max(body.delay, 0.0), float(settings.max_delay_seconds))
    now = time.time()

    # Validate the public key before spending any login budget slot: a
    # malformed key is a client error, not a password attempt.
    try:
        public_key_hex = public_key_to_hex(body.public_key)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_public_key",
                    "message": "公钥不是合法的 P-256 未压缩点"},
        )

    conn = db.connect()
    try:
        account = db.get_account(conn, body.username.strip())
    finally:
        conn.close()

    if account is None:
        # Spend an argon2 verification anyway so timing does not reveal
        # whether the username exists. No slot exists for unknown users.
        verify_password(_DUMMY_HASH, body.password)
        raise HTTPException(
            status_code=401,
            detail={"error": "invalid_credentials", "message": "用户名或密码错误"},
        )

    account_id = account["id"]

    # --- Atomic reservation: windowed errors + in-flight vs. the limit ---
    slot_id = db.acquire_slot(account_id, now=now)
    if slot_id is None:
        # Full: reject immediately and do NOT hash the password.
        retry_after = math.ceil(db.next_retry_after(account_id))
        raise HTTPException(
            status_code=429,
            headers={"Retry-After": str(retry_after)},
            detail={
                "error": "rate_limited",
                "message": "该账号错误次数/在途核验已达上限，请稍后再试",
                "retry_after": retry_after,
                "account": next(
                    (a for a in db.account_stats() if a["account_id"] == account_id),
                    None,
                ),
            },
        )

    # --- Verification runs with NO database write lock held and NO global ---
    # --- lock; other requests/processes verify in parallel.              ---
    ok = False
    try:
        if delay:
            time.sleep(delay)  # demo knob: interleave completion ordering
        ok = verify_password(account["password_hash"], body.password)
    except Exception:
        ok = False

    # --- Settlement always happens, even if the client has disconnected ---
    if ok:
        token = new_session_token()
        expires_at = time.time() + settings.session_ttl_seconds
        # Session insert (with the bound public key) + slot release + error
        # reset commit together.
        settled = db.settle(
            slot_id,
            account_id,
            success=True,
            session_token=token,
            session_expires_at=expires_at,
            session_public_key=public_key_hex,
        )
        if not settled:
            # The slot was reclaimed by a startup cleanup while we were
            # verifying; no session can be issued for a slot we no longer own.
            logger.warning("slot %s reclaimed before successful settlement", slot_id)
            return JSONResponse(
                status_code=503,
                content={
                    "ok": False,
                    "error": "slot_reclaimed",
                    "message": "服务刚完成重启，请重试登录",
                    "served_by": settings.process_name,
                    "stats": _stats_payload(),
                },
            )
        response = JSONResponse(
            {
                "ok": True,
                "username": account["username"],
                "message": "登录成功，会话已绑定浏览器 P-256 公钥",
                "served_by": settings.process_name,
                "stats": _stats_payload(),
            }
        )
        _set_session_cookie(response, token)
        return response

    settled = db.settle(slot_id, account_id, success=False)
    if not settled:
        # Slot was already reclaimed (crash recovery); the verification
        # still ran to completion, but its error must not be double-counted.
        logger.warning("slot %s reclaimed before failure settlement", slot_id)
    return JSONResponse(
        status_code=401,
        content={
            "ok": False,
            "error": "invalid_credentials",
            "message": "用户名或密码错误",
            "served_by": settings.process_name,
            "stats": _stats_payload(),
        },
    )
