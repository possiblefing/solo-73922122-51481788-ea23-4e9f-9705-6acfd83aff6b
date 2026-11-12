"""SQLite-backed shared state for the login service.

Concurrency model
-----------------
Two (or more) uvicorn worker processes share one SQLite database file.

* The database runs in WAL mode, so a reader never blocks a writer and two
  readers never block each other; writers still serialize through the single
  WAL writer, which is exactly the serialization point we need for the
  per-account slot accounting.
* Every state-changing operation opens a *short* ``BEGIN IMMEDIATE``
  transaction. The argon2 hash itself is computed by the caller **outside**
  any transaction (see :mod:`app.security`), so CPU-bound password hashing
  never holds the SQLite write lock.
* There is deliberately no in-process global lock around verification:
  cross-process coordination happens entirely inside SQLite transactions.
* Each request uses its own connection; no connection is ever shared across
  threads.
"""
from __future__ import annotations

import os
import sqlite3
import time
import uuid
from contextlib import contextmanager
from typing import Iterator, Optional

from .config import settings
from .security import hash_password

# Demo accounts. Only the argon2 hashes are ever persisted; the plaintext
# passwords live here solely so the one-time seed can be generated and are
# shown on the demo page for convenience.
SEED_ACCOUNTS = (
    ("alice", "alice-pass-2026"),
    ("bob", "bob-pass-2026"),
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    id            INTEGER PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at    REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS login_errors (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id INTEGER NOT NULL REFERENCES accounts(id),
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_login_errors_account_time
    ON login_errors(account_id, created_at);

CREATE TABLE IF NOT EXISTS login_inflight (
    slot_id    TEXT PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(id),
    acquired_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_login_inflight_account
    ON login_inflight(account_id);

CREATE TABLE IF NOT EXISTS sessions (
    token       TEXT PRIMARY KEY,
    account_id  INTEGER NOT NULL REFERENCES accounts(id),
    created_at  REAL NOT NULL,
    expires_at  REAL NOT NULL,
    -- P-256 uncompressed point (hex) bound at login; proof-of-possession
    -- checks sign challenges with the matching non-extractable private key.
    public_key  TEXT NOT NULL,
    -- 1 = key-bound session created by the current schema; 0 would only
    -- appear on legacy rows produced by an older deployment, which must be
    -- rejected (they have no key to prove possession with).
    bound       INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS auth_challenges (
    id            TEXT PRIMARY KEY,
    session_token TEXT NOT NULL,
    purpose       TEXT NOT NULL,
    method        TEXT NOT NULL,
    path          TEXT NOT NULL,
    created_at    REAL NOT NULL,
    expires_at    REAL NOT NULL,
    consumed_at   REAL
);
CREATE INDEX IF NOT EXISTS idx_auth_challenges_session
    ON auth_challenges(session_token);
CREATE INDEX IF NOT EXISTS idx_auth_challenges_expiry
    ON auth_challenges(expires_at);
"""


def connect() -> sqlite3.Connection:
    """Open a brand-new connection with concurrency-friendly settings."""
    os.makedirs(os.path.dirname(settings.db_path), exist_ok=True)
    conn = sqlite3.connect(
        settings.db_path,
        timeout=30.0,            # wait on the write lock instead of erroring
        isolation_level=None,    # explicit BEGIN/COMMIT, no implicit txns
        check_same_thread=False,  # connections are per-call, never shared
    )
    conn.row_factory = sqlite3.Row
    # Persistent WAL/journal settings are stored in the DB file itself;
    # re-issuing them on every connection is cheap and makes a fresh file
    # self-initializing even before init_db() runs.
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


@contextmanager
def immediate_tx(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """Acquire the WAL write lock up-front and commit/roll back as a unit."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
        # An inner block may have rolled back explicitly to bail out cleanly.
        if conn.in_transaction:
            conn.execute("COMMIT")
    except Exception:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise


def _migrate_legacy_schema(conn: sqlite3.Connection) -> None:
    """Upgrade a database created by an older version of the service.

    Sessions issued before key binding have no public key. They are kept on
    disk (so the rolling-window accounts remain untouched) but flagged
    ``bound = 0``; every authenticated endpoint rejects such rows, i.e.
    "old unbound sessions refuse to authenticate". A fresh login replaces
    them with a key-bound session.
    """
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(sessions)")}
    if "public_key" not in cols:
        conn.execute(
            "ALTER TABLE sessions ADD COLUMN public_key TEXT"
        )
    if "bound" not in cols:
        conn.execute(
            "ALTER TABLE sessions ADD COLUMN bound INTEGER NOT NULL DEFAULT 0"
        )
    # Any historical row necessarily lacks a key; mark it unbound explicitly.
    conn.execute(
        "UPDATE sessions SET bound = 0"
        " WHERE public_key IS NULL OR length(public_key) = 0"
    )


def init_db() -> None:
    """Create the schema, seed demo accounts and clear stale state.

    Safe to run concurrently from several processes: DDL uses
    ``IF NOT EXISTS`` and account seeding uses ``INSERT OR IGNORE``.
    Challenges and sessions are *durable* across restarts (the spec requires
    surviving sessions/challenges to keep working), so neither table is
    truncated here; only expired challenge rows are pruned lazily.
    """
    conn = connect()
    try:
        conn.executescript(SCHEMA)
        now = time.time()
        with immediate_tx(conn):
            _migrate_legacy_schema(conn)
            for username, password in SEED_ACCOUNTS:
                row = conn.execute(
                    "SELECT id FROM accounts WHERE username = ?", (username,)
                ).fetchone()
                if row is None:
                    # Hashing happens before the write; it is not performed
                    # while holding any lock beyond this short seed txn.
                    conn.execute(
                        "INSERT OR IGNORE INTO accounts"
                        " (username, password_hash, created_at)"
                        " VALUES (?, ?, ?)",
                        (username, hash_password(password), now),
                    )
            # A process restart means every previously in-flight verifier is
            # dead: reclaim all slots. Completed errors are intentionally
            # kept so the rolling window survives the restart.
            conn.execute("DELETE FROM login_inflight")
            # Expired challenges can never be used again; drop them. Valid
            # challenges (and all sessions) intentionally survive the restart.
            conn.execute(
                "DELETE FROM auth_challenges WHERE expires_at <= ?", (now,)
            )
    finally:
        conn.close()


def get_account(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    return conn.execute(
        "SELECT id, username, password_hash FROM accounts WHERE username = ?",
        (username,),
    ).fetchone()


def acquire_slot(account_id: int, now: Optional[float] = None) -> Optional[str]:
    """Atomically take one verification slot for an account.

    Counts *completed* errors inside the rolling window plus *in-flight*
    verifications. When the account is at capacity the function returns
    ``None`` without inserting anything (caller returns HTTP 429 and must
    not hash the password).
    """
    now = time.time() if now is None else now
    cutoff = now - settings.error_window_seconds
    slot_id = uuid.uuid4().hex
    conn = connect()
    try:
        with immediate_tx(conn):
            conn.execute(
                "DELETE FROM login_errors WHERE created_at < ?", (cutoff,)
            )
            errors = conn.execute(
                "SELECT COUNT(*) AS c FROM login_errors WHERE account_id = ?",
                (account_id,),
            ).fetchone()["c"]
            inflight = conn.execute(
                "SELECT COUNT(*) AS c FROM login_inflight WHERE account_id = ?",
                (account_id,),
            ).fetchone()["c"]
            if errors + inflight >= settings.max_slots:
                return None
            conn.execute(
                "INSERT INTO login_inflight (slot_id, account_id, acquired_at)"
                " VALUES (?, ?, ?)",
                (slot_id, account_id, now),
            )
            return slot_id
    finally:
        conn.close()


def settle(
    slot_id: str,
    account_id: int,
    success: bool,
    now: Optional[float] = None,
    session_token: Optional[str] = None,
    session_expires_at: Optional[float] = None,
    session_public_key: Optional[str] = None,
) -> bool:
    """Book a finished verification and, on success, issue the session.

    The slot release, the error record (or error-window reset) and the
    session row are written in one transaction, so settlement and session
    issuance commit together or not at all.

    On success the currently completed errors of the account are cleared.
    Other in-flight attempts are untouched: if they fail when they finish,
    their failures are still recorded and start a fresh window.

    Returns ``True`` when the slot was settled normally, ``False`` when the
    slot no longer existed (e.g. a startup cleanup after a crash reclaimed
    it while the verifier was still finishing). A missing slot means the
    accounting was already reconciled, so the caller must not treat this as
    a hard failure.
    """
    now = time.time() if now is None else now
    conn = connect()
    try:
        with immediate_tx(conn):
            cur = conn.execute(
                "DELETE FROM login_inflight WHERE slot_id = ?", (slot_id,)
            )
            if cur.rowcount == 0:
                # Slot was reclaimed out from under us (crash/startup
                # cleanup). Roll back the no-op delete and let the caller
                # decide; no error/session rows are written for a slot we no
                # longer own.
                conn.execute("ROLLBACK")
                return False
            if success:
                conn.execute(
                    "DELETE FROM login_errors WHERE account_id = ?", (account_id,)
                )
                if session_token is None or session_expires_at is None:
                    raise RuntimeError("successful settlement requires a session")
                if not session_public_key:
                    raise RuntimeError(
                        "successful settlement requires a bound public key"
                    )
                conn.execute(
                    "INSERT INTO sessions"
                    " (token, account_id, created_at, expires_at,"
                    "  public_key, bound)"
                    " VALUES (?, ?, ?, ?, ?, 1)",
                    (session_token, account_id, now, session_expires_at,
                     session_public_key),
                )
            else:
                # Error is counted at *completion* time, not acquisition time.
                conn.execute(
                    "INSERT INTO login_errors (account_id, created_at)"
                    " VALUES (?, ?)",
                    (account_id, now),
                )
        return True
    finally:
        conn.close()


def get_session(token: str, now: Optional[float] = None) -> Optional[sqlite3.Row]:
    """Return a live, **key-bound** session row, or ``None``.

    Legacy rows created before key binding carry ``bound = 0`` and are never
    returned: holding their cookie alone cannot authenticate because there is
    no key to prove possession with.
    """
    now = time.time() if now is None else now
    conn = connect()
    try:
        return conn.execute(
            "SELECT s.token, s.expires_at, s.public_key,"
            " a.id AS account_id, a.username"
            " FROM sessions s JOIN accounts a ON a.id = s.account_id"
            " WHERE s.token = ? AND s.expires_at > ? AND s.bound = 1",
            (token, now),
        ).fetchone()
    finally:
        conn.close()


def delete_session(token: str) -> None:
    conn = connect()
    try:
        with immediate_tx(conn):
            conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
            # A dead session can never answer a challenge again.
            conn.execute(
                "DELETE FROM auth_challenges WHERE session_token = ?", (token,)
            )
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Proof-of-possession challenges
# ---------------------------------------------------------------------------

def create_challenge(
    session_token: str,
    purpose: str,
    method: str,
    path: str,
    ttl_seconds: int,
    now: Optional[float] = None,
) -> dict:
    """Mint a random, session- and purpose-bound challenge.

    Multiple tabs each get their own row: issuing never overwrites another
    outstanding challenge, so parallel tabs never invalidate each other.
    Expired rows of this session are pruned opportunistically.
    """
    now = time.time() if now is None else now
    challenge_id = uuid.uuid4().hex + uuid.uuid4().hex  # 256 bits
    expires_at = now + ttl_seconds
    conn = connect()
    try:
        with immediate_tx(conn):
            conn.execute(
                "DELETE FROM auth_challenges"
                " WHERE session_token = ? AND expires_at <= ?",
                (session_token, now),
            )
            conn.execute(
                "INSERT INTO auth_challenges"
                " (id, session_token, purpose, method, path,"
                "  created_at, expires_at, consumed_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, NULL)",
                (challenge_id, session_token, purpose,
                 method.upper(), path, now, expires_at),
            )
    finally:
        conn.close()
    return {
        "challenge": challenge_id,
        "purpose": purpose,
        "method": method.upper(),
        "path": path,
        "expires_at": expires_at,
        "ttl_seconds": ttl_seconds,
    }


def get_challenge(challenge_id: str, now: Optional[float] = None) -> Optional[sqlite3.Row]:
    """Read-only lookup used *before* signature verification.

    No write lock is taken here (and none is held while the ECDSA check
    runs). The row is re-validated atomically inside :func:`consume_challenge`
    at submission time.
    """
    now = time.time() if now is None else now
    conn = connect()
    try:
        return conn.execute(
            "SELECT id, session_token, purpose, method, path,"
            " created_at, expires_at, consumed_at"
            " FROM auth_challenges WHERE id = ?",
            (challenge_id,),
        ).fetchone()
    finally:
        conn.close()


def consume_challenge(
    challenge_id: str,
    session_token: str,
    purpose: str,
    method: str,
    path: str,
    revoke_session: bool,
    now: Optional[float] = None,
) -> Optional[sqlite3.Row]:
    """Atomically validate-and-consume one challenge, optionally revoking.

    The whole check runs in a single ``BEGIN IMMEDIATE`` transaction, which is
    the cross-process serialization point: two concurrent submissions of the
    same challenge race for the WAL write lock; the first consumes the row,
    the second finds ``consumed_at`` already set and fails.

    A challenge is consumed only when *everything* matches (session still
    live and bound, purpose/method/path equal, not expired, not consumed).
    Signature failures never reach this function, so a failed signature never
    consumes a challenge. When ``revoke_session`` is set, the session row is
    deleted in the same transaction -- challenge consumption and logout
    commit together or not at all, and no late verification can restore the
    session afterwards.

    Returns the authorized session row on success, otherwise ``None``.
    """
    now = time.time() if now is None else now
    conn = connect()
    try:
        with immediate_tx(conn):
            row = conn.execute(
                "SELECT id, session_token, purpose, method, path,"
                " expires_at, consumed_at"
                " FROM auth_challenges WHERE id = ?",
                (challenge_id,),
            ).fetchone()
            if row is None:
                conn.execute("ROLLBACK")
                return None
            if (
                row["consumed_at"] is not None
                or row["expires_at"] <= now
                or row["session_token"] != session_token
                or row["purpose"] != purpose
                or row["method"] != method.upper()
                or row["path"] != path
            ):
                conn.execute("ROLLBACK")
                return None
            # Re-check that the session is still live AND key-bound at
            # submission time: it may have been revoked between challenge
            # issuance and this request.
            session = conn.execute(
                "SELECT s.token, s.expires_at, s.public_key,"
                " a.id AS account_id, a.username"
                " FROM sessions s JOIN accounts a ON a.id = s.account_id"
                " WHERE s.token = ? AND s.expires_at > ? AND s.bound = 1",
                (session_token, now),
            ).fetchone()
            if session is None:
                conn.execute("ROLLBACK")
                return None
            cur = conn.execute(
                "UPDATE auth_challenges SET consumed_at = ?"
                " WHERE id = ? AND consumed_at IS NULL",
                (now, challenge_id),
            )
            if cur.rowcount != 1:
                # Lost the concurrent-consume race (or a duplicate row id,
                # which cannot happen with 256 random bits).
                conn.execute("ROLLBACK")
                return None
            if revoke_session:
                conn.execute(
                    "DELETE FROM sessions WHERE token = ?", (session_token,)
                )
                # Outstanding challenges of the revoked session die with it.
                conn.execute(
                    "DELETE FROM auth_challenges WHERE session_token = ?",
                    (session_token,),
                )
            return session
    finally:
        conn.close()


def account_stats(now: Optional[float] = None) -> list[dict]:
    """Snapshot of every account: windowed errors, in-flight, slots left."""
    now = time.time() if now is None else now
    cutoff = now - settings.error_window_seconds
    conn = connect()
    try:
        rows = conn.execute(
            """
            SELECT a.id, a.username,
                   (SELECT COUNT(*) FROM login_errors e
                     WHERE e.account_id = a.id AND e.created_at >= ?) AS errors,
                   (SELECT COUNT(*) FROM login_inflight f
                     WHERE f.account_id = a.id) AS inflight
              FROM accounts a
             ORDER BY a.username
            """,
            (cutoff,),
        ).fetchall()
    finally:
        conn.close()
    out = []
    for row in rows:
        used = row["errors"] + row["inflight"]
        out.append(
            {
                "account_id": row["id"],
                "username": row["username"],
                "window_errors": row["errors"],
                "inflight": row["inflight"],
                "used_slots": used,
                "remaining_slots": max(0, settings.max_slots - used),
                "max_slots": settings.max_slots,
                "window_seconds": settings.error_window_seconds,
            }
        )
    return out


def next_retry_after(account_id: int, now: Optional[float] = None) -> float:
    """Seconds until at least one occupied slot frees up (for Retry-After)."""
    now = time.time() if now is None else now
    cutoff = now - settings.error_window_seconds
    conn = connect()
    try:
        oldest_error = conn.execute(
            "SELECT MIN(created_at) AS t FROM login_errors"
            " WHERE account_id = ? AND created_at >= ?",
            (account_id, cutoff),
        ).fetchone()["t"]
        oldest_inflight = conn.execute(
            "SELECT MIN(acquired_at) AS t FROM login_inflight WHERE account_id = ?",
            (account_id,),
        ).fetchone()["t"]
    finally:
        conn.close()
    candidates = []
    if oldest_error is not None:
        candidates.append(oldest_error + settings.error_window_seconds - now)
    if oldest_inflight is not None:
        # In-flight work has no known deadline from SQL's perspective; the
        # caller's requested delay bounds it, but a safe answer is to wait
        # for the oldest error to age out. Fall back to one window if the
        # account is saturated purely by in-flight attempts.
        candidates.append(settings.error_window_seconds)
    return max(1.0, min(candidates) if candidates else 1.0)
