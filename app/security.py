"""Password hashing (argon2), session tokens and ECDSA P-256 verification."""
from __future__ import annotations

import hmac
import secrets
from base64 import urlsafe_b64decode

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

# Deliberately interactive-grade parameters: this is the expensive operation
# that must run *outside* the SQLite write transaction/lock.
ph = PasswordHasher(
    time_cost=3,
    memory_cost=64 * 1024,  # 64 MiB
    parallelism=2,
    hash_len=32,
    salt_len=16,
)


def hash_password(password: str) -> str:
    return ph.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    """Constant-ish argon2 verification. Never raises on a wrong password."""
    try:
        return ph.verify(password_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False
    except Exception:
        # Malformed hash etc. treat as authentication failure rather than
        # leaking a 500 that differentiates accounts.
        return False


def needs_rehash(password_hash: str) -> bool:
    try:
        return ph.check_needs_rehash(password_hash)
    except Exception:
        return False


def new_session_token() -> str:
    """256 bits of CSPRNG randomness, URL-safe."""
    return secrets.token_urlsafe(32)


def compare_tokens(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)


# ---------------------------------------------------------------------------
# ECDSA P-256 proof-of-possession primitives
# ---------------------------------------------------------------------------
#
# Wire formats (mirrored 1:1 by the browser's Web Crypto code):
#   * public key: raw uncompressed point, base64url, 65 bytes when decoded
#     (0x04 || X || Y). Stored as hex in SQLite.
#   * signature: Web Crypto's raw ECDSA signature is the fixed-length
#     concatenation r || s (64 bytes for P-256), base64url encoded.
#   * signed message: an explicit, length-prefixed ASCII string so no field
#     can be confused with another -- see build_signing_message.

_P256_RAW_KEY_LEN = 65
_P256_RAW_SIG_LEN = 64


def _b64url_decode(data: str) -> bytes:
    # Be permissive about padding; reject anything that still will not parse.
    pad = "=" * (-len(data) % 4)
    return urlsafe_b64decode(data + pad)


def decode_public_key(public_key_b64url: str) -> ec.EllipticCurvePublicKey:
    """Parse a Web Crypto raw P-256 public key; raise ValueError if malformed."""
    try:
        raw = _b64url_decode(public_key_b64url)
    except Exception as exc:  # noqa: BLE001 - any decode failure is a bad key
        raise ValueError("public key is not valid base64url") from exc
    if len(raw) != _P256_RAW_KEY_LEN or raw[0] != 0x04:
        raise ValueError("public key is not an uncompressed P-256 point")
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
    except Exception as exc:  # noqa: BLE001 - invalid curve point etc.
        raise ValueError("invalid P-256 public key") from exc


def public_key_to_hex(public_key_b64url: str) -> str:
    """Validate and normalize a client public key for storage/comparison."""
    return decode_public_key(public_key_b64url).public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    ).hex()


def _raw_signature_to_der(raw: bytes) -> bytes:
    if len(raw) != _P256_RAW_SIG_LEN:
        raise ValueError("signature must be 64 bytes (r || s)")
    r = int.from_bytes(raw[:32], "big")
    s = int.from_bytes(raw[32:], "big")
    return encode_dss_signature(r, s)


def build_signing_message(challenge: str, method: str, path: str) -> bytes:
    """Deterministic byte string covered by the ECDSA signature.

    Every field is length-prefixed so ``("ab","c")`` cannot collide with
    ``("a","bc")``. The HTTP method is normalized upper-case; the path is
    stored on the challenge-side request exactly as the server will
    re-serialize it, so the client signs precisely what the server checks.
    """
    parts = (challenge.encode("ascii"), method.upper().encode("ascii"),
             path.encode("ascii"))
    out = bytearray()
    for part in parts:
        out += str(len(part)).encode("ascii")
        out += b":"
        out += part
        out += b"|"
    return bytes(out)


def verify_ecdsa_signature(
    public_key_hex: str, signature_b64url: str, message: bytes
) -> bool:
    """Verify a raw r||s ECDSA-SHA256 signature. Never raises."""
    try:
        raw_sig = _b64url_decode(signature_b64url)
        der_sig = _raw_signature_to_der(raw_sig)
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), bytes.fromhex(public_key_hex)
        )
        public_key.verify(
            der_sig, message, ec.ECDSA(hashes.SHA256())
        )
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
    except Exception:  # noqa: BLE001 - verification must never 500
        return False
