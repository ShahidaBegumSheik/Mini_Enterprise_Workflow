import base64
import hashlib
import hmac
import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from cryptography.fernet import Fernet
from jose import ExpiredSignatureError, JWTError, jwt

from app.core.config import settings

_hasher = PasswordHasher()
_fernet_instance: Fernet | None = None


# ---------------------------------------------------------------------------
# OTP
# ---------------------------------------------------------------------------


def generate_otp(length: int | None = None) -> str:
    """Generate a cryptographically secure numeric OTP."""
    digits = length or settings.otp_length
    return f"{secrets.randbelow(10 ** digits):0{digits}d}"


def compare_otp(submitted: str, expected: str) -> bool:
    """Constant-time comparison of the submitted OTP against the expected one."""
    return hmac.compare_digest(submitted, expected)


# ---------------------------------------------------------------------------
# Fernet (encrypts the sensitive OTP flow payload, including the OTP itself)
# ---------------------------------------------------------------------------

def _fernet_otp_key_bytes() -> bytes:
    raw = settings.otp_encryption_key.strip()
    if raw:
        try:
            key = base64.urlsafe_b64decode(raw.encode("ascii"))
        except Exception as exc:
            raise ValueError("OTP_ENCRYPTION_KEY must be a base64-urlsafe encoded 32-byte key") from exc
        if len(key) != 32:
            raise ValueError("OTP_ENCRYPTION_KEY must decode to exactly 32 bytes")
        return key
    digest = hashlib.sha256(settings.jwt_secret_key.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


def _fernet() -> Fernet:
    global _fernet_instance
    if _fernet_instance is None:
        _fernet_instance = Fernet(_fernet_otp_key_bytes())
    return _fernet_instance


# ---------------------------------------------------------------------------
# OTP flow token (signed JWT wrapping an encrypted, short-lived payload)
# ---------------------------------------------------------------------------


def seal_otp_flow(
    payload: dict[str, Any],
    ttl: timedelta | None = None,
    *,
    exp_at: datetime | None = None,
) -> str:
    """Create the signed OTP flow token.

    The sensitive payload (registration data + the OTP itself) is encrypted
    with Fernet and carried in a single ``data`` claim of an HS256-signed
    JWT. Raw OTP values are therefore never persisted or logged, and the
    token is both authenticated (signature) and confidential (encryption).

    The absolute expiry is stamped into the encrypted payload as well, so a
    re-issued token (resend / wrong attempt) can preserve the original
    expiry bound instead of extending it.
    """
    if exp_at is None:
        exp_at = datetime.now(timezone.utc) + (ttl or timedelta(minutes=settings.otp_expire_minutes))
    payload = {**payload, "exp_at": exp_at.isoformat()}
    encrypted = _fernet().encrypt(
        json.dumps(payload, separators=(",", ":")).encode("utf-8")
    )
    claims = {
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "jti": secrets.token_hex(16),
        "use": "otp_flow",
        "data": encrypted.decode("ascii"),
        "iat": datetime.now(timezone.utc),
        "exp": exp_at,
    }
    return jwt.encode(claims, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def open_otp_flow(token: str) -> dict[str, Any]:
    """Verify the OTP flow token and return its decrypted payload.

    Raises ValueError for any invalid, tampered or expired token.
    """
    try:
        claims = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
            audience=settings.jwt_audience,
            issuer=settings.jwt_issuer,
        )
    except ExpiredSignatureError as exc:
        raise ValueError("OTP has expired") from exc
    except JWTError as exc:
        raise ValueError("Invalid or expired OTP flow token") from exc

    if claims.get("use") != "otp_flow" or not claims.get("data"):
        raise ValueError("Invalid or expired OTP flow token")

    try:
        raw = _fernet().decrypt(claims["data"].encode("ascii"))
        payload = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise ValueError("Invalid or expired OTP flow token") from exc

    exp_at = payload.get("exp_at")
    if exp_at:
        try:
            expires = datetime.fromisoformat(exp_at)
        except (TypeError, ValueError) as exc:
            raise ValueError("Invalid or expired OTP flow token") from exc
        if expires <= datetime.now(timezone.utc):
            raise ValueError("OTP has expired")
    return payload


# ---------------------------------------------------------------------------
# Passwords
# ---------------------------------------------------------------------------


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, encoded: str) -> bool:
    try:
        return _hasher.verify(encoded, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


# ---------------------------------------------------------------------------
# Session tokens (access + refresh JWTs)
# ---------------------------------------------------------------------------

ACCESS_TOKEN_TYPE = "access"
REFRESH_TOKEN_TYPE = "refresh"


class TokenError(Exception):
    """Raised when a session token cannot be validated (expired, tampered, wrong type)."""


def _base_token_claims(
    user_id: int,
    token_type: str,
    ttl: timedelta,
    *,
    token_version: int | None = None,
    session_id: str | None = None,
) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    claims: dict[str, Any] = {
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "sub": str(user_id),
        "jti": secrets.token_hex(16),
        "type": token_type,
        "iat": now,
        "exp": now + ttl,
    }
    if token_version is not None:
        claims["ver"] = token_version
    if session_id is not None:
        claims["sid"] = session_id
    return claims


def _encode(claims: dict[str, Any]) -> str:
    return jwt.encode(claims, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def create_access_token(
    user_id: int,
    *,
    token_version: int | None = None,
    session_id: str | None = None,
    ttl: timedelta | None = None,
) -> str:
    """Create a signed authentication JWT (purpose: authentication)."""
    ttl = ttl or timedelta(minutes=settings.access_token_expire_minutes)
    return _encode(
        _base_token_claims(user_id, ACCESS_TOKEN_TYPE, ttl, token_version=token_version, session_id=session_id)
    )


def create_refresh_token(
    user_id: int,
    *,
    token_version: int | None = None,
    session_id: str | None = None,
    jti: str | None = None,
    ttl: timedelta | None = None,
) -> str:
    """Create a signed session-renewal JWT (purpose: session renewal)."""
    ttl = ttl or timedelta(days=settings.refresh_token_expire_days)
    claims = _base_token_claims(
        user_id, REFRESH_TOKEN_TYPE, ttl, token_version=token_version, session_id=session_id
    )
    if jti:
        claims["jti"] = jti
    return _encode(claims)


def decode_token(token: str, *, expected_type: str | None = None) -> dict[str, Any]:
    """Verify signature/audience/issuer/expiry and return the claims.

    Raises TokenError for expired, tampered, malformed or wrong-typed tokens.
    """
    try:
        claims = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
            audience=settings.jwt_audience,
            issuer=settings.jwt_issuer,
        )
    except ExpiredSignatureError as exc:
        raise TokenError("Token has expired") from exc
    except JWTError as exc:
        raise TokenError("Invalid token") from exc

    if expected_type is not None and claims.get("type") != expected_type:
        raise TokenError("Invalid token type")
    return claims


def validate_access_token(token: str) -> dict[str, Any]:
    """Validate an access token and return its claims. Raises TokenError otherwise."""
    return decode_token(token, expected_type=ACCESS_TOKEN_TYPE)


def validate_refresh_token(token: str) -> dict[str, Any]:
    """Validate a refresh token and return its claims. Raises TokenError otherwise."""
    return decode_token(token, expected_type=REFRESH_TOKEN_TYPE)