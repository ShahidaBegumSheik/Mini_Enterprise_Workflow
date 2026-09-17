import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from jose import JWTError, jwt

from app.core.config import settings

_hasher = PasswordHasher()


def generate_otp() -> str:
    return f"{secrets.randbelow(10 ** settings.otp_length):0{settings.otp_length}d}"


def hash_otp(code: str) -> str:
    return _hasher.hash(code)


def verify_otp(code: str, encoded: str) -> bool:
    try:
        return _hasher.verify(encoded, code)
    except (VerifyMismatchError, InvalidHashError):
        return False


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, encoded: str) -> bool:
    try:
        return _hasher.verify(encoded, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_token(payload: dict, expires: timedelta) -> str:
    data = payload.copy()
    data.update(
        {
            "iss": settings.jwt_issuer,
            "aud": settings.jwt_audience,
            "jti": secrets.token_hex(16),
            "exp": datetime.now(timezone.utc) + expires,
        }
    )
    return jwt.encode(data, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
            audience=settings.jwt_audience,
            issuer=settings.jwt_issuer,
        )
    except JWTError as exc:
        raise ValueError("Invalid or expired token") from exc


def create_access_token(user_id: int, version: int = 0) -> str:
    return create_token(
        {"sub": str(user_id), "type": "access", "ver": version},
        timedelta(minutes=settings.access_token_expire_minutes),
    )


def create_refresh_token(user_id: int, version: int = 0) -> str:
    return create_token(
        {"sub": str(user_id), "type": "refresh", "ver": version},
        timedelta(days=settings.refresh_token_expire_days),
    )


def create_password_reset_verified_token(user_id: int, flow_id: str) -> str:
    return create_token(
        {"sub": str(user_id), "type": "password_reset_verified", "flow": flow_id},
        timedelta(minutes=settings.otp_expire_minutes),
    )