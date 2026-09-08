import hashlib
import secrets
from datetime import datetime, timedelta, timezone

import bcrypt
from jose import JWTError, jwt

from app.core.config import settings


def hash_password(password: str) -> str:
    return bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt(rounds=settings.BCRYPT_ROUNDS),
    ).decode("utf-8")


def verify_password(
    plain_password: str,
    hashed_password: str,
) -> bool:
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8"),
        )
    except ValueError:
        return False


def create_access_token(
    data: dict,
) -> str:
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
    )

    payload = data.copy()
    payload.update(
        {
            "type": "access",
            "exp": expire,
        }
    )

    return jwt.encode(
        payload,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )


def create_refresh_token(
    data: dict,
) -> str:
    expire = datetime.now(timezone.utc) + timedelta(
        days=settings.REFRESH_TOKEN_EXPIRE_DAYS
    )

    payload = data.copy()
    payload.update(
        {
            "type": "refresh",
            "exp": expire,
            "jti": secrets.token_urlsafe(32),
        }
    )

    return jwt.encode(
        payload,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )


def decode_token(token: str) -> dict:
    return jwt.decode(
        token,
        settings.JWT_SECRET_KEY,
        algorithms=[settings.JWT_ALGORITHM],
    )


def create_otp_token(
    data: dict,
) -> str:
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=settings.OTP_EXPIRE_MINUTES
    )

    payload = data.copy()
    payload.update(
        {
            "type": "otp",
            "exp": expire,
        }
    )

    return jwt.encode(
        payload,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )


def generate_otp() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


def hash_otp(otp: str) -> str:
    return hashlib.sha256(
        otp.encode("utf-8")
    ).hexdigest()


def verify_otp(
    otp: str,
    otp_hash: str,
) -> bool:
    return secrets.compare_digest(
        hash_otp(otp),
        otp_hash,
    )