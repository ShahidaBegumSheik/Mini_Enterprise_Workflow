import hashlib
from datetime import datetime, timedelta

from fastapi import HTTPException, status
from jose import JWTError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import (
    create_refresh_token,
    decode_token,
)
from app.models.refresh_token import RefreshToken


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _utcnow() -> datetime:
    return datetime.utcnow()


def issue_refresh_token(db: Session, user_id: int) -> str:
    """Create a refresh token, persist it, and return the raw JWT."""
    token = create_refresh_token({"sub": str(user_id)})
    payload = decode_token(token)
    jti = payload["jti"]

    record = RefreshToken(
        user_id=user_id,
        jti=jti,
        token_hash=_hash_token(token),
        expires_at=_utcnow()
        + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        is_revoked=False,
    )
    db.add(record)
    db.commit()
    return token


def get_stored_token_by_jti(db: Session, jti: str) -> RefreshToken | None:
    return db.query(RefreshToken).filter(RefreshToken.jti == jti).first()


def validate_refresh_token(
    db: Session,
    token: str,
) -> RefreshToken:
    """Validate a refresh token JWT and return its stored record.

    Raises HTTP 401 for missing/invalid/expired/revoked tokens.
    """
    try:
        payload = decode_token(token)
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )

    if payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )

    jti = payload.get("jti")
    record = get_stored_token_by_jti(db, jti)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )

    if record.is_revoked:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has been revoked",
        )

    if _utcnow() > record.expires_at:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has expired",
        )

    return record


def revoke_token(db: Session, record: RefreshToken) -> None:
    record.is_revoked = True
    db.commit()


def rotate_refresh_token(
    db: Session,
    refresh_token: str,
    user_id: int,
) -> str:
    old_record = validate_refresh_token(db, refresh_token)
    revoke_token(db, old_record)
    return issue_refresh_token(db, user_id)
