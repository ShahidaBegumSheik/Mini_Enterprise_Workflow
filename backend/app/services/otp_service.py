from datetime import datetime, timedelta

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.email import send_otp_email
from app.core.security import generate_otp, hash_otp, verify_otp as verify_otp_hash
from app.models.otp_verification import OTPVerification

REGISTRATION_PURPOSE = "registration"
RESET_PURPOSE = "reset_password"


def _utcnow() -> datetime:
    return datetime.utcnow()


def create_otp(
    db: Session,
    email: str,
    purpose: str,
    otp_code: str | None = None,
) -> OTPVerification:
    """Create a fresh OTP record, invalidating any previous one for the same
    email/purpose, and deliver it via email."""
    old = (
        db.query(OTPVerification)
        .filter(
            OTPVerification.email == email,
            OTPVerification.purpose == purpose,
        )
        .all()
    )
    for record in old:
        db.delete(record)
    db.flush()

    code = otp_code if otp_code is not None else generate_otp()
    record = OTPVerification(
        email=email,
        otp_hash=hash_otp(code),
        purpose=purpose,
        expires_at=_utcnow() + timedelta(minutes=settings.OTP_EXPIRE_MINUTES),
        attempts=0,
        is_verified=False,
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    send_otp_email(email=email, otp=code, purpose=purpose)
    return record


def resend_otp(
    db: Session,
    email: str,
    purpose: str,
    otp_code: str | None = None,
) -> OTPVerification:
    """Resend an OTP. Enforces a cooldown period and invalidates the old OTP."""
    existing = (
        db.query(OTPVerification)
        .filter(
            OTPVerification.email == email,
            OTPVerification.purpose == purpose,
        )
        .order_by(OTPVerification.created_at.desc())
        .first()
    )

    if existing and not existing.is_verified:
        elapsed = (_utcnow() - existing.created_at).total_seconds()
        cooldown = settings.OTP_RESEND_COOLDOWN_SECONDS
        if elapsed < cooldown:
            remaining = int(cooldown - elapsed)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Please wait {remaining} seconds before resending",
            )

    return create_otp(
        db=db,
        email=email,
        purpose=purpose,
        otp_code=otp_code,
    )


def verify_otp(
    db: Session,
    otp_record: OTPVerification,
    otp_code: str,
) -> bool:
    """Verify a provided OTP against the stored (hashed) OTP with attempt and
    expiry enforcement."""
    if otp_record.is_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This OTP has already been used",
        )

    if _utcnow() > otp_record.expires_at:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OTP has expired",
        )

    if otp_record.attempts >= settings.OTP_MAX_ATTEMPTS:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Maximum OTP attempts exceeded. Please resend a new OTP",
        )

    if not verify_otp_hash(otp_code, otp_record.otp_hash):
        otp_record.attempts += 1
        db.commit()
        remaining = settings.OTP_MAX_ATTEMPTS - otp_record.attempts
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Invalid OTP"
                + (f". {remaining} attempt(s) remaining" if remaining > 0 else "")
            ),
        )

    otp_record.attempts += 1
    otp_record.is_verified = True
    otp_record.expires_at = _utcnow()
    db.commit()
    return True


def get_otp_by_token_context(
    db: Session,
    email: str,
    purpose: str,
) -> OTPVerification | None:
    return (
        db.query(OTPVerification)
        .filter(
            OTPVerification.email == email,
            OTPVerification.purpose == purpose,
        )
        .order_by(OTPVerification.created_at.desc())
        .first()
    )


def get_active_otp(
    db: Session,
    email: str,
    purpose: str,
) -> OTPVerification | None:
    """Return a pending (not verified, not expired) OTP record if one exists."""
    record = get_otp_by_token_context(db, email, purpose)
    if record is None or record.is_verified:
        return None
    if _utcnow() > record.expires_at:
        return None
    return record
