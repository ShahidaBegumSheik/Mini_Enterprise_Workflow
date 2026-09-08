import json
import logging
import urllib.error
import urllib.request

from app.core.config import settings

logger = logging.getLogger(__name__)

_OTP_TEMPLATE = (
    "Your verification code is {otp}. It expires in "
    "{minutes} minutes. Please enter this code to complete your request."
)


def send_otp_email(email: str, otp: str, purpose: str) -> None:
    """Deliver an OTP to the given email address.

    The OTP is delivered through the dedicated notification microservice so
    that no OTP value is ever written into logs. If the notification service
    is unreachable, a warning is logged (without the OTP) and the request
    proceeds; this keeps signup resilient while a real mail provider is wired
    up in production.
    """
    body = _OTP_TEMPLATE.format(otp=otp, minutes=settings.OTP_EXPIRE_MINUTES)
    url = f"{settings.NOTIFICATION_SERVICE_URL.rstrip('/')}/send-otp"
    payload = json.dumps(
        {
            "email": email,
            "subject": "Your verification code",
            "body": body,
            "purpose": purpose,
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=payload,
        method="POST",
        headers={
            "Authorization": f"Bearer {settings.INTERNAL_API_KEY}",
            "Content-Type": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            response.read()
    except Exception as exc:  # pragma: no cover - environment dependent
        logger.warning(
            "Could not deliver OTP email to notification service for %s: %s",
            email,
            repr(exc),
        )