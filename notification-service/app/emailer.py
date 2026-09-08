import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from app.config import settings

logger = logging.getLogger(__name__)


class EmailDeliveryError(Exception):
    """Raised when an email cannot be delivered."""


def smtp_configured() -> bool:
    return bool(settings.SMTP_ENABLED and settings.SMTP_HOST)


def send_email(to_email: str, subject: str, body: str) -> None:
    """Send a plain-text email via SMTP.

    The recipient address and subject are logged for observability, but the
    message body (which may contain an OTP) is never logged.
    """
    if not smtp_configured():
        raise EmailDeliveryError(
            "Email delivery is not configured. Set SMTP_ENABLED=true and "
            "SMTP_HOST to enable sending."
        )

    from_email = settings.SMTP_FROM_EMAIL or settings.SMTP_USERNAME
    if not from_email:
        raise EmailDeliveryError(
            "Email delivery is not configured. SMTP_FROM_EMAIL or "
            "SMTP_USERNAME must be set when SMTP is enabled."
        )

    message = MIMEMultipart("alternative")
    message["Subject"] = subject
    message["From"] = from_email
    message["To"] = to_email
    message.attach(MIMEText(body, "plain", "utf-8"))

    try:
        if settings.SMTP_USE_TLS:
            with smtplib.SMTP(
                settings.SMTP_HOST, settings.SMTP_PORT, timeout=15
            ) as server:
                server.starttls()
                if settings.SMTP_USERNAME:
                    server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
                server.send_message(message)
        else:
            with smtplib.SMTP(
                settings.SMTP_HOST, settings.SMTP_PORT, timeout=15
            ) as server:
                if settings.SMTP_USERNAME:
                    server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
                server.send_message(message)
    except EmailDeliveryError:
        raise
    except Exception as exc:
        logger.warning(
            "SMTP delivery failed for %s: %s", to_email, exc.__class__.__name__
        )
        raise EmailDeliveryError("SMTP delivery failed") from exc

    logger.info("OTP email delivered to %s (subject: %s)", to_email, subject)