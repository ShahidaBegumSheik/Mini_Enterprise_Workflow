import smtplib
from email.message import EmailMessage

from app.core.config import settings


def send_email(
    to_email: str,
    subject: str,
    body: str,
) -> bool:
    if not settings.smtp_enabled:
        print(
            f"[EMAIL DISABLED] To: {to_email}, Subject: {subject}, Body: {body}",
        )
        return False

    recipient = settings.developer_redirect_email or to_email

    from_email = (
        settings.smtp_from_email
        or settings.smtp_username
        or "noreply@mecwf.local"
    )

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = (
        f"{settings.email_from_name} <{from_email}>"
        if settings.email_from_name
        else from_email
    )
    message["To"] = recipient
    message.set_content(body)

    try:
        if settings.smtp_use_ssl:
            with smtplib.SMTP_SSL(settings.smtp_host, settings.smtp_port) as smtp:
                if settings.smtp_username:
                    smtp.login(settings.smtp_username, settings.smtp_password)
                smtp.send_message(message)
        else:
            with smtplib.SMTP(settings.smtp_host, settings.smtp_port) as smtp:
                smtp.ehlo()
                if settings.smtp_use_tls:
                    smtp.starttls()
                    smtp.ehlo()
                if settings.smtp_username:
                    smtp.login(settings.smtp_username, settings.smtp_password)
                smtp.send_message(message)
        return True
    except Exception as exc:
        print("EMAIL SEND ERROR:", type(exc).__name__, str(exc))
        return False