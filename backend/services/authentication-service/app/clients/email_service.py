from typing import Any

from app.core.email_sender import send_email


class EmailServiceClient:
    async def send_email_notification(
        self,
        *,
        recipient_email: str,
        event_type: str,
        template_variables: dict[str, Any],
    ) -> None:
        otp = template_variables.get("otp") if isinstance(template_variables, dict) else None
        expires_minutes = template_variables.get("expires_in_minutes") if isinstance(template_variables, dict) else None
        if event_type == "individual_registration_otp":
            subject = "Your verification code"
            body = f"Your OTP is {otp}. It expires in {expires_minutes} minutes."
            send_email(recipient_email, subject, body)
            return
        if event_type == "organization_registration_otp":
            subject = "Your organization verification code"
            body = f"Your OTP is {otp}. It expires in {expires_minutes} minutes."
            send_email(recipient_email, subject, body)
            return
        if event_type == "forgot_password_otp":
            subject = "Password reset code"
            body = f"Your OTP is {otp}. It expires in {expires_minutes} minutes."
            send_email(recipient_email, subject, body)
            return
        subject = "MECWF notification"
        body = f"Event: {event_type}. Details: {template_variables}"
        send_email(recipient_email, subject, body)
