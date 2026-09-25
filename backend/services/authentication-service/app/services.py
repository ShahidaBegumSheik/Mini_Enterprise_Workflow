"""Business logic and email delivery for the Authentication Service (single source file)."""

import secrets
import smtplib
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from typing import Any

import httpx
from fastapi import HTTPException

from app.clients.contracts import ServiceCallError, ServiceResponseError
from app.clients.tenant_admin_service import TenantAdminServiceClient
from app.clients.user_service import UserServiceClient
from app.core.config import settings
from app.core.security import (
    TokenError,
    compare_otp,
    create_access_token,
    create_refresh_token,
    generate_otp,
    hash_password,
    open_otp_flow,
    seal_otp_flow,
    validate_refresh_token,
    verify_password,
)
from app.core.utils import utcnow
from app.repositories import AuthRepository
from app.schemas import RegisterRequest

__all__ = [
    "FlowError",
    "InvalidOTPError",
    "OTPAttemptsExhaustedError",
    "OTPResendLimitExceededError",
    "AuthService",
    "send_email",
]

REGISTRATION_PURPOSE = "registration"


class FlowError(Exception):
    """Base error for OTP flow problems surfaced to the HTTP layer."""

    status = 400
    detail = "Invalid OTP flow"


class InvalidOTPError(FlowError):
    def __init__(self, remaining_attempts: int, new_token: str) -> None:
        self.remaining_attempts = remaining_attempts
        self.new_token = new_token
        super().__init__("Invalid OTP")


class OTPAttemptsExhaustedError(FlowError):
    status = 429
    detail = "Maximum OTP verification attempts exceeded"


class OTPResendLimitExceededError(FlowError):
    status = 429
    detail = "Maximum OTP resend limit exceeded"


def _flow_exp_at(flow: dict[str, Any]) -> datetime:
    return datetime.fromisoformat(flow["exp_at"])


def _flow_remaining_seconds(flow: dict[str, Any]) -> int:
    remaining = int((_flow_exp_at(flow) - datetime.now(timezone.utc)).total_seconds())
    return max(remaining, 0) if remaining else 0


def _seal_preserving_expiry(flow: dict[str, Any]) -> str:
    """Re-seal a flow payload keeping the original expiry bound."""
    return seal_otp_flow(flow, exp_at=_flow_exp_at(flow))


def _extract_user_id(response: dict[str, Any], service: str) -> int:
    user_id = response.get("user_id") if response.get("user_id") is not None else response.get("id")
    try:
        return int(user_id)
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=502,
            detail=f"{service} returned an invalid response",
        ) from exc


def _extract_organization_id(response: dict[str, Any], service: str) -> int:
    org_id = (
        response.get("organization_id")
        if response.get("organization_id") is not None
        else response.get("tenant_id")
        if response.get("tenant_id") is not None
        else response.get("id")
    )
    try:
        return int(org_id)
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=502,
            detail=f"{service} returned an invalid response",
        ) from exc


def _map_upstream_error(
    exc: Exception,
    service: str,
    conflict_detail: str,
) -> HTTPException:
    if isinstance(exc, ServiceCallError):
        if exc.status_code == 409:
            return HTTPException(status_code=409, detail=conflict_detail)
        if 400 <= exc.status_code < 500:
            return HTTPException(
                status_code=502,
                detail=f"{service} rejected the registration request",
            )
        return HTTPException(
            status_code=502,
            detail=f"{service} failed (HTTP {exc.status_code})",
        )
    if isinstance(exc, ServiceResponseError):
        return HTTPException(
            status_code=502,
            detail=f"{service} returned an invalid response",
        )
    if isinstance(exc, httpx.HTTPError):
        return HTTPException(
            status_code=503,
            detail=f"{service} is unreachable at this time",
        )
    return HTTPException(
        status_code=502,
        detail=f"{service} could not complete the registration",
    )


class AuthService:
    """Authentication orchestrator for the registration flow.

    The Authentication Service owns credentials only; user records are
    created through the User Service HTTP contract and organization records
    through the Tenant Admin Service HTTP contract. The OTP flow itself is
    entirely stateless: the OTP and the minimum required registration data
    travel inside a short-lived, signed and encrypted ``otp_token`` cookie.
    """

    def __init__(
        self,
        repo: AuthRepository,
        users: UserServiceClient,
        tenants: TenantAdminServiceClient,
    ) -> None:
        self.repo = repo
        self.users = users
        self.tenants = tenants

    async def register(self, data: RegisterRequest) -> dict[str, Any]:
        email = str(data.email).lower()

        if self.repo.credential_by_email(email):
            raise HTTPException(status_code=409, detail="Email is already registered")

        otp = generate_otp()
        flow_payload: dict[str, Any] = {
            "purpose": REGISTRATION_PURPOSE,
            "email": email,
            "full_name": data.full_name,
            "account_type": data.account_type,
            "organization_name": data.organization_name,
            "organization_type": data.organization_type,
            "industry": data.industry,
            "password_hash": hash_password(data.password),
            "otp": otp,
            "attempts": 0,
            "resends": 0,
        }
        token = seal_otp_flow(
            flow_payload,
            ttl=timedelta(minutes=settings.otp_expire_minutes),
        )
        await self._send_otp(email, otp)
        return {"token": token, "expires_in": settings.otp_expire_minutes * 60}

    async def login(
        self,
        email: str,
        password: str,
        *,
        device_info: str | None = None,
        ip_address: str | None = None,
    ) -> dict[str, Any]:
        """Authenticate a principal against this service's credential store.

        Credentials (email + password hash + status) are owned by this
        service's own database; the User Service is never reached directly
        and profile data is resolved later through the User Service contract.
        """
        credential = self.repo.credential_by_email(email.lower())
        if credential is None or not verify_password(password, credential.password_hash):
            raise HTTPException(status_code=401, detail="Incorrect email or password")

        if not credential.is_active:
            raise HTTPException(status_code=403, detail="Account is inactive")
        if not credential.is_verified:
            raise HTTPException(status_code=403, detail="Account is not verified")

        session_id = secrets.token_hex(16)
        expires_at = utcnow() + timedelta(days=settings.refresh_token_expire_days)
        self.repo.create_refresh_session(
            session_id=session_id,
            user_id=credential.user_id,
            expires_at=expires_at,
            device_info=device_info,
            ip_address=ip_address,
        )

        access_token = create_access_token(
            credential.user_id,
            token_version=credential.token_version,
            session_id=session_id,
        )
        refresh_token = create_refresh_token(
            credential.user_id,
            token_version=credential.token_version,
            session_id=session_id,
            jti=session_id,
        )

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user_id": credential.user_id,
            "email": credential.email,
            "account_type": credential.account_type,
            "session_id": session_id,
            "access_token_expires_in": settings.access_token_expire_minutes * 60,
            "refresh_token_expires_in": settings.refresh_token_expire_days * 24 * 60 * 60,
        }

    async def refresh(
        self,
        refresh_token: str,
        *,
        device_info: str | None = None,
        ip_address: str | None = None,
    ) -> dict[str, Any]:
        """Rotate a valid refresh token into a fresh session.

        Order: signature/expiry/type validation, then session-state validation,
        then rotation. The old session is revoked and linked to the new one via
        ``replaced_by`` so that presenting an already-rotated token (reuse) can
        be detected and the entire token family revoked.
        """
        try:
            claims = validate_refresh_token(refresh_token)
        except TokenError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc

        session_id = claims.get("sid") or claims.get("jti")
        if not session_id:
            raise HTTPException(status_code=401, detail="Invalid refresh token")

        session = self.repo.refresh_session_by_id(session_id)
        if session is None:
            raise HTTPException(status_code=401, detail="Invalid refresh token")
        if session.revoked_at is not None:
            # Already rotated or revoked: this is a reuse/revoked-token attempt.
            # Kill the whole refresh family, then reject.
            self.repo.revoke_refresh_family(session_id)
            raise HTTPException(
                status_code=401, detail="Refresh token has been revoked"
            ) from None
        try:
            sub = int(claims["sub"])
        except (KeyError, TypeError, ValueError) as exc:
            raise HTTPException(status_code=401, detail="Invalid refresh token") from exc
        if sub != session.user_id:
            raise HTTPException(status_code=401, detail="Invalid refresh token")
        if session.expires_at <= utcnow():
            self.repo.revoke_refresh_session(session_id)
            raise HTTPException(status_code=401, detail="Refresh token has expired")

        credential = self.repo.credential_by_user_id(session.user_id)
        if credential is None or not credential.is_active or not credential.is_verified:
            self.repo.revoke_refresh_family(session_id)
            raise HTTPException(status_code=401, detail="Invalid refresh token")

        new_session_id = secrets.token_hex(16)
        expires_at = utcnow() + timedelta(days=settings.refresh_token_expire_days)
        self.repo.create_refresh_session(
            session_id=new_session_id,
            user_id=credential.user_id,
            expires_at=expires_at,
            device_info=device_info,
            ip_address=ip_address,
        )
        self.repo.revoke_refresh_session(session_id, replaced_by=new_session_id)

        access_token = create_access_token(
            credential.user_id,
            token_version=credential.token_version,
            session_id=new_session_id,
        )
        new_refresh_token = create_refresh_token(
            credential.user_id,
            token_version=credential.token_version,
            session_id=new_session_id,
            jti=new_session_id,
        )

        return {
            "access_token": access_token,
            "refresh_token": new_refresh_token,
            "user_id": credential.user_id,
            "session_id": new_session_id,
            "access_token_expires_in": settings.access_token_expire_minutes * 60,
            "refresh_token_expires_in": settings.refresh_token_expire_days * 24 * 60 * 60,
        }

    async def logout(self, refresh_token: str | None) -> dict[str, Any]:
        """Revoke the session tied to this refresh token, if any.

        Idempotent and safe when the token is missing, malformed or already
        revoked. Never raises; the caller always clears the auth cookies.
        """
        if not refresh_token:
            return {"revoked": False}
        try:
            claims = validate_refresh_token(refresh_token)
        except TokenError:
            return {"revoked": False}

        session_id = claims.get("sid") or claims.get("jti")
        session = self.repo.refresh_session_by_id(session_id) if session_id else None
        if session is None or session.revoked_at is not None:
            return {"revoked": False}

        self.repo.revoke_refresh_session(session_id)
        return {"revoked": True}

    async def resend_otp(self, token: str) -> dict[str, Any]:
        flow = self._open_flow(token)

        if flow["resends"] >= settings.otp_max_resends:
            raise OTPResendLimitExceededError()

        otp = generate_otp()
        flow["otp"] = otp
        flow["attempts"] = 0
        flow["resends"] = flow["resends"] + 1

        new_token = _seal_preserving_expiry(flow)
        await self._send_otp(flow["email"], otp)
        return {
            "token": new_token,
            "resend_count": flow["resends"],
            "expires_in": _flow_remaining_seconds(flow),
        }

    async def verify_otp(self, token: str, submitted_otp: str) -> dict[str, Any]:
        flow = self._open_flow(token)

        if flow["attempts"] >= settings.otp_max_attempts:
            raise OTPAttemptsExhaustedError()

        if not compare_otp(submitted_otp, flow["otp"]):
            flow["attempts"] = flow["attempts"] + 1
            remaining = max(settings.otp_max_attempts - flow["attempts"], 0)
            raise InvalidOTPError(remaining, _seal_preserving_expiry(flow))

        account_type = flow["account_type"]
        organization: dict[str, Any] | None = None
        organization_id: int | None = None

        if self.repo.credential_by_email(flow["email"]):
            raise HTTPException(status_code=409, detail="Email is already registered")

        if account_type == "organization":
            try:
                organization = await self.tenants.create_organization(
                    {
                        "name": flow["organization_name"],
                        "organization_type": flow["organization_type"] or "enterprise",
                        "industry": flow["industry"],
                    }
                )
            except Exception as exc:
                raise _map_upstream_error(
                    exc, "tenant-admin-service", "Organization already exists"
                ) from exc
            organization_id = _extract_organization_id(
                organization, "tenant-admin-service"
            )
            try:
                user_profile = await self.users.create_user(
                    {
                        "full_name": flow["full_name"],
                        "email": flow["email"],
                        "account_type": account_type,
                        "organization_id": organization_id,
                        "role_code": "tenant_admin",
                    }
                )
            except Exception as exc:
                raise _map_upstream_error(
                    exc, "user-service", "Email is already registered"
                ) from exc
        else:
            try:
                user_profile = await self.users.create_user(
                    {
                        "full_name": flow["full_name"],
                        "email": flow["email"],
                        "account_type": account_type,
                    }
                )
            except Exception as exc:
                raise _map_upstream_error(
                    exc, "user-service", "Email is already registered"
                ) from exc

        user_id = _extract_user_id(user_profile, "user-service")

        self.repo.create_credential(
            user_id=user_id,
            email=flow["email"],
            password_hash=flow["password_hash"],
            account_type=account_type,
            organization_id=organization_id,
        )

        await self._send_welcome(flow["email"], flow["full_name"])
        return {
            "verified": True,
            "message": "Registration completed successfully",
            "user_id": user_id,
            "email": flow["email"],
            "account_type": account_type,
            "organization": organization,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _open_flow(self, token: str) -> dict[str, Any]:
        try:
            flow = open_otp_flow(token)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if flow.get("purpose") != REGISTRATION_PURPOSE:
            raise HTTPException(
                status_code=400, detail="Invalid or expired OTP flow token"
            )
        return flow

    async def _send_otp(self, email: str, otp: str) -> None:
        send_email(
            email,
            "MECWF Registration OTP",
            f"Your OTP is {otp}. It expires in {settings.otp_expire_minutes} minutes.",
        )

    async def _send_welcome(self, email: str, full_name: str) -> None:
        send_email(
            email,
            "Welcome to MECWF",
            f"Welcome {full_name}. Your MECWF account is ready.",
        )


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