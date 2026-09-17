from datetime import timedelta
from typing import Any

import httpx
from fastapi import HTTPException

from app.clients.contracts import ServiceCallError
from app.clients.tenant_admin_service import TenantAdminServiceClient
from app.clients.user_service import UserServiceClient
from app.core.config import settings
from app.core.security import (
    create_access_token,
    create_password_reset_verified_token,
    create_refresh_token,
    decode_token,
    generate_otp,
    hash_otp,
    hash_password,
    hash_token,
    verify_otp,
    verify_password,
)
from app.core.utils import utcnow
from app.models.auth_credential import AuthCredential
from app.models.otp_flow import OTPFlow
from app.repositories.auth_repository import AuthRepository
from app.services.email import send_email

REGISTRATION_PURPOSE = "registration"
PASSWORD_RESET_PURPOSE = "password_reset"


class AuthService:
    """Business logic for the Authentication Service."""

    def __init__(
        self,
        repo: AuthRepository,
        users: UserServiceClient,
        tenants: TenantAdminServiceClient,
    ) -> None:
        self.repo = repo
        self.users = users
        self.tenants = tenants

    # ------------------------------------------------------------------
    # Registration flow
    # ------------------------------------------------------------------

    async def register(self, data) -> dict[str, Any]:
        email = str(data.email).lower()
        if self.repo.credential_by_email(email):
            raise HTTPException(status_code=409, detail="Email is already registered")

        code = generate_otp()
        flow = self.repo.create_otp_flow(
            email=email,
            purpose=REGISTRATION_PURPOSE,
            code_hash=hash_otp(code),
            context={
                "full_name": data.full_name,
                "account_type": data.account_type,
                "password_hash": hash_password(data.password),
                "organization_name": data.organization_name,
                "organization_type": data.organization_type,
                "industry": data.industry,
            },
            expires_at=utcnow() + timedelta(minutes=settings.otp_expire_minutes),
        )
        await self._send_otp(email, code, REGISTRATION_PURPOSE)
        return {
            "flow_id": flow.id,
            "expires_in": settings.otp_expire_minutes * 60,
        }

    async def resend_registration_otp(self, flow_id: str) -> dict[str, Any]:
        return await self._resend_otp(flow_id, REGISTRATION_PURPOSE)

    async def verify_registration(
        self, flow_id: str, submitted_otp: str, *, client_ip: str | None = None
    ) -> dict[str, Any]:
        flow = self._check_flow(flow_id, REGISTRATION_PURPOSE)

        if not verify_otp(submitted_otp, flow.code_hash):
            remaining = self._consume_attempt(flow)
            return {"verified": False, "remaining_attempts": remaining}

        context = flow.context or {}
        if self.repo.credential_by_email(flow.email):
            raise HTTPException(status_code=409, detail="Email is already registered")

        try:
            # The User Service owns user records; we only create a credential.
            user_profile = await self.users.create_user(
                {
                    "email": flow.email,
                    "full_name": context.get("full_name"),
                    "account_type": context.get("account_type"),
                }
            )
            user_id = int(
                user_profile.get("user_id") or user_profile.get("id")
            )
            account_type = str(context.get("account_type", "individual"))
            organization_id: int | None = None
            organization: dict[str, Any] | None = None

            if account_type == "organization":
                access_token = create_access_token(user_id, 0)
                organization_payload = {
                    "name": context.get("organization_name"),
                    "organization_type": context.get("organization_type")
                    or "enterprise",
                    "industry": context.get("industry"),
                }
                organization = await self.tenants.create_organization(
                    organization_payload, access_token=access_token
                )
                organization_id = int(
                    organization.get("tenant_id") or organization.get("id")
                )

            self.repo.create_credential(
                user_id=user_id,
                email=flow.email,
                password_hash=context["password_hash"],
                account_type=account_type,
                organization_id=organization_id,
            )
            self.repo.mark_flow_used(flow)
        except ServiceCallError as exc:
            raise HTTPException(
                status_code=502,
                detail=f"{exc.service} unavailable during registration: {exc.detail}",
            ) from exc
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=502,
                detail="Unable to complete registration at this time",
            ) from exc

        await self._send_welcome(flow.email, context.get("full_name", flow.email))
        return {
            "verified": True,
            "message": "Registration completed successfully",
            "user_id": user_id,
            "email": flow.email,
            "account_type": account_type,
            "organization": organization,
        }

    # ------------------------------------------------------------------
    # Login / refresh / logout
    # ------------------------------------------------------------------

    async def login(
        self,
        email: str,
        password: str,
        *,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> dict[str, Any]:
        credential = self.repo.credential_by_email(email)
        if not credential or not verify_password(password, credential.password_hash):
            raise HTTPException(status_code=401, detail="Invalid email or password")
        if not credential.is_active or not credential.is_verified:
            raise HTTPException(status_code=403, detail="Account is inactive or not verified")

        self.repo.touch_last_login(credential)

        refresh = create_refresh_token(credential.user_id, credential.token_version)
        self.repo.create_refresh_session(
            user_id=credential.user_id,
            token_hash=hash_token(refresh),
            expires_at=utcnow() + timedelta(days=settings.refresh_token_expire_days),
            device_info=user_agent,
            ip_address=ip_address,
        )
        return {
            "access_token": create_access_token(
                credential.user_id, credential.token_version
            ),
            "refresh_token": refresh,
            "user": await self._user_context(credential),
        }

    def refresh(
        self,
        refresh_token: str,
        *,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> dict[str, Any]:
        try:
            payload = decode_token(refresh_token)
        except ValueError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc

        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid refresh token")

        credential = self.repo.credential_by_user_id(int(payload["sub"]))
        if (
            not credential
            or not credential.is_active
            or credential.token_version != int(payload.get("ver", -1))
        ):
            raise HTTPException(status_code=401, detail="Refresh token is invalid or revoked")

        session = self.repo.refresh_session_by_hash(hash_token(refresh_token))
        if not session or session.is_revoked or session.expires_at <= utcnow():
            raise HTTPException(status_code=401, detail="Refresh token has been revoked or expired")

        new_refresh = create_refresh_token(credential.user_id, credential.token_version)
        self.repo.rotate_session(
            session,
            token_hash=hash_token(new_refresh),
            expires_at=utcnow() + timedelta(days=settings.refresh_token_expire_days),
            ip_address=ip_address,
            device_info=user_agent,
        )
        return {
            "access_token": create_access_token(
                credential.user_id, credential.token_version
            ),
            "refresh_token": new_refresh,
        }

    def logout(self, refresh_token: str | None) -> None:
        if not refresh_token:
            return
        try:
            payload = decode_token(refresh_token)
            credential = self.repo.credential_by_user_id(int(payload["sub"]))
        except (ValueError, KeyError, TypeError):
            return
        session = self.repo.refresh_session_by_hash(hash_token(refresh_token))
        if session and payload.get("type") == "refresh":
            self.repo.revoke_session(session)
        if credential:
            # Invalidate previously issued access + refresh tokens immediately.
            self.repo.increment_version(credential)
            self.repo.revoke_all_user_sessions(credential.user_id)

    # ------------------------------------------------------------------
    # Forgot password / reset
    # ------------------------------------------------------------------

    async def forgot_password(self, email: str) -> dict[str, Any] | None:
        email = email.lower()
        credential = self.repo.credential_by_email(email)
        if not credential:
            return None

        code = generate_otp()
        flow = self.repo.create_otp_flow(
            email=email,
            purpose=PASSWORD_RESET_PURPOSE,
            code_hash=hash_otp(code),
            context={"user_id": credential.user_id},
            expires_at=utcnow() + timedelta(minutes=settings.otp_expire_minutes),
        )
        await self._send_otp(email, code, PASSWORD_RESET_PURPOSE)
        return {
            "flow_id": flow.id,
            "expires_in": settings.otp_expire_minutes * 60,
        }

    async def resend_password_reset_otp(self, flow_id: str) -> dict[str, Any]:
        return await self._resend_otp(flow_id, PASSWORD_RESET_PURPOSE)

    def verify_reset_otp(self, flow_id: str, submitted_otp: str) -> dict[str, Any]:
        flow = self._check_flow(flow_id, PASSWORD_RESET_PURPOSE)

        if not verify_otp(submitted_otp, flow.code_hash):
            remaining = self._consume_attempt(flow)
            return {"verified": False, "remaining_attempts": remaining}

        user_id = int((flow.context or {}).get("user_id"))
        self.repo.mark_flow_used(flow)
        return {
            "verified": True,
            "verified_token": create_password_reset_verified_token(user_id, flow_id),
            "expires_in": settings.otp_expire_minutes * 60,
        }

    def reset_password(self, verified_token: str, new_password: str) -> None:
        try:
            payload = decode_token(verified_token)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        if payload.get("type") != "password_reset_verified":
            raise HTTPException(status_code=400, detail="Invalid password reset flow token")

        credential = self.repo.credential_by_user_id(int(payload["sub"]))
        if not credential:
            raise HTTPException(status_code=404, detail="Account not found")
        if verify_password(new_password, credential.password_hash):
            raise HTTPException(
                status_code=400, detail="New password cannot be the current password"
            )

        self.repo.update_password(credential, hash_password(new_password))
        self.repo.revoke_all_user_sessions(credential.user_id)

    # ------------------------------------------------------------------
    # Session / token validation
    # ------------------------------------------------------------------

    def validate_access(self, token: str) -> AuthCredential:
        try:
            payload = decode_token(token)
        except ValueError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc

        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid access token")

        credential = self.repo.credential_by_user_id(int(payload["sub"]))
        if (
            not credential
            or not credential.is_active
            or credential.token_version != int(payload.get("ver", -1))
        ):
            raise HTTPException(status_code=401, detail="Token is invalid or revoked")
        return credential

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _resend_otp(self, flow_id: str, purpose: str) -> dict[str, Any]:
        flow = self.repo.otp_flow_by_id(flow_id)
        if not flow or flow.purpose != purpose:
            raise HTTPException(status_code=400, detail="Invalid or expired OTP flow")
        if flow.resend_count >= settings.otp_max_resends:
            raise HTTPException(
                status_code=429, detail="Maximum OTP resend limit exceeded"
            )

        code = generate_otp()
        self.repo.refresh_otp_code(
            flow,
            code_hash=hash_otp(code),
            expires_minutes=settings.otp_expire_minutes,
        )
        await self._send_otp(flow.email, code, purpose)
        return {
            "flow_id": flow.id,
            "resend_count": flow.resend_count,
            "expires_in": settings.otp_expire_minutes * 60,
        }

    def _check_flow(self, flow_id: str, purpose: str) -> OTPFlow:
        flow = self.repo.otp_flow_by_id(flow_id)
        if not flow or flow.purpose != purpose:
            raise HTTPException(status_code=400, detail="Invalid or expired OTP flow")
        if flow.is_used:
            raise HTTPException(status_code=400, detail="OTP has already been used")
        if flow.expires_at <= utcnow():
            raise HTTPException(status_code=400, detail="OTP has expired")
        if flow.attempts >= settings.otp_max_attempts:
            raise HTTPException(
                status_code=429, detail="Maximum OTP verification attempts exceeded"
            )
        return flow

    def _consume_attempt(self, flow: OTPFlow) -> int:
        attempts = self.repo.increment_attempts(flow)
        remaining = max(settings.otp_max_attempts - attempts, 0)
        return remaining

    async def _user_context(self, credential: AuthCredential) -> dict[str, Any]:
        base = {
            "user_id": credential.user_id,
            "email": credential.email,
            "account_type": credential.account_type,
            "organization_id": credential.organization_id,
            "is_active": credential.is_active,
            "is_verified": credential.is_verified,
            "created_at": credential.created_at.isoformat()
            if credential.created_at
            else None,
        }
        if not settings.enable_external_services:
            return base
        try:
            profile = await self.users.get_user(credential.user_id)
        except (ServiceCallError, httpx.HTTPError):
            return base
        if profile:
            return {**base, **profile}
        return base

    async def _send_otp(self, email: str, otp: str, purpose: str) -> None:
        send_email(
            email,
            f"MECWF {purpose.replace('_', ' ').title()} OTP",
            f"Your OTP is {otp}. It expires in {settings.otp_expire_minutes} minutes.",
        )

    async def _send_welcome(self, email: str, full_name: str) -> None:
        send_email(
            email,
            "Welcome to MECWF",
            f"Welcome {full_name}. Your MECWF account is ready.",
        )