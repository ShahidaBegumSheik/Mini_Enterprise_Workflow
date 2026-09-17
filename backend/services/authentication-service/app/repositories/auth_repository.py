from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.utils import utcnow
from app.models.auth_credential import AuthCredential
from app.models.otp_flow import OTPFlow
from app.models.refresh_session import RefreshSession


class AuthRepository:
    """Data access for authentication-owned state.

    Owns auth_credentials, otp_flows and refresh_sessions. It never
    touches User Service or Tenant Admin Service databases.
    """

    def __init__(self, db: Session) -> None:
        self.db = db

    # ------------------------------------------------------------------
    # Auth credentials
    # ------------------------------------------------------------------

    def credential_by_email(self, email: str) -> AuthCredential | None:
        return self.db.scalar(
            select(AuthCredential).where(AuthCredential.email == email.lower())
        )

    def credential_by_user_id(self, user_id: int) -> AuthCredential | None:
        return self.db.scalar(
            select(AuthCredential).where(AuthCredential.user_id == user_id)
        )

    def create_credential(
        self,
        *,
        user_id: int,
        email: str,
        password_hash: str,
        account_type: str,
        organization_id: int | None = None,
        is_active: bool = True,
        is_verified: bool = True,
    ) -> AuthCredential:
        credential = AuthCredential(
            user_id=user_id,
            email=email.lower(),
            password_hash=password_hash,
            account_type=account_type,
            organization_id=organization_id,
            is_active=is_active,
            is_verified=is_verified,
        )
        self.db.add(credential)
        self.db.commit()
        self.db.refresh(credential)
        return credential

    def update_password(self, credential: AuthCredential, password_hash: str) -> None:
        credential.password_hash = password_hash
        credential.must_change_password = False
        credential.token_version += 1
        self.db.commit()
        self.db.refresh(credential)

    def increment_version(self, credential: AuthCredential) -> None:
        credential.token_version += 1
        self.db.commit()
        self.db.refresh(credential)

    def touch_last_login(self, credential: AuthCredential) -> None:
        credential.last_login_at = utcnow()
        self.db.commit()

    # ------------------------------------------------------------------
    # OTP flows
    # ------------------------------------------------------------------

    def create_otp_flow(
        self,
        *,
        email: str,
        purpose: str,
        code_hash: str,
        context: dict | None,
        expires_at: datetime,
    ) -> OTPFlow:
        flow = OTPFlow(
            email=email.lower(),
            purpose=purpose,
            code_hash=code_hash,
            context=context,
            expires_at=expires_at,
        )
        self.db.add(flow)
        self.db.commit()
        self.db.refresh(flow)
        return flow

    def otp_flow_by_id(self, flow_id: str) -> OTPFlow | None:
        return self.db.get(OTPFlow, flow_id)

    def increment_attempts(self, flow: OTPFlow) -> int:
        flow.attempts = flow.attempts + 1
        self.db.commit()
        self.db.refresh(flow)
        return flow.attempts

    def mark_flow_used(self, flow: OTPFlow) -> None:
        flow.is_used = True
        self.db.commit()
        self.db.refresh(flow)

    def refresh_otp_code(
        self, flow: OTPFlow, *, code_hash: str, expires_minutes: int
    ) -> None:
        flow.code_hash = code_hash
        flow.attempts = 0
        flow.is_used = False
        flow.resend_count = flow.resend_count + 1
        flow.expires_at = utcnow() + timedelta(minutes=expires_minutes)
        self.db.commit()
        self.db.refresh(flow)

    # ------------------------------------------------------------------
    # Refresh sessions
    # ------------------------------------------------------------------

    def create_refresh_session(
        self,
        *,
        user_id: int,
        token_hash: str,
        expires_at: datetime,
        device_info: str | None = None,
        ip_address: str | None = None,
    ) -> RefreshSession:
        session = RefreshSession(
            user_id=user_id,
            token_hash=token_hash,
            expires_at=expires_at,
            device_info=device_info,
            ip_address=ip_address,
        )
        self.db.add(session)
        self.db.commit()
        self.db.refresh(session)
        return session

    def refresh_session_by_hash(self, token_hash: str) -> RefreshSession | None:
        return self.db.scalar(
            select(RefreshSession).where(RefreshSession.token_hash == token_hash)
        )

    def revoke_session(self, session: RefreshSession) -> None:
        session.is_revoked = True
        self.db.commit()
        self.db.refresh(session)

    def rotate_session(
        self,
        session: RefreshSession,
        *,
        token_hash: str,
        expires_at: datetime,
        device_info: str | None = None,
        ip_address: str | None = None,
    ) -> RefreshSession:
        session.is_revoked = True
        self.db.add(session)
        new_session = RefreshSession(
            user_id=session.user_id,
            token_hash=token_hash,
            expires_at=expires_at,
            device_info=device_info,
            ip_address=ip_address,
        )
        self.db.add(new_session)
        self.db.commit()
        self.db.refresh(new_session)
        return new_session

    def revoke_all_user_sessions(self, user_id: int) -> None:
        sessions = self.db.scalars(
            select(RefreshSession).where(RefreshSession.user_id == user_id)
        ).all()
        for session in sessions:
            session.is_revoked = True
        self.db.commit()