from fastapi import HTTPException, Response, status
from jose import JWTError
from sqlalchemy.orm import Session

from app.core.security import (
    create_access_token,
    create_otp_token,
    decode_token,
    verify_password,
)
from app.schemas.auth import (
    IndividualRegisterRequest,
    LoginRequest,
    OrganizationRegisterRequest,
    VerifyAccountRequest,
)
from app.services.otp_service import (
    RESET_PURPOSE,
    REGISTRATION_PURPOSE,
    create_otp,
    get_active_otp,
    get_otp_by_token_context,
    resend_otp,
    verify_otp as verify_otp_code,
)
from app.services.token_service import (
    get_stored_token_by_jti,
    issue_refresh_token,
    revoke_token,
    rotate_refresh_token,
    validate_refresh_token,
)
from app.services.user_service import UserService


def _otp_context(purpose: str, email: str, **extra) -> dict:
    return {"type": "otp", "purpose": purpose, "email": email, **extra}


def _validate_otp_token_cookie(cookie_value: str | None) -> dict:
    if not cookie_value:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="OTP token missing. Please start the request again",
        )
    try:
        payload = decode_token(cookie_value)
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid OTP token",
        )
    if payload.get("type") != "otp":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid OTP token",
        )
    return payload


class AuthenticationService:
    """Authentication Service: registration, OTP, login, tokens and recovery."""

    def __init__(self, db: Session) -> None:
        self.db = db
        self.users = UserService(db)

    # ---------- Registration (initiate) ----------

    def initiate_registration(
        self,
        payload: IndividualRegisterRequest | OrganizationRegisterRequest,
    ) -> dict:
        email = str(payload.email).lower()

        if self.users.email_exists(email):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="An account with this email already exists",
            )

        if get_active_otp(self.db, email, REGISTRATION_PURPOSE) is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "An OTP verification is already pending for this email. "
                    "Use /auth/resend-otp to request a new code"
                ),
            )

        return _otp_context(
            REGISTRATION_PURPOSE,
            email,
            account_type=payload.account_type,
        )

    def generate_registration_otp(
        self,
        context: dict,
        response: Response,
    ) -> dict:
        token = create_otp_token(context)
        self._set_otp_cookie(response, token)
        create_otp(
            db=self.db,
            email=context["email"],
            purpose=REGISTRATION_PURPOSE,
        )
        return context

    def complete_registration(
        self,
        context: dict,
        payload: VerifyAccountRequest,
        response: Response,
    ) -> dict:
        if context.get("purpose") != REGISTRATION_PURPOSE:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid OTP token purpose",
            )

        email = context.get("email")
        context_account_type = context.get("account_type")

        if str(payload.email).lower() != email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email does not match the OTP request",
            )
        if payload.account_type != context_account_type:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Account type does not match the OTP request",
            )

        otp_record = get_otp_by_token_context(
            self.db, email, REGISTRATION_PURPOSE
        )
        if otp_record is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No pending OTP for this account",
            )

        verify_otp_code(self.db, otp_record, payload.otp)

        if payload.account_type == "individual":
            user = self.users.create_individual_user(
                full_name=payload.full_name,
                email=email,
                password=payload.password,
            )
            tenant_id = None
        else:
            user = self.users.create_tenant_admin_user(
                full_name=payload.full_name,
                email=email,
                password=payload.password,
                organization_name=payload.organization_name,
            )
            tenant_id = user.tenant_id

        self._issue_session_cookies(user.id, response)

        return {
            "message": "Account verified and created successfully",
            "user": user,
            "tenant_id": tenant_id,
        }

    def resend_registration_otp(self, context: dict, response: Response) -> dict:
        resend_otp(
            db=self.db,
            email=context["email"],
            purpose=REGISTRATION_PURPOSE,
        )
        token = create_otp_token(context)
        self._set_otp_cookie(response, token)
        return {"email": context["email"]}

    # ---------- Login ----------

    def login(
        self,
        payload: LoginRequest,
        response: Response,
    ) -> dict:
        email = str(payload.email).lower()
        user = self.users.get_by_email(email)
        if not user or not verify_password(payload.password, user.password_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password",
            )

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account is not active",
            )

        self._issue_session_cookies(user.id, response)
        return {"user": user}

    # ---------- Forgot / reset password ----------

    def initiate_forgot_password(self, email: str, response: Response) -> dict:
        email = email.lower()
        user = self.users.get_by_email(email)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No account found with this email",
            )

        context = _otp_context(RESET_PURPOSE, email)
        token = create_otp_token(context)
        self._set_otp_cookie(response, token)
        create_otp(
            db=self.db,
            email=email,
            purpose=RESET_PURPOSE,
        )
        return {"email": email}

    def verify_forgot_password_otp(
        self,
        context: dict,
        otp: str,
    ) -> dict:
        if context.get("purpose") != RESET_PURPOSE:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid OTP token purpose",
            )

        email = context.get("email")
        otp_record = get_otp_by_token_context(self.db, email, RESET_PURPOSE)
        if otp_record is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No pending OTP for this account",
            )

        verify_otp_code(self.db, otp_record, otp)
        return {"email": email}

    def reset_password(
        self,
        context: dict,
        new_password: str,
    ) -> None:
        if context.get("purpose") != RESET_PURPOSE:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid OTP token purpose",
            )

        email = context.get("email")
        otp_record = get_otp_by_token_context(self.db, email, RESET_PURPOSE)
        if otp_record is None or not otp_record.is_verified:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="OTP must be verified before resetting password",
            )

        user = self.users.get_by_email(email)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No account found with this email",
            )

        self.users.set_password(user, new_password)

    # ---------- Refresh & logout ----------

    def rotate_refresh(
        self,
        refresh_token: str,
        response: Response,
    ) -> str:
        record = validate_refresh_token(self.db, refresh_token)
        new_access = create_access_token({"sub": str(record.user_id)})
        new_refresh = rotate_refresh_token(
            self.db, refresh_token, record.user_id
        )
        self._set_auth_cookies(response, new_access, new_refresh)
        return new_access

    def logout(self, refresh_token: str | None) -> None:
        if not refresh_token:
            return
        try:
            payload = decode_token(refresh_token)
        except JWTError:
            return
        if payload.get("type") != "refresh":
            return
        jti = payload.get("jti")
        if not jti:
            return
        record = get_stored_token_by_jti(self.db, jti)
        if record is None:
            return
        revoke_token(self.db, record)

    # ---------- helpers ----------

    def _issue_session_cookies(self, user_id: int, response: Response) -> None:
        access_token = create_access_token({"sub": str(user_id)})
        refresh_token = issue_refresh_token(self.db, user_id)
        self._set_auth_cookies(response, access_token, refresh_token)

    def _set_auth_cookies(
        self,
        response: Response,
        access_token: str,
        refresh_token: str,
    ) -> None:
        from app.core.cookies import (
            set_access_token_cookie,
            set_refresh_token_cookie,
        )

        set_access_token_cookie(response, access_token)
        set_refresh_token_cookie(response, refresh_token)

    def _set_otp_cookie(self, response: Response, token: str) -> None:
        from app.core.cookies import set_otp_token_cookie

        set_otp_token_cookie(response, token)
