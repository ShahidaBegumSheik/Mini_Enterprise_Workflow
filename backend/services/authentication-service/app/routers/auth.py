import secrets

from fastapi import APIRouter, Cookie, Depends, Header, HTTPException, Request, Response, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.clients.tenant_admin_service import TenantAdminServiceClient
from app.clients.user_service import UserServiceClient
from app.core.config import settings
from app.core.cookies import (
    clear_auth_cookies,
    clear_flow_cookie,
    set_auth_cookies,
    set_flow_cookie,
)
from app.database.session import get_db
from app.dependencies.auth import get_current_user
from app.repositories.auth_repository import AuthRepository
from app.schemas.auth import (
    AuthUserInfo,
    ForgotPasswordRequest,
    LoginRequest,
    LoginResponse,
    OTPVerifyRequest,
    RegisterRequest,
    RegistrationVerifiedResponse,
    ResetPasswordRequest,
    TokenContextResponse,
)
from app.schemas.common import MessageResponse
from app.services.auth import AuthService

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])
bearer = HTTPBearer(auto_error=False, scheme_name="BearerAuth")


def service(request: Request, db: Session = Depends(get_db)) -> AuthService:
    return AuthService(
        AuthRepository(db),
        UserServiceClient(request.app.state.http),
        TenantAdminServiceClient(request.app.state.http),
    )


def require_internal_key(
    x_internal_api_key: str = Header(..., alias="X-Internal-API-Key"),
) -> None:
    if not secrets.compare_digest(x_internal_api_key, settings.internal_api_key):
        raise HTTPException(status_code=401, detail="Invalid internal API key")


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


@router.post("/register", response_model=MessageResponse)
async def register(
    data: RegisterRequest,
    response: Response,
    svc: AuthService = Depends(service),
):
    result = await svc.register(data)
    set_flow_cookie(response, settings.registration_otp_cookie_name, result["flow_id"])
    return MessageResponse(
        message="OTP sent successfully. Verify it within five minutes.",
        expires_in=result["expires_in"],
    )


@router.post("/verify-otp", response_model=RegistrationVerifiedResponse)
async def verify_registration(
    data: OTPVerifyRequest,
    response: Response,
    request: Request,
    registration_token: str | None = Cookie(
        default=None, alias=settings.registration_otp_cookie_name
    ),
    svc: AuthService = Depends(service),
):
    if not registration_token:
        raise HTTPException(status_code=401, detail="Registration OTP cookie is missing")
    result = await svc.verify_registration(
        registration_token,
        data.otp,
        client_ip=request.client.host if request.client else None,
    )
    if not result["verified"]:
        error = (
            "Maximum OTP verification attempts exceeded"
            if result["remaining_attempts"] <= 0
            else "Invalid OTP"
        )
        raise HTTPException(
            status_code=400,
            detail=error,
            headers={"x-remaining-attempts": str(result["remaining_attempts"])},
        )
    clear_flow_cookie(response, settings.registration_otp_cookie_name)
    return RegistrationVerifiedResponse(
        message=result["message"],
        user_id=result["user_id"],
        email=result["email"],
        account_type=result["account_type"],
        organization=result.get("organization"),
    )


@router.post("/resend-otp", response_model=MessageResponse)
async def resend_registration(
    response: Response,
    registration_token: str | None = Cookie(
        default=None, alias=settings.registration_otp_cookie_name
    ),
    svc: AuthService = Depends(service),
):
    if not registration_token:
        raise HTTPException(status_code=401, detail="Registration OTP cookie is missing")
    result = await svc.resend_registration_otp(registration_token)
    set_flow_cookie(response, settings.registration_otp_cookie_name, result["flow_id"])
    return MessageResponse(
        message="OTP resent successfully",
        resend_count=result["resend_count"],
        expires_in=result["expires_in"],
    )


# ---------------------------------------------------------------------------
# Login / refresh / logout
# ---------------------------------------------------------------------------


@router.post("/login", response_model=LoginResponse)
async def login(
    data: LoginRequest,
    request: Request,
    response: Response,
    svc: AuthService = Depends(service),
):
    result = await svc.login(
        str(data.email),
        data.password,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    set_auth_cookies(response, result["access_token"], result["refresh_token"])
    return LoginResponse(
        message="Login successful",
        user=AuthUserInfo.model_validate(result["user"]),
    )


@router.post("/refresh-token", response_model=MessageResponse)
@router.post("/refresh", response_model=MessageResponse, include_in_schema=False)
def refresh_token(
    response: Response,
    request: Request,
    refresh_token_value: str | None = Cookie(
        default=None, alias=settings.refresh_cookie_name
    ),
    svc: AuthService = Depends(service),
):
    if not refresh_token_value:
        raise HTTPException(status_code=401, detail="Refresh-token cookie is missing")
    result = svc.refresh(
        refresh_token_value,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    set_auth_cookies(response, result["access_token"], result["refresh_token"])
    return MessageResponse(message="Session refreshed successfully")


@router.post("/logout", response_model=MessageResponse)
def logout(
    response: Response,
    refresh_token_value: str | None = Cookie(
        default=None, alias=settings.refresh_cookie_name
    ),
    svc: AuthService = Depends(service),
):
    svc.logout(refresh_token_value)
    clear_auth_cookies(response)
    return MessageResponse(message="Logged out successfully")


# ---------------------------------------------------------------------------
# Forgot password / reset
# ---------------------------------------------------------------------------


@router.post("/forgot-password", response_model=MessageResponse)
async def forgot_password(
    data: ForgotPasswordRequest,
    response: Response,
    svc: AuthService = Depends(service),
):
    result = await svc.forgot_password(str(data.email))
    if result:
        set_flow_cookie(response, settings.password_reset_otp_cookie_name, result["flow_id"])
    return MessageResponse(message="If the account exists, an OTP has been sent.")


@router.post("/verify-forgot-otp", response_model=MessageResponse)
@router.post("/verify-reset-otp", response_model=MessageResponse, include_in_schema=False)
def verify_forgot_otp(
    data: OTPVerifyRequest,
    response: Response,
    reset_token: str | None = Cookie(
        default=None, alias=settings.password_reset_otp_cookie_name
    ),
    svc: AuthService = Depends(service),
):
    if not reset_token:
        raise HTTPException(status_code=401, detail="Password-reset OTP cookie is missing")
    result = svc.verify_reset_otp(reset_token, data.otp)
    if not result["verified"]:
        raise HTTPException(
            status_code=400,
            detail="Invalid OTP",
            headers={"x-remaining-attempts": str(result["remaining_attempts"])},
        )
    clear_flow_cookie(response, settings.password_reset_otp_cookie_name)
    set_flow_cookie(
        response, settings.password_reset_verified_cookie_name, result["verified_token"]
    )
    return MessageResponse(
        message="Password-reset OTP verified successfully",
        expires_in=result["expires_in"],
    )


@router.post("/resend-forgot-otp", response_model=MessageResponse)
async def resend_forgot_otp(
    response: Response,
    reset_token: str | None = Cookie(
        default=None, alias=settings.password_reset_otp_cookie_name
    ),
    svc: AuthService = Depends(service),
):
    if not reset_token:
        raise HTTPException(status_code=401, detail="Password-reset OTP cookie is missing")
    result = await svc.resend_password_reset_otp(reset_token)
    set_flow_cookie(response, settings.password_reset_otp_cookie_name, result["flow_id"])
    return MessageResponse(
        message="Password-reset OTP resent successfully",
        resend_count=result["resend_count"],
        expires_in=result["expires_in"],
    )


@router.post("/reset-password", response_model=MessageResponse)
def reset_password(
    data: ResetPasswordRequest,
    response: Response,
    verified_token: str | None = Cookie(
        default=None, alias=settings.password_reset_verified_cookie_name
    ),
    svc: AuthService = Depends(service),
):
    if not verified_token:
        raise HTTPException(
            status_code=401, detail="Verified password-reset cookie is missing"
        )
    svc.reset_password(verified_token, data.new_password)
    clear_flow_cookie(response, settings.password_reset_verified_cookie_name)
    clear_auth_cookies(response)
    return MessageResponse(message="Password updated successfully")


# ---------------------------------------------------------------------------
# Authenticated session context
# ---------------------------------------------------------------------------


@router.get("/me", response_model=TokenContextResponse)
def me(credential=Depends(get_current_user)):
    return TokenContextResponse(
        user_id=credential.user_id,
        email=credential.email,
        account_type=credential.account_type,
        organization_id=credential.organization_id,
        token_version=credential.token_version,
        is_active=credential.is_active,
        is_verified=credential.is_verified,
    )


# ---------------------------------------------------------------------------
# Internal endpoints used by other microservices
# ---------------------------------------------------------------------------


@router.post(
    "/internal/validate-token",
    dependencies=[Depends(require_internal_key)],
    include_in_schema=False,
)
@router.post(
    "/internal/token/context",
    dependencies=[Depends(require_internal_key)],
    include_in_schema=False,
)
def token_context(
    credentials: HTTPAuthorizationCredentials | None = Security(bearer),
    svc: AuthService = Depends(service),
):
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=401,
            detail="Bearer access token is required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    credential = svc.validate_access(credentials.credentials)
    return _credential_dict(credential)


@router.get(
    "/internal/credentials/by-email",
    dependencies=[Depends(require_internal_key)],
    include_in_schema=False,
)
def internal_credential_by_email(
    email: str, db: Session = Depends(get_db)
):
    credential = AuthRepository(db).credential_by_email(email)
    if not credential:
        raise HTTPException(status_code=404, detail="Credentials not found")
    return _credential_dict(credential)


@router.get(
    "/internal/credentials/by-user-id",
    dependencies=[Depends(require_internal_key)],
    include_in_schema=False,
)
def internal_credential_by_user_id(
    user_id: int, db: Session = Depends(get_db)
):
    credential = AuthRepository(db).credential_by_user_id(user_id)
    if not credential:
        raise HTTPException(status_code=404, detail="Credentials not found")
    return _credential_dict(credential)


def _credential_dict(credential) -> dict:
    return {
        "user_id": credential.user_id,
        "email": credential.email,
        "account_type": credential.account_type,
        "organization_id": credential.organization_id,
        "is_active": credential.is_active,
        "is_verified": credential.is_verified,
        "must_change_password": credential.must_change_password,
        "token_version": credential.token_version,
        "last_login_at": credential.last_login_at,
        "created_at": credential.created_at,
    }