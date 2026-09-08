import logging

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.config import settings
from app.emailer import EmailDeliveryError, send_email
from app.schemas import OTPEmailRequest, OTPEmailResponse

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s - %(message)s",
)

logger = logging.getLogger(__name__)

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "Delivers OTP emails for the ECWF authentication module. All "
        "endpoints except /health require the internal service API key as a "
        "Bearer token in the Authorization header."
    ),
)

security = HTTPBearer(auto_error=False)


def require_internal_key(
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
) -> None:
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )
    expected = settings.INTERNAL_API_KEY
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Notification service API key is not configured",
        )
    if credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization scheme",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if credentials.credentials != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "Bearer"},
        )


@app.get("/health", tags=["System"], summary="Health check")
def health() -> dict:
    return {"status": "healthy"}


@app.post(
    "/send-otp",
    response_model=OTPEmailResponse,
    status_code=status.HTTP_200_OK,
    tags=["Notifications"],
    summary="Send an OTP email",
    description=(
        "Validates the internal API key and delivers an OTP email through the "
        "configured SMTP provider. The OTP value itself is never logged. "
        "Requires `Authorization: Bearer <INTERNAL_API_KEY>`."
    ),
    responses={
        200: {"description": "Email accepted for delivery"},
        401: {"description": "Missing or invalid API key"},
        422: {"description": "Invalid request body"},
        502: {"description": "SMTP delivery failed"},
        503: {"description": "Email delivery is not configured"},
    },
)
def send_otp(
    request: OTPEmailRequest,
    _: None = Depends(require_internal_key),
) -> OTPEmailResponse:
    summary = (
        f"ECWF verification code for {request.purpose}"
        if not request.subject
        else request.subject
    )
    try:
        send_email(
            to_email=str(request.email),
            subject=summary,
            body=request.body,
        )
    except EmailDeliveryError as exc:
        logger.warning(
            "OTP email could not be delivered to %s: %s",
            request.email,
            str(exc),
        )
        detail = str(exc)
        code = (
            status.HTTP_503_SERVICE_UNAVAILABLE
            if "configured" in detail.lower()
            else status.HTTP_502_BAD_GATEWAY
        )
        raise HTTPException(status_code=code, detail=detail)

    return OTPEmailResponse(
        message="OTP email accepted for delivery",
        email=str(request.email),
        purpose=request.purpose,
    )