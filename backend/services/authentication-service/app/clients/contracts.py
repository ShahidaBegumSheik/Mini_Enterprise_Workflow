from typing import Any, Protocol


class ServiceCallError(Exception):
    """Raised when a downstream service returns an error response."""

    def __init__(
        self,
        service: str,
        status_code: int,
        detail: str | None = None,
    ) -> None:
        self.service = service
        self.status_code = status_code
        self.detail = detail
        message = f"{service} returned {status_code}"
        if detail:
            message = f"{message}: {detail}"
        super().__init__(message)


class ServiceResponseError(Exception):
    """Raised when a downstream service returns an unexpected response."""

    def __init__(self, service: str, detail: str) -> None:
        self.service = service
        self.detail = detail
        super().__init__(f"{service} response error: {detail}")


# ---------------------------------------------------------------------------
# User Service contract
# ---------------------------------------------------------------------------


class UserServiceContract(Protocol):
    """Interface the Authentication Service relies on from the User Service."""

    async def create_user(self, payload: dict[str, Any]) -> dict[str, Any]:
        ...

    async def get_user(self, user_id: int) -> dict[str, Any] | None:
        ...

    async def bootstrap_user(self, user_id: int) -> None:
        ...

    async def sync_user(self, user_id: int, action: str, payload: dict[str, Any]) -> None:
        ...

    async def notify_user(
        self, user_id: int, title: str, message: str, notification_type: str
    ) -> None:
        ...


# ---------------------------------------------------------------------------
# Tenant Admin Service contract
# ---------------------------------------------------------------------------


class TenantAdminServiceContract(Protocol):
    """Interface the Authentication Service relies on from the Tenant Admin Service."""

    async def create_organization(
        self, payload: dict[str, Any], *, access_token: str = ""
    ) -> dict[str, Any]:
        ...

    async def update_organization_profile(
        self, payload: dict[str, Any], *, access_token: str
    ) -> dict[str, Any]:
        ...

    async def update_organization_settings(
        self, payload: dict[str, Any], *, access_token: str
    ) -> dict[str, Any]:
        ...

    async def get_organization_dashboard(self, *, access_token: str) -> dict[str, Any]:
        ...

    async def sync_user(self, user_id: int, action: str, payload: dict[str, Any]) -> None:
        ...


# Event constants used by the Authentication Service for email OTP delivery
NTF_INDIVIDUAL_REGISTRATION_OTP = "individual_registration_otp"
NTF_ORGANIZATION_REGISTRATION_OTP = "organization_registration_otp"
NTF_FORGOT_PASSWORD_OTP = "forgot_password_otp"


class EmailServiceContract(Protocol):
    """Interface the Authentication Service relies on for email delivery."""

    async def send_email_notification(
        self,
        *,
        recipient_email: str,
        event_type: str,
        template_variables: dict[str, Any],
    ) -> None:
        ...
