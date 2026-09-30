from typing import Any, Protocol


class ServiceCallError(Exception):
    """Raised when a downstream microservice returns a non-2xx response."""

    def __init__(self, service: str, status_code: int, detail: str = "") -> None:
        self.service = service
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"{service} returned {status_code}: {detail}")


class ServiceResponseError(Exception):
    """Raised when a downstream microservice returns a malformed/invalid body."""

    def __init__(self, service: str, detail: str = "") -> None:
        self.service = service
        self.detail = detail
        super().__init__(f"{service} returned an invalid response: {detail}")


# ---------------------------------------------------------------------------
# User Service contract
# ---------------------------------------------------------------------------


class UserServiceContract(Protocol):
    """Interface the Authentication Service relies on from the User Service.

    The User Service owns user profile / user records. The endpoints below
    are the internal HTTP contract that the User Service team must expose:

    - POST   /api/v1/internal/users            create a user profile (returns user_id)
    - GET    /api/v1/internal/users/{id}       fetch a user profile
    - POST   /api/v1/internal/users/{id}/bootstrap
    - POST   /api/v1/internal/sync/users/{id}  receive user sync events (best effort)
    - POST   /api/v1/internal/users/{id}/notifications
    """

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
    """Interface the Authentication Service relies on from the Tenant Admin Service.

    The Tenant Admin Service owns tenant / organization records. Endpoints:

    - POST   /api/v1/internal/organizations                     create organization
    - PUT    /api/v1/organizations/profile                      update org profile
    - PUT    /api/v1/organizations/settings                     update org settings
    - GET    /api/v1/dashboard/organization                     org dashboard
    - POST   /api/v1/internal/sync/users/{id}                   receive user sync events
    """

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


# ---------------------------------------------------------------------------
# Notification Service contract
# ---------------------------------------------------------------------------

# Event constants used by the Authentication Service. They are the contract
# with the Notification Service's templated email events; raw OTP values travel
# inside ``template_variables`` and are never logged or persisted.
NTF_INDIVIDUAL_REGISTRATION_OTP = "individual_registration_otp"
NTF_ORGANIZATION_REGISTRATION_OTP = "organization_registration_otp"
NTF_FORGOT_PASSWORD_OTP = "forgot_password_otp"


class NotificationServiceContract(Protocol):
    """Interface the Authentication Service relies on from the Notification Service.

    The Authentication Service never implements notification business logic
    itself; it only asks the Notification Service to render + deliver a
    templated email for a given event. The request is strictly:

    - POST  /api/v1/internal/notifications
      {"recipient_email": str, "event_type": str, "template_variables": dict}

    Never send passwords, JWT tokens or any secrets in the payload — only the
    recipient address, the event type, and the variables the template needs
    (e.g. the OTP and its expiry). The Authentication Service has its own DB
    and never reads the Notification Service's data.
    """

    async def send_email_notification(
        self,
        *,
        recipient_email: str,
        event_type: str,
        template_variables: dict[str, Any],
    ) -> None:
        ...