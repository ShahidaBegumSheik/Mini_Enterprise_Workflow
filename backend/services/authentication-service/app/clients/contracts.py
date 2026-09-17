from typing import Any, Protocol


class ServiceCallError(Exception):
    """Raised when a downstream microservice returns a non-2xx response."""

    def __init__(self, service: str, status_code: int, detail: str = "") -> None:
        self.service = service
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"{service} returned {status_code}: {detail}")


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
        self, payload: dict[str, Any], *, access_token: str
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