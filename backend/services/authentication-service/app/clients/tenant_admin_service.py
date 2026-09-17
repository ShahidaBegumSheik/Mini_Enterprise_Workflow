from typing import Any

import httpx

from app.clients.contracts import ServiceCallError, TenantAdminServiceContract
from app.core.config import settings


class TenantAdminServiceClient(TenantAdminServiceContract):
    """HTTPX-based implementation of the Tenant Admin Service contract."""

    def __init__(
        self,
        http: httpx.AsyncClient,
        base_url: str | None = None,
        internal_api_key: str | None = None,
    ) -> None:
        self.http = http
        self.base_url = (base_url or settings.tenant_admin_service_url).rstrip("/")
        self.internal_api_key = internal_api_key or settings.internal_api_key

    def _headers(self, access_token: str = "") -> dict[str, str]:
        headers = {"X-Internal-API-Key": self.internal_api_key}
        if access_token:
            headers["Authorization"] = f"Bearer {access_token}"
        return headers

    def _raise_for(self, response: httpx.Response) -> None:
        if response.status_code >= 400:
            raise ServiceCallError(
                service="tenant-admin-service",
                status_code=response.status_code,
                detail=response.text,
            )

    async def create_organization(
        self, payload: dict[str, Any], *, access_token: str
    ) -> dict[str, Any]:
        response = await self.http.post(
            f"{self.base_url}/api/v1/internal/organizations",
            headers=self._headers(access_token),
            json=payload,
        )
        self._raise_for(response)
        return response.json()

    async def update_organization_profile(
        self, payload: dict[str, Any], *, access_token: str
    ) -> dict[str, Any]:
        response = await self.http.put(
            f"{self.base_url}/api/v1/organizations/profile",
            headers=self._headers(access_token),
            json=payload,
        )
        self._raise_for(response)
        return response.json()

    async def update_organization_settings(
        self, payload: dict[str, Any], *, access_token: str
    ) -> dict[str, Any]:
        response = await self.http.put(
            f"{self.base_url}/api/v1/organizations/settings",
            headers=self._headers(access_token),
            json=payload,
        )
        self._raise_for(response)
        return response.json()

    async def get_organization_dashboard(
        self, *, access_token: str
    ) -> dict[str, Any]:
        response = await self.http.get(
            f"{self.base_url}/api/v1/dashboard/organization",
            headers=self._headers(access_token),
        )
        self._raise_for(response)
        return response.json()

    async def sync_user(
        self, user_id: int, action: str, payload: dict[str, Any]
    ) -> None:
        try:
            response = await self.http.post(
                f"{self.base_url}/api/v1/internal/sync/users/{user_id}",
                headers=self._headers(),
                json={**payload, "action": action},
            )
            self._raise_for(response)
        except (httpx.HTTPError, ServiceCallError):
            pass