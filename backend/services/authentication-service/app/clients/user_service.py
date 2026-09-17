from typing import Any

import httpx

from app.clients.contracts import ServiceCallError, UserServiceContract
from app.core.config import settings


class UserServiceClient(UserServiceContract):
    """HTTPX-based implementation of the User Service contract."""

    def __init__(
        self,
        http: httpx.AsyncClient,
        base_url: str | None = None,
        internal_api_key: str | None = None,
    ) -> None:
        self.http = http
        self.base_url = (base_url or settings.user_service_url).rstrip("/")
        self.internal_api_key = internal_api_key or settings.internal_api_key

    def _headers(self) -> dict[str, str]:
        return {"X-Internal-API-Key": self.internal_api_key}

    def _raise_for(self, response: httpx.Response) -> None:
        if response.status_code >= 400:
            raise ServiceCallError(
                service="user-service",
                status_code=response.status_code,
                detail=response.text,
            )

    async def create_user(self, payload: dict[str, Any]) -> dict[str, Any]:
        response = await self.http.post(
            f"{self.base_url}/api/v1/internal/users",
            headers=self._headers(),
            json=payload,
        )
        self._raise_for(response)
        return response.json()

    async def get_user(self, user_id: int) -> dict[str, Any] | None:
        response = await self.http.get(
            f"{self.base_url}/api/v1/internal/users/{user_id}",
            headers=self._headers(),
        )
        if response.status_code == 404:
            return None
        self._raise_for(response)
        return response.json()

    async def bootstrap_user(self, user_id: int) -> None:
        response = await self.http.post(
            f"{self.base_url}/api/v1/internal/users/{user_id}/bootstrap",
            headers=self._headers(),
        )
        self._raise_for(response)

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
            # Best effort: sync failures never fail the caller's operation.
            pass

    async def notify_user(
        self, user_id: int, title: str, message: str, notification_type: str
    ) -> None:
        try:
            response = await self.http.post(
                f"{self.base_url}/api/v1/internal/users/{user_id}/notifications",
                headers=self._headers(),
                json={
                    "title": title,
                    "message": message,
                    "notification_type": notification_type,
                },
            )
            self._raise_for(response)
        except (httpx.HTTPError, ServiceCallError):
            pass