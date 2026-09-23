import httpx

from app.clients.contracts import ServiceCallError


class FakeUserClient:
    """In-memory User Service client for tests."""

    def __init__(self) -> None:
        self.created: list[dict] = []
        self.fail_mode: str | None = None
        self.returns: dict = {"user_id": 1001}

    async def create_user(self, payload: dict) -> dict:
        self.created.append(payload)
        if self.fail_mode == "connect":
            raise httpx.ConnectError("connection refused to user-service")
        if self.fail_mode == "timeout":
            raise httpx.ReadTimeout("user-service read timeout")
        if self.fail_mode == "invalid":
            return {"unexpected": True}
        if self.fail_mode == "409":
            raise ServiceCallError("user-service", 409, "duplicate email")
        if self.fail_mode == "500":
            raise ServiceCallError("user-service", 500, "boom")
        return dict(self.returns)

    async def get_user(self, user_id: int) -> dict | None:
        if self.fail_mode == "404":
            return None
        return {"user_id": user_id, "email": "alice@gmail.com"}

    async def bootstrap_user(self, user_id: int) -> None:
        return None

    async def sync_user(self, user_id: int, action: str, payload: dict) -> None:
        return None

    async def notify_user(
        self, user_id: int, title: str, message: str, notification_type: str
    ) -> None:
        return None


class FakeTenantClient:
    """In-memory Tenant Admin Service client for tests."""

    def __init__(self) -> None:
        self.created: list[dict] = []
        self.fail_mode: str | None = None
        self.returns: dict = {"organization_id": 5001}

    async def create_organization(
        self, payload: dict, *, access_token: str = ""
    ) -> dict:
        self.created.append(payload)
        if self.fail_mode == "connect":
            raise httpx.ConnectError("connection refused to tenant-admin-service")
        if self.fail_mode == "invalid":
            return {"unexpected": True}
        if self.fail_mode == "409":
            raise ServiceCallError("tenant-admin-service", 409, "duplicate org")
        if self.fail_mode == "500":
            raise ServiceCallError("tenant-admin-service", 500, "boom")
        return dict(self.returns)

    async def update_organization_profile(
        self, payload: dict, *, access_token: str
    ) -> dict:
        return {"ok": True}

    async def update_organization_settings(
        self, payload: dict, *, access_token: str
    ) -> dict:
        return {"ok": True}

    async def get_organization_dashboard(self, *, access_token: str) -> dict:
        return {"organization_id": 5001}

    async def sync_user(self, user_id: int, action: str, payload: dict) -> None:
        return None