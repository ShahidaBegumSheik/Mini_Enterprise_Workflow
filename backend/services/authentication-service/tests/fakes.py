from app.clients.contracts import ServiceCallError


class FakeUserClient:
    """In-memory fake of the User Service contract."""

    def __init__(self):
        self.users = {}
        self.next_id = 1
        self.fail_create = False
        self.create_calls = []

    async def create_user(self, payload):
        self.create_calls.append(payload)
        if self.fail_create:
            raise ServiceCallError("user-service", 500, "user service down")
        user_id = self.next_id
        self.next_id += 1
        profile = {**payload, "user_id": user_id, "is_active": True}
        self.users[user_id] = profile
        return profile

    async def get_user(self, user_id):
        return self.users.get(user_id)

    async def bootstrap_user(self, user_id):
        return None

    async def sync_user(self, user_id, action, payload):
        return None

    async def notify_user(self, user_id, title, message, notification_type):
        return None


class FakeTenantClient:
    """In-memory fake of the Tenant Admin Service contract."""

    def __init__(self):
        self.next_id = 1
        self.fail_create = False
        self.create_calls = []

    async def create_organization(self, payload, *, access_token):
        self.create_calls.append(payload)
        if self.fail_create:
            raise ServiceCallError("tenant-admin-service", 500, "tenant down")
        org_id = self.next_id
        self.next_id += 1
        return {"tenant_id": org_id, **payload}

    async def update_organization_profile(self, payload, *, access_token):
        return {"ok": True}

    async def update_organization_settings(self, payload, *, access_token):
        return {"ok": True}

    async def get_organization_dashboard(self, *, access_token):
        return {"ok": True}

    async def sync_user(self, user_id, action, payload):
        return None