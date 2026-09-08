from sqlalchemy.orm import Session

from app.models.tenant import Tenant


class TenantAdminService:
    """Tenant Admin Service: organization/tenant creation and management."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def create_tenant(
        self,
        name: str,
        activate: bool = True,
        commit: bool = True,
    ) -> Tenant:
        tenant = Tenant(name=name, is_active=activate)
        self.db.add(tenant)
        if commit:
            self.db.commit()
            self.db.refresh(tenant)
        return tenant

    def get_tenant_by_name(self, name: str) -> Tenant | None:
        return (
            self.db.query(Tenant)
            .filter(Tenant.name == name)
            .first()
        )

    def deactivate_tenant(self, tenant_id: int) -> None:
        tenant = self.db.get(Tenant, tenant_id)
        if tenant:
            tenant.is_active = False
            self.db.commit()
