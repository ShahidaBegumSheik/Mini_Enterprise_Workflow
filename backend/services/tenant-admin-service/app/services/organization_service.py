import re

from fastapi import HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.organization import Organization
from app.repositories.organization_repository import OrganizationRepository
from app.schemas.organization import (
    OrganizationCreate,
    OrganizationSettingsUpdate,
    OrganizationUpdate,
)


class OrganizationService:
    def __init__(self, db: Session) -> None:
        self.repository = OrganizationRepository(db)

    @staticmethod
    def _slugify(value: str) -> str:
        value = value.strip().lower()
        value = re.sub(r"[^a-z0-9]+", "-", value)
        value = value.strip("-")

        return value or "organization"

    def _generate_unique_slug(self, name: str) -> str:
        base_slug = self._slugify(name)
        slug = base_slug
        counter = 2

        while self.repository.get_by_slug(slug):
            slug = f"{base_slug}-{counter}"
            counter += 1

        return slug

    def create_organization(
        self,
        data: OrganizationCreate,
    ) -> Organization:
        if data.slug:
            slug = self._slugify(data.slug)

            if self.repository.get_by_slug(slug):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Organization slug already exists",
                )
        else:
            slug = self._generate_unique_slug(data.name)

        organization = Organization(
            name=data.name,
            slug=slug,
            organization_type=data.organization_type,
            industry=data.industry,
            description=data.description,
            email=data.email,
            phone=data.phone,
            website=str(data.website) if data.website else None,
            address=data.address,
            logo_url=str(data.logo_url) if data.logo_url else None,
            timezone=data.timezone,
        )

        try:
            return self.repository.create(organization)

        except IntegrityError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Organization already exists",
            ) from exc

    def get_organization(
        self,
        organization_id: int,
    ) -> Organization:
        organization = self.repository.get_by_id(organization_id)

        if organization is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Organization not found",
            )

        return organization

    def update_profile(
        self,
        organization_id: int,
        data: OrganizationUpdate,
    ) -> Organization:
        organization = self.get_organization(organization_id)

        updates = data.model_dump(exclude_unset=True)

        for field, value in updates.items():
            if field in {"website", "logo_url"} and value is not None:
                value = str(value)

            setattr(organization, field, value)

        return self.repository.update(organization)

    def update_settings(
        self,
        organization_id: int,
        data: OrganizationSettingsUpdate,
    ) -> Organization:
        organization = self.get_organization(organization_id)

        updates = data.model_dump(exclude_unset=True)

        for field, value in updates.items():
            setattr(organization, field, value)

        return self.repository.update(organization)