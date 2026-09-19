from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.dependencies.auth import (
    require_authenticated_user,
    require_internal_api_key,
)
from app.schemas.organization import (
    OrganizationCreate,
    OrganizationResponse,
    OrganizationSettingsUpdate,
    OrganizationUpdate,
)
from app.services.organization_service import OrganizationService


router = APIRouter(
    prefix="/api/v1/organizations",
    tags=["Organizations"],
)

internal_router = APIRouter(
    prefix="/api/v1/internal/organizations",
    tags=["Internal Organizations"],
)


@internal_router.post(
    "",
    response_model=OrganizationResponse,
)
def create_organization(
    data: OrganizationCreate,
    db: Session = Depends(get_db),
    _: None = Depends(require_internal_api_key),
) -> OrganizationResponse:
    service = OrganizationService(db)
    return service.create_organization(data)


@router.put(
    "/profile",
    response_model=OrganizationResponse,
)
def update_organization_profile(
    data: OrganizationUpdate,
    token_payload: dict = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
) -> OrganizationResponse:
    organization_id = token_payload.get("organization_id")

    if organization_id is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Organization ID is missing from access token",
        )

    service = OrganizationService(db)

    return service.update_profile(
        organization_id=int(organization_id),
        data=data,
    )


@router.put(
    "/settings",
    response_model=OrganizationResponse,
)
def update_organization_settings(
    data: OrganizationSettingsUpdate,
    token_payload: dict = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
) -> OrganizationResponse:
    organization_id = token_payload.get("organization_id")

    if organization_id is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Organization ID is missing from access token",
        )

    service = OrganizationService(db)

    return service.update_settings(
        organization_id=int(organization_id),
        data=data,
    )