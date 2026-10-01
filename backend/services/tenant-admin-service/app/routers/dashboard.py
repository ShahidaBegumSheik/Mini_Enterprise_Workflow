from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.dependencies.auth import require_authenticated_user
from app.schemas.organization import OrganizationResponse
from app.services.organization_service import OrganizationService


router = APIRouter(
    prefix="/api/v1/dashboard",
    tags=["Dashboard"],
)


@router.get(
    "/organization",
    response_model=OrganizationResponse,
)
def get_organization_dashboard(
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

    return service.get_organization(int(organization_id))