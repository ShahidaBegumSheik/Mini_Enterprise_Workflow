from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.dependencies.auth import get_current_user_id
from app.schemas.user import UserResponse, UserUpdate
from app.services.user_service import (
    get_user,
    update_user_profile,
)


router = APIRouter(
    prefix="/users",
    tags=["Users"],
)


@router.get(
    "/profile",
    response_model=UserResponse,
    summary="Get authenticated user profile",
    description="Return the profile for the user identified by the Authentication Service JWT.",
)
def get_profile(
    db: Session = Depends(get_db),
    user_id: int = Depends(get_current_user_id),
):
    return get_user(
        db=db,
        user_id=user_id,
    )


@router.put(
    "/profile",
    response_model=UserResponse,
    summary="Update authenticated user profile",
    description="Update editable profile fields for the user identified by the Authentication Service JWT.",
)
def update_profile(
    data: UserUpdate,
    db: Session = Depends(get_db),
    user_id: int = Depends(get_current_user_id),
):
    return update_user_profile(
        db=db,
        user_id=user_id,
        data=data.model_dump(exclude_unset=True),
    )
