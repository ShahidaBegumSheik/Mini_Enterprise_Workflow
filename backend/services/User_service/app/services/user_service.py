from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.models.user import User
from app.repositories.user_repository import (
    get_user_by_id,
    update_user,
)


def get_user(
    db: Session,
    user_id: int,
) -> User:
    user = get_user_by_id(db, user_id)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    return user


def update_user_profile(
    db: Session,
    user_id: int,
    data: dict,
) -> User:
    user = get_user(db, user_id)

    return update_user(
        db=db,
        user=user,
        data=data,
    )
