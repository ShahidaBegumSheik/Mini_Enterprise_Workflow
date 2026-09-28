from collections.abc import Mapping
from typing import Any

from fastapi import HTTPException, status
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.exceptions import DatabaseOperationError
from app.models.user import User
from app.repositories.user_repository import (
    get_user_by_id,
    update_user,
)


def get_user(
    db: Session,
    user_id: int,
) -> User:
    try:
        user = get_user_by_id(db, user_id)
    except SQLAlchemyError as exc:
        db.rollback()
        raise DatabaseOperationError from exc

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    return user


def update_user_profile(
    db: Session,
    user_id: int,
    data: Mapping[str, Any],
) -> User:
    try:
        user = get_user(db, user_id)
        return update_user(
            db=db,
            user=user,
            data=data,
        )
    except DatabaseOperationError:
        raise
    except SQLAlchemyError as exc:
        db.rollback()
        raise DatabaseOperationError from exc
