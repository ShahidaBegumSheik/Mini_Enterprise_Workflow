"""add user listing indexes

Non-destructive: only creates the two indexes that back the paginated
``GET /users`` listing. No column is added, dropped or retyped and no row is
touched, so existing data is preserved. Every step is guarded by an inspection
so the migration is a no-op on databases that already carry the indexes or that
do not have a ``users`` table yet.

Revision ID: 20260929_0004
Revises: 20260925_0003
Create Date: 2026-09-29
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import context, op


revision: str = "20260929_0004"
down_revision: str | None = "20260925_0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


INDEXES: tuple[tuple[str, str], ...] = (
    ("ix_users_is_active", "is_active"),
    ("ix_users_created_at", "created_at"),
)


def _inspector(bind: sa.Connection) -> sa.Inspector | None:
    inspector = sa.inspect(bind)
    if "users" not in inspector.get_table_names():
        return None
    return inspector


def _missing_indexes(inspector: sa.Inspector) -> list[tuple[str, str]]:
    columns = {column["name"] for column in inspector.get_columns("users")}
    existing = {index["name"] for index in inspector.get_indexes("users")}
    existing.update(
        constraint["name"] or "" for constraint in inspector.get_unique_constraints("users")
    )

    return [
        (name, column)
        for name, column in INDEXES
        if name not in existing and column in columns
    ]


def upgrade() -> None:
    if context.is_offline_mode():
        for name, column in INDEXES:
            op.create_index(name, "users", [column], unique=False)
        return

    bind = op.get_bind()
    inspector = _inspector(bind)
    if inspector is None:
        return

    for name, column in _missing_indexes(inspector):
        op.create_index(name, "users", [column], unique=False)


def downgrade() -> None:
    if context.is_offline_mode():
        for name, _column in reversed(INDEXES):
            op.drop_index(name, table_name="users")
        return

    bind = op.get_bind()
    inspector = _inspector(bind)
    if inspector is None:
        return

    existing = {index["name"] for index in inspector.get_indexes("users")}

    for name, _column in reversed(INDEXES):
        if name in existing:
            op.drop_index(name, table_name="users")
