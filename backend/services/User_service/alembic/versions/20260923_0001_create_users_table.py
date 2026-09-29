"""create users table

Non-destructive: when a ``users`` table already exists (for example the
pre-split table that carried ``full_name`` / ``password_hash`` / ``role`` and
friends) the table is left completely untouched and only the missing indexes
are created. The later revisions add and backfill ``first_name`` /
``last_name``, so a pre-existing table still converges on the shape this
service owns. No database, table or row is ever dropped.

Revision ID: 20260923_0001
Revises:
Create Date: 2026-09-23
"""

from collections.abc import Sequence
from typing import Union

from alembic import context, op
import sqlalchemy as sa


revision: str = "20260923_0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


#: Columns owned by another service. A table carrying them was not created by
#: this revision, so it must never be dropped from here.
EXTERNAL_USER_COLUMNS = {
    "full_name",
    "password_hash",
    "account_type",
    "role",
    "tenant_id",
    "is_verified",
    "is_password_set",
    "auth_provider",
    "google_id",
}


def _users_exists(bind: sa.Connection) -> bool:
    return "users" in sa.inspect(bind).get_table_names()


def _existing_columns(bind: sa.Connection) -> set[str]:
    return {column["name"] for column in sa.inspect(bind).get_columns("users")}


def _existing_indexes(bind: sa.Connection) -> set[str]:
    inspector = sa.inspect(bind)
    names = {index["name"] for index in inspector.get_indexes("users")}
    names.update(
        constraint["name"] or ""
        for constraint in inspector.get_unique_constraints("users")
    )
    return names


def upgrade() -> None:
    if context.is_offline_mode():
        op.create_table(
            "users",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("email", sa.String(length=255), nullable=False),
            sa.Column("first_name", sa.String(length=100), nullable=False),
            sa.Column("last_name", sa.String(length=100), nullable=True),
            sa.Column("phone_number", sa.String(length=30), nullable=True),
            sa.Column("bio", sa.Text(), nullable=True),
            sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index(op.f("ix_users_email"), "users", ["email"], unique=True)
        op.create_index(op.f("ix_users_id"), "users", ["id"], unique=False)
        return

    bind = op.get_bind()

    if not _users_exists(bind):
        op.create_table(
            "users",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("email", sa.String(length=255), nullable=False),
            sa.Column("first_name", sa.String(length=100), nullable=False),
            sa.Column("last_name", sa.String(length=100), nullable=True),
            sa.Column("phone_number", sa.String(length=30), nullable=True),
            sa.Column("bio", sa.Text(), nullable=True),
            sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.PrimaryKeyConstraint("id"),
        )

    columns = _existing_columns(bind)
    indexes = _existing_indexes(bind)

    if "email" in columns and "ix_users_email" not in indexes:
        op.create_index(op.f("ix_users_email"), "users", ["email"], unique=True)

    if "id" in columns and "ix_users_id" not in indexes:
        op.create_index(op.f("ix_users_id"), "users", ["id"], unique=False)


def downgrade() -> None:
    if context.is_offline_mode():
        op.drop_index(op.f("ix_users_id"), table_name="users")
        op.drop_index(op.f("ix_users_email"), table_name="users")
        op.drop_table("users")
        return

    bind = op.get_bind()
    if not _users_exists(bind):
        return

    # A table this revision did not create is never dropped.
    if _existing_columns(bind) & EXTERNAL_USER_COLUMNS:
        return

    indexes = _existing_indexes(bind)
    if "ix_users_id" in indexes:
        op.drop_index(op.f("ix_users_id"), table_name="users")
    if "ix_users_email" in indexes:
        op.drop_index(op.f("ix_users_email"), table_name="users")

    op.drop_table("users")
