"""align an inherited users table with the columns this service owns

Non-destructive: for a ``users`` table that predates the split, this adds only
the columns the :class:`~app.models.user.User` model maps but that no earlier
revision created. Every added column is nullable or carries a constant server
default, so no row is rewritten and no data is lost.

Revisions ``0002`` / ``0003`` already add and backfill ``first_name`` and
``last_name``; ``id``, ``email``, ``is_active``, ``created_at`` and
``updated_at`` exist both on a freshly created table (``0001``) and on the
pre-split table, so they need no ``ALTER``.

Revision ID: 20260929_0005
Revises: 20260929_0004
Create Date: 2026-09-29
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import context, op


revision: str = "20260929_0005"
down_revision: str | None = "20260929_0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


#: column name -> column definition, in the order they should be added.
OWNED_COLUMNS: tuple[tuple[str, sa.Column], ...] = (
    ("phone_number", sa.Column("phone_number", sa.String(length=30), nullable=True)),
    ("bio", sa.Column("bio", sa.Text(), nullable=True)),
    (
        "is_active",
        sa.Column(
            "is_active",
            sa.Boolean(),
            nullable=False,
            server_default=sa.true(),
        ),
    ),
)

#: Columns the downgrade may remove. ``is_active`` is excluded on purpose: it
#: is also part of the table this revision inherits, so dropping it here could
#: destroy data this revision never created.
REVERSIBLE_COLUMNS: tuple[str, ...] = ("bio", "phone_number")


def _existing_columns(bind: sa.Connection) -> set[str] | None:
    inspector = sa.inspect(bind)
    if "users" not in inspector.get_table_names():
        return None

    return {column["name"] for column in inspector.get_columns("users")}


def _existing_indexes(bind: sa.Connection) -> set[str]:
    return {index["name"] for index in sa.inspect(bind).get_indexes("users")}


def _indexes_on(bind: sa.Connection, column: str) -> list[str]:
    return [
        index["name"]
        for index in sa.inspect(bind).get_indexes("users")
        if column in (index.get("column_names") or [])
    ]


def _is_empty(bind: sa.Connection, column: str) -> bool:
    """True when no row holds a value, so removing the column loses nothing."""

    total = bind.execute(
        sa.text(f"SELECT COUNT(*) FROM users WHERE {column} IS NOT NULL")
    ).scalar()

    return not total


def _missing_columns(columns: set[str]) -> list[sa.Column]:
    return [
        column
        for name, column in OWNED_COLUMNS
        if name not in columns
    ]


def upgrade() -> None:
    if context.is_offline_mode():
        for column in _missing_columns(set()):
            op.add_column("users", column)
        return

    bind = op.get_bind()
    columns = _existing_columns(bind)
    if columns is None:
        return

    for column in _missing_columns(columns):
        op.add_column("users", column)


def downgrade() -> None:
    if context.is_offline_mode():
        for name in reversed(REVERSIBLE_COLUMNS):
            op.drop_column("users", name)
        return

    bind = op.get_bind()
    columns = _existing_columns(bind)
    if columns is None:
        return

    for name in reversed(REVERSIBLE_COLUMNS):
        if name not in columns or not _is_empty(bind, name):
            continue

        for index_name in _indexes_on(bind, name):
            op.drop_index(index_name, table_name="users")

        op.drop_column("users", name)
