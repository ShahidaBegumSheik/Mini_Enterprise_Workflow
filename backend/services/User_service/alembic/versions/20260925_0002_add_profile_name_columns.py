from collections.abc import Sequence

import sqlalchemy as sa
from alembic import context, op


revision: str = "20260925_0002"
down_revision: str | None = "20260923_0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _get_users_columns(bind: sa.Connection) -> set[str]:
    inspector = sa.inspect(bind)
    if "users" not in inspector.get_table_names():
        return set()
    return {column["name"] for column in inspector.get_columns("users")}


def _backfill_profile_names(
    bind: sa.Connection,
    columns: set[str],
) -> None:
    if "full_name" not in columns or "email" not in columns:
        return

    rows = bind.execute(
        sa.text(
            "SELECT id, full_name, email, first_name, last_name FROM users"
        )
    ).mappings()

    for row in rows:
        full_name = str(row["full_name"] or "").strip()
        email = str(row["email"] or "").strip()
        name_parts = full_name.split()
        first_name = name_parts[0] if name_parts else email.split("@", 1)[0]
        if not first_name:
            first_name = "Unknown"
        first_name = first_name[:100]
        last_name = " ".join(name_parts[1:]) if len(name_parts) > 1 else None
        if last_name is not None:
            last_name = last_name[:100]

        if not str(row["first_name"] or "").strip():
            bind.execute(
                sa.text(
                    "UPDATE users SET first_name = :first_name WHERE id = :user_id"
                ),
                {"first_name": first_name, "user_id": row["id"]},
            )

        if row["last_name"] is None and last_name is not None:
            bind.execute(
                sa.text(
                    "UPDATE users SET last_name = :last_name WHERE id = :user_id"
                ),
                {"last_name": last_name, "user_id": row["id"]},
            )


def upgrade() -> None:
    if context.is_offline_mode():
        return

    bind = op.get_bind()
    columns = _get_users_columns(bind)
    if not columns:
        return

    if "first_name" not in columns:
        op.add_column(
            "users",
            sa.Column(
                "first_name",
                sa.String(length=100),
                nullable=False,
                server_default=sa.text("''"),
            ),
        )
        columns.add("first_name")

    if "last_name" not in columns:
        op.add_column(
            "users",
            sa.Column("last_name", sa.String(length=100), nullable=True),
        )
        columns.add("last_name")

    _backfill_profile_names(bind, columns)


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "users" not in inspector.get_table_names():
        return

    first_name = next(
        (
            column
            for column in inspector.get_columns("users")
            if column["name"] == "first_name"
        ),
        None,
    )
    if first_name is None or first_name.get("default") is None:
        return

    if "last_name" in {column["name"] for column in inspector.get_columns("users")}:
        op.drop_column("users", "last_name")
    op.drop_column("users", "first_name")
