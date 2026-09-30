from collections.abc import Sequence

import sqlalchemy as sa
from alembic import context, op


revision: str = "20260925_0003"
down_revision: str | None = "20260925_0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    if context.is_offline_mode():
        return

    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "users" not in inspector.get_table_names():
        return

    columns = {column["name"] for column in inspector.get_columns("users")}
    required_columns = {"id", "full_name", "email", "first_name", "last_name"}
    if not required_columns.issubset(columns):
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

        if str(row["first_name"] or "").strip():
            continue
        if last_name is None:
            bind.execute(
                sa.text(
                    "UPDATE users SET first_name = :first_name WHERE id = :user_id"
                ),
                {"first_name": first_name, "user_id": row["id"]},
            )
        else:
            bind.execute(
                sa.text(
                    "UPDATE users SET first_name = :first_name, "
                    "last_name = :last_name WHERE id = :user_id"
                ),
                {
                    "first_name": first_name,
                    "last_name": last_name,
                    "user_id": row["id"],
                },
            )


def downgrade() -> None:
    return None
