"""add organization type and industry

Revision ID: c3af5aca74f8
Revises: 1d4b981fb54f
Create Date: 2026-09-28 10:03:20.665641

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "c3af5aca74f8"
down_revision: Union[str, Sequence[str], None] = "1d4b981fb54f"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "organizations",
        sa.Column(
            "organization_type",
            sa.String(length=100),
            nullable=True,
        ),
    )

    op.add_column(
        "organizations",
        sa.Column(
            "industry",
            sa.String(length=150),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("organizations", "industry")
    op.drop_column("organizations", "organization_type")