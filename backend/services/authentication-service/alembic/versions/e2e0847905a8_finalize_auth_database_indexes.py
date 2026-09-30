"""finalize auth database indexes

Revision ID: e2e0847905a8
Revises: 0004_password_resets
Create Date: 2026-09-29 10:52:39.293162
"""
from alembic import op

revision = "e2e0847905a8"
down_revision = "0004_password_resets"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Expiry lookups / cleanup scans and revoked-status scans were missing
    # indexes. (token_hash and user_id are already covered by unique
    # constraints and explicit indexes from 0001/0002/0004.)
    op.create_index(
        "ix_refresh_sessions_revoked_at", "refresh_sessions", ["revoked_at"], unique=False
    )
    op.create_index(
        "ix_password_resets_expires_at", "password_resets", ["expires_at"], unique=False
    )
    op.create_index(
        "ix_password_resets_consumed_at", "password_resets", ["consumed_at"], unique=False
    )


def downgrade() -> None:
    op.drop_index("ix_password_resets_consumed_at", table_name="password_resets")
    op.drop_index("ix_password_resets_expires_at", table_name="password_resets")
    op.drop_index("ix_refresh_sessions_revoked_at", table_name="refresh_sessions")