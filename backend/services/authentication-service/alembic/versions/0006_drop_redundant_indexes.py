"""drop redundant unique-column indexes

Revision ID: 0006_drop_redundant_indexes
Revises: e2e0847905a8
Create Date: 2026-09-29
"""
from alembic import op

revision = "0006_drop_redundant_indexes"
down_revision = "e2e0847905a8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # The UNIQUE constraints on email/user_id (auth_credentials) and token_hash
    # (refresh_sessions, password_resets) already provide the equality lookup
    # index; the separate non-unique indexes were redundant write overhead.
    op.drop_index("ix_auth_credentials_email", table_name="auth_credentials")
    op.drop_index("ix_auth_credentials_user_id", table_name="auth_credentials")
    op.drop_index("ix_refresh_sessions_token_hash", table_name="refresh_sessions")
    op.drop_index("ix_password_resets_token_hash", table_name="password_resets")


def downgrade() -> None:
    op.create_index("ix_password_resets_token_hash", "password_resets", ["token_hash"], unique=False)
    op.create_index("ix_refresh_sessions_token_hash", "refresh_sessions", ["token_hash"], unique=False)
    op.create_index("ix_auth_credentials_user_id", "auth_credentials", ["user_id"], unique=False)
    op.create_index("ix_auth_credentials_email", "auth_credentials", ["email"], unique=False)