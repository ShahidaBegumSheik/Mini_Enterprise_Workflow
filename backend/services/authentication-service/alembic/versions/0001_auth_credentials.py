from alembic import op
import sqlalchemy as sa

revision = "0001_auth_credentials"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "auth_credentials",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("account_type", sa.String(30), nullable=False, server_default="individual"),
        sa.Column("organization_id", sa.Integer(), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("is_verified", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("must_change_password", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("token_version", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_login_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("user_id", name="uq_auth_credentials_user_id"),
        sa.UniqueConstraint("email", name="uq_auth_credentials_email"),
    )
    op.create_index("ix_auth_credentials_email", "auth_credentials", ["email"])
    op.create_index("ix_auth_credentials_user_id", "auth_credentials", ["user_id"])


def downgrade() -> None:
    op.drop_table("auth_credentials")