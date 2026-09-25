from alembic import op
import sqlalchemy as sa

revision = "0003_refresh_sessions_updated_at"
down_revision = "0002_refresh_sessions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "refresh_sessions",
        sa.Column(
            "updated_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
    )


def downgrade() -> None:
    op.drop_column("refresh_sessions", "updated_at")