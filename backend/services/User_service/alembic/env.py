from sqlalchemy import engine_from_config, pool

from alembic import context

from app.core.config import settings
from app.database.base import Base
from app.models.user import User


config = context.config

config.set_main_option(
    "sqlalchemy.url",
    settings.database_url.replace("%", "%%"),
)


target_metadata = Base.metadata
USER_TABLE_NAME = User.__tablename__
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


def include_object(
    _object: object,
    name: str | None,
    type_: str,
    reflected: bool,
    _compare_to: object | None,
) -> bool:
    if type_ == "table":
        return name in target_metadata.tables

    table_name = getattr(getattr(_object, "table", None), "name", None)
    if table_name != USER_TABLE_NAME:
        return False

    if (
        type_ == "column"
        and reflected
        and name in EXTERNAL_USER_COLUMNS
    ):
        return False

    if type_ in {
        "foreign_key",
        "foreign_key_constraint",
        "index",
        "unique_constraint",
    }:
        column_names = {
            column.name for column in getattr(_object, "columns", [])
        }
        if column_names & EXTERNAL_USER_COLUMNS:
            return False

    return True


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")

    context.configure(
        url=url,
        target_metadata=target_metadata,
        include_object=include_object,
        compare_server_default=False,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            include_object=include_object,
            compare_server_default=False,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
