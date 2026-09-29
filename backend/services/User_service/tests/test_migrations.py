"""Alembic migration safety.

Migrations must never drop a database, drop the ``users`` table or lose rows,
whether the table is created from scratch or inherited from the pre-split
schema. These tests run the real migration chain against a throwaway SQLite
file, which keeps them fast and completely isolated from MySQL.
"""

from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.engine import Engine


SERVICE_ROOT = Path(__file__).resolve().parents[1]
ALEMBIC_INI = SERVICE_ROOT / "alembic.ini"
HEAD = "20260929_0005"

LEGACY_USERS_DDL = """
CREATE TABLE users (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    email VARCHAR(255) NOT NULL UNIQUE,
    full_name VARCHAR(200) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(30),
    tenant_id INTEGER,
    is_active BOOLEAN NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
)
"""


def _config(url: str) -> Config:
    config = Config(str(ALEMBIC_INI))
    config.set_main_option("script_location", str(SERVICE_ROOT / "alembic"))
    config.set_main_option("sqlalchemy.url", url)
    return config


@pytest.fixture()
def engine(tmp_path: Path) -> Engine:
    engine = sa.create_engine(f"sqlite+pysqlite:///{tmp_path / 'migrations.db'}")
    yield engine
    engine.dispose()


def _upgrade(engine: Engine) -> None:
    with engine.connect() as connection:
        connection.execute(sa.text("SELECT 1"))
    command.upgrade(_config(str(engine.url)), "head")


def _columns(engine: Engine) -> set[str]:
    inspector = sa.inspect(engine)
    return {column["name"] for column in inspector.get_columns("users")}


def _indexes(engine: Engine) -> set[str]:
    inspector = sa.inspect(engine)
    return {index["name"] for index in inspector.get_indexes("users")}


def _rows(engine: Engine) -> list[dict[str, object]]:
    with engine.connect() as connection:
        return [
            dict(row)
            for row in connection.execute(
                sa.text("SELECT * FROM users ORDER BY id")
            ).mappings()
        ]


def test_upgrade_on_an_empty_database_creates_the_table(engine: Engine) -> None:
    _upgrade(engine)

    assert _columns(engine) == {
        "id",
        "email",
        "first_name",
        "last_name",
        "phone_number",
        "bio",
        "is_active",
        "created_at",
        "updated_at",
    }
    assert {"ix_users_is_active", "ix_users_created_at"} <= _indexes(engine)

    with engine.connect() as connection:
        version = connection.execute(
            sa.text("SELECT version_num FROM alembic_version")
        ).scalar_one()
    assert version == HEAD


def test_upgrade_preserves_a_legacy_table_and_its_rows(engine: Engine) -> None:
    with engine.connect() as connection:
        connection.execute(sa.text(LEGACY_USERS_DDL))
        connection.execute(
            sa.text(
                "INSERT INTO users (email, full_name, password_hash, role) "
                "VALUES ('ada@example.com', 'Ada Lovelace', 'argon2$a', 'admin')"
            )
        )
        connection.execute(
            sa.text(
                "INSERT INTO users (email, full_name, password_hash, role) "
                "VALUES ('grace@example.com', 'Grace Brewster', 'argon2$b', NULL)"
            )
        )
        connection.commit()

    _upgrade(engine)

    columns = _columns(engine)
    assert {"first_name", "last_name", "phone_number", "bio"} <= columns
    # The columns owned by other services are still there.
    assert {"full_name", "password_hash", "role", "tenant_id"} <= columns
    assert {"ix_users_is_active", "ix_users_created_at"} <= _indexes(engine)

    rows = {row["email"]: row for row in _rows(engine)}
    assert set(rows) == {"ada@example.com", "grace@example.com"}
    assert rows["ada@example.com"]["first_name"] == "Ada"
    assert rows["ada@example.com"]["last_name"] == "Lovelace"
    assert rows["ada@example.com"]["password_hash"] == "argon2$a"
    assert rows["grace@example.com"]["first_name"] == "Grace"
    assert rows["grace@example.com"]["last_name"] == "Brewster"


def test_upgrade_is_idempotent(engine: Engine) -> None:
    _upgrade(engine)
    _upgrade(engine)

    assert len(_rows(engine)) == 0
    assert _columns(engine)


def test_downgrade_never_drops_an_inherited_table(engine: Engine) -> None:
    with engine.connect() as connection:
        connection.execute(sa.text(LEGACY_USERS_DDL))
        connection.execute(
            sa.text(
                "INSERT INTO users (email, full_name, password_hash) "
                "VALUES ('ada@example.com', 'Ada Lovelace', 'argon2$a')"
            )
        )
        connection.commit()

    _upgrade(engine)
    command.downgrade(_config(str(engine.url)), "base")

    rows = _rows(engine)
    assert len(rows) == 1
    assert rows[0]["email"] == "ada@example.com"
    assert rows[0]["password_hash"] == "argon2$a"


def test_downgrade_and_upgrade_round_trip(engine: Engine) -> None:
    _upgrade(engine)
    command.downgrade(_config(str(engine.url)), "base")
    _upgrade(engine)

    assert _columns(engine) == {
        "id",
        "email",
        "first_name",
        "last_name",
        "phone_number",
        "bio",
        "is_active",
        "created_at",
        "updated_at",
    }


def test_migration_chain_has_a_single_head(engine: Engine) -> None:
    from alembic.script import ScriptDirectory

    script = ScriptDirectory.from_config(_config(str(engine.url)))
    heads = script.get_heads()

    assert heads == [HEAD]
