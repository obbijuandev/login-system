import pytest
from sqlalchemy import StaticPool, create_engine
from sqlalchemy.orm import sessionmaker

from app.db.schema import (
    Base,
    DEFAULT_ROLE_NAME,
    INITIAL_ROLE_NAMES,
    USER_EMAIL_FALLBACK_INDEX,
    USER_EMAIL_UNIQUE_INDEX,
    USER_ROLE_INDEX,
    init_db,
    migrate_legacy_schema,
)

# Configurar la base SQLite en memoria para pruebas
DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(
    DATABASE_URL,
    connect_args={
        "check_same_thread": False,
    },
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
init_db(engine)


def make_sqlite_engine():
    return create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )


def get_table_columns(db_engine, table_name: str) -> set[str]:
    with db_engine.connect() as connection:
        rows = (
            connection.exec_driver_sql(f"PRAGMA table_info('{table_name}')")
            .mappings()
            .all()
        )
    return {row["name"] for row in rows}


def get_indexes(db_engine, table_name: str) -> dict[str, dict]:
    with db_engine.connect() as connection:
        indexes = (
            connection.exec_driver_sql(f"PRAGMA index_list('{table_name}')")
            .mappings()
            .all()
        )
        return {index["name"]: index for index in indexes}


def get_role_names(db_engine) -> list[str]:
    with db_engine.connect() as connection:
        rows = connection.exec_driver_sql("SELECT name FROM roles ORDER BY name").all()
    return [row[0] for row in rows]


def get_user_role_ids(db_engine) -> list[int | None]:
    with db_engine.connect() as connection:
        rows = connection.exec_driver_sql("SELECT role_id FROM users ORDER BY id").all()
    return [row[0] for row in rows]


def test_init_db_creates_users_and_roles_tables_with_required_indexes():
    db_engine = make_sqlite_engine()

    init_db(db_engine)

    user_columns = get_table_columns(db_engine, "users")
    role_columns = get_table_columns(db_engine, "roles")
    indexes = get_indexes(db_engine, "users")

    assert {"id", "name", "email", "password_hash", "role_id"}.issubset(user_columns)
    assert {"id", "name"}.issubset(role_columns)
    assert get_role_names(db_engine) == sorted(INITIAL_ROLE_NAMES)
    assert USER_EMAIL_UNIQUE_INDEX in indexes
    assert indexes[USER_EMAIL_UNIQUE_INDEX]["unique"] == 1
    assert indexes[USER_EMAIL_UNIQUE_INDEX]["partial"] == 1
    assert USER_ROLE_INDEX in indexes


def test_migrate_legacy_schema_adds_missing_columns_and_unique_email_index():
    db_engine = make_sqlite_engine()

    with db_engine.begin() as connection:
        connection.exec_driver_sql(
            "CREATE TABLE users (id INTEGER PRIMARY KEY, name VARCHAR(255) NOT NULL)"
        )

    migrate_legacy_schema(db_engine)

    columns = get_table_columns(db_engine, "users")
    indexes = get_indexes(db_engine, "users")

    assert {"email", "password_hash", "role_id"}.issubset(columns)
    assert get_role_names(db_engine) == sorted(INITIAL_ROLE_NAMES)
    assert USER_EMAIL_UNIQUE_INDEX in indexes
    assert indexes[USER_EMAIL_UNIQUE_INDEX]["unique"] == 1
    assert USER_ROLE_INDEX in indexes


def test_init_db_seeds_roles_idempotently():
    db_engine = make_sqlite_engine()

    init_db(db_engine)
    init_db(db_engine)

    assert get_role_names(db_engine) == sorted(INITIAL_ROLE_NAMES)


def test_migrate_legacy_schema_falls_back_when_duplicate_emails_exist(
    caplog: pytest.LogCaptureFixture,
):
    db_engine = make_sqlite_engine()

    with db_engine.begin() as connection:
        connection.exec_driver_sql(
            """
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                email VARCHAR(255)
            )
            """
        )
        connection.exec_driver_sql(
            "INSERT INTO users (name, email) VALUES ('Ada', 'dup@example.com')"
        )
        connection.exec_driver_sql(
            "INSERT INTO users (name, email) VALUES ('Grace', 'dup@example.com')"
        )

    with caplog.at_level("WARNING"):
        migrate_legacy_schema(db_engine)

    columns = get_table_columns(db_engine, "users")
    indexes = get_indexes(db_engine, "users")

    assert {"password_hash", "role_id"}.issubset(columns)
    assert USER_EMAIL_UNIQUE_INDEX not in indexes
    assert USER_EMAIL_FALLBACK_INDEX in indexes
    assert indexes[USER_EMAIL_FALLBACK_INDEX]["unique"] == 0
    assert "Se omitió la creación del índice único de email" in caplog.text


def test_migrate_legacy_schema_backfills_legacy_users_to_default_role():
    db_engine = make_sqlite_engine()

    with db_engine.begin() as connection:
        connection.exec_driver_sql(
            """
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                name VARCHAR(255) NOT NULL
            )
            """
        )
        connection.exec_driver_sql("INSERT INTO users (name) VALUES ('Ada'), ('Grace')")

    migrate_legacy_schema(db_engine)

    with db_engine.connect() as connection:
        default_role_id = connection.exec_driver_sql(
            "SELECT id FROM roles WHERE name = ?",
            (DEFAULT_ROLE_NAME,),
        ).scalar_one()

    assert get_user_role_ids(db_engine) == [default_role_id, default_role_id]
