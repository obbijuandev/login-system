"""Inicialización del esquema de base de datos.

Estrategia:
- Las instalaciones nuevas de SQLite dependen de create_all() y luego agregan
  un índice único parcial para users.email cuando email IS NOT NULL.
- Las bases SQLite existentes se actualizan en el lugar con sentencias
  ALTER TABLE aditivas, porque create_all() no migra tablas existentes.
- Si los datos legacy ya contienen correos no nulos duplicados, la aplicación
  sigue iniciando, deja email como nullable y crea solo un índice de búsqueda
  no único hasta que los duplicados se limpien en un paso posterior.
"""

import logging
from enum import StrEnum

from sqlalchemy import ForeignKey, String, create_engine
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    relationship,
    sessionmaker,
)

from app.core.config import config

engine = create_engine(config.db_url, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

logger = logging.getLogger(__name__)
USER_EMAIL_UNIQUE_INDEX = "uq_users_email_non_null"
USER_EMAIL_FALLBACK_INDEX = "ix_users_email_non_null"
USER_ROLE_INDEX = "ix_users_role_id"


class RoleName(StrEnum):
    ADMIN = "ADMIN"
    AGENTE = "AGENTE"
    SUPERVISOR = "SUPERVISOR"


INITIAL_ROLE_NAMES = tuple(role_name.value for role_name in RoleName)
DEFAULT_ROLE_NAME = RoleName.AGENTE


class Base(DeclarativeBase):
    pass


class Role(Base):
    __tablename__ = "roles"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(50), unique=True, index=True)

    users: Mapped[list["User"]] = relationship(back_populates="role")


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    role_id: Mapped[int | None] = mapped_column(
        ForeignKey("roles.id"), nullable=True, index=True
    )

    role: Mapped[Role | None] = relationship(back_populates="users")


def init_db(db_engine=engine) -> None:
    """Crea tablas faltantes y actualiza esquemas legacy de SQLite de forma segura."""
    Base.metadata.create_all(bind=db_engine)
    migrate_legacy_schema(db_engine)


def migrate_legacy_schema(db_engine=engine) -> None:
    """Aplica cambios aditivos al esquema SQLite que create_all() no puede manejar."""
    with db_engine.begin() as connection:
        tables = {
            row[0]
            for row in connection.exec_driver_sql(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }

        if Role.__tablename__ not in tables:
            connection.exec_driver_sql(
                """
                CREATE TABLE roles (
                    id INTEGER PRIMARY KEY,
                    name VARCHAR(50) NOT NULL UNIQUE
                )
                """
            )
            logger.info("Se creó la tabla roles para la base SQLite legacy")

        _ensure_initial_roles(connection)

        if User.__tablename__ not in tables:
            return

        columns = _get_table_columns(connection, User.__tablename__)
        if "email" not in columns:
            connection.exec_driver_sql(
                f"ALTER TABLE {User.__tablename__} ADD COLUMN email VARCHAR(255)"
            )
            logger.info("Se agregó la columna users.email para la base SQLite legacy")

        if "password_hash" not in columns:
            connection.exec_driver_sql(
                f"ALTER TABLE {User.__tablename__} ADD COLUMN password_hash VARCHAR(255)"
            )
            logger.info(
                "Se agregó la columna users.password_hash para la base SQLite legacy"
            )

        if "role_id" not in columns:
            connection.exec_driver_sql(
                f"ALTER TABLE {User.__tablename__} ADD COLUMN role_id INTEGER"
            )
            logger.info("Se agregó la columna users.role_id para la base SQLite legacy")

        _ensure_email_indexes(connection)
        _ensure_role_index(connection)
        _backfill_legacy_users_role(connection)


def _get_table_columns(connection, table_name: str) -> set[str]:
    rows = (
        connection.exec_driver_sql(f"PRAGMA table_info('{table_name}')")
        .mappings()
        .all()
    )
    return {row["name"] for row in rows}


def _get_indexes(connection, table_name: str) -> list[dict]:
    return (
        connection.exec_driver_sql(f"PRAGMA index_list('{table_name}')")
        .mappings()
        .all()
    )


def _index_columns(connection, index_name: str) -> list[str]:
    rows = (
        connection.exec_driver_sql(f"PRAGMA index_info('{index_name}')")
        .mappings()
        .all()
    )
    return [row["name"] for row in rows]


def _has_email_duplicates(connection) -> bool:
    duplicate_email = connection.exec_driver_sql(
        """
        SELECT email
        FROM users
        WHERE email IS NOT NULL
        GROUP BY email
        HAVING COUNT(*) > 1
        LIMIT 1
        """
    ).first()
    return duplicate_email is not None


def _ensure_initial_roles(connection) -> None:
    for role_name in INITIAL_ROLE_NAMES:
        connection.exec_driver_sql(
            "INSERT OR IGNORE INTO roles (name) VALUES (?)",
            (role_name,),
        )


def _get_role_id(connection, role_name: str) -> int | None:
    row = connection.exec_driver_sql(
        "SELECT id FROM roles WHERE name = ? LIMIT 1",
        (role_name,),
    ).first()
    return None if row is None else row[0]


def _ensure_role_index(connection) -> None:
    connection.exec_driver_sql(
        f"CREATE INDEX IF NOT EXISTS {USER_ROLE_INDEX} ON users (role_id)"
    )


def _backfill_legacy_users_role(connection) -> None:
    default_role_id = _get_role_id(connection, DEFAULT_ROLE_NAME)
    if default_role_id is None:
        raise RuntimeError(
            f"No existe el rol por defecto requerido: {DEFAULT_ROLE_NAME}"
        )

    result = connection.exec_driver_sql(
        "UPDATE users SET role_id = ? WHERE role_id IS NULL",
        (default_role_id,),
    )
    if result.rowcount:
        logger.info(
            "Se asignó el rol %s a %s usuarios legacy sin role_id",
            DEFAULT_ROLE_NAME,
            result.rowcount,
        )


def _ensure_email_indexes(connection) -> None:
    email_indexes = [
        index
        for index in _get_indexes(connection, User.__tablename__)
        if _index_columns(connection, index["name"]) == ["email"]
    ]

    has_unique_email_index = any(index["unique"] for index in email_indexes)
    if has_unique_email_index:
        return

    if _has_email_duplicates(connection):
        if not any(
            index["name"] == USER_EMAIL_FALLBACK_INDEX for index in email_indexes
        ):
            connection.exec_driver_sql(
                f"CREATE INDEX IF NOT EXISTS {USER_EMAIL_FALLBACK_INDEX} "
                "ON users (email) WHERE email IS NOT NULL"
            )
        logger.warning(
            "Se omitió la creación del índice único de email porque los usuarios legacy contienen correos duplicados"
        )
        return

    connection.exec_driver_sql(
        f"CREATE UNIQUE INDEX IF NOT EXISTS {USER_EMAIL_UNIQUE_INDEX} "
        "ON users (email) WHERE email IS NOT NULL"
    )
