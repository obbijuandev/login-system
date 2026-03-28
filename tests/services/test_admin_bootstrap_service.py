import pytest

from app.db.schema import Role, RoleName, User
from app.services.admin_bootstrap_service import (
    AdminAlreadyExistsError,
    AdminBootstrapService,
    UserNotFoundForAdminBootstrapError,
)
from tests.test_db import TestingSessionLocal


def create_user(*, name: str, email: str, role_name: RoleName) -> User:
    session = TestingSessionLocal()
    try:
        role = session.query(Role).filter(Role.name == role_name).first()
        assert role is not None

        user = User(name=name, email=email, password_hash="hashed", role=role)
        session.add(user)
        session.commit()
        session.refresh(user)
        session.expunge(user)
        return user
    finally:
        session.close()


@pytest.fixture(autouse=True)
def clean_users_table():
    session = TestingSessionLocal()
    session.query(User).delete()
    session.commit()
    try:
        yield
    finally:
        session.query(User).delete()
        session.commit()
        session.close()


def test_promote_first_admin_by_email_promotes_existing_user_and_normalizes_email():
    create_user(name="Ada", email="ada@example.com", role_name=RoleName.AGENTE)

    session = TestingSessionLocal()
    try:
        service = AdminBootstrapService(session=session)

        promoted_user = service.promote_first_admin_by_email("  ADA@example.com  ")

        assert promoted_user.email == "ada@example.com"
        assert promoted_user.role is not None
        assert promoted_user.role.name == RoleName.ADMIN
    finally:
        session.close()


def test_promote_first_admin_by_email_fails_when_admin_already_exists():
    create_user(name="Admin", email="admin@example.com", role_name=RoleName.ADMIN)
    create_user(name="Agent", email="agent@example.com", role_name=RoleName.AGENTE)

    session = TestingSessionLocal()
    try:
        service = AdminBootstrapService(session=session)

        with pytest.raises(
            AdminAlreadyExistsError,
            match="Ya existe al menos un usuario con rol ADMIN",
        ):
            service.promote_first_admin_by_email("agent@example.com")
    finally:
        session.close()


def test_promote_first_admin_by_email_fails_when_user_does_not_exist_and_does_not_create_it():
    session = TestingSessionLocal()
    try:
        service = AdminBootstrapService(session=session)

        with pytest.raises(
            UserNotFoundForAdminBootstrapError,
            match="No existe un usuario registrado con el correo electrónico indicado",
        ):
            service.promote_first_admin_by_email("missing@example.com")

        assert session.query(User).count() == 0
    finally:
        session.close()
