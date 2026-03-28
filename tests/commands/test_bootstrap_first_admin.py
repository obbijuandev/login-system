from io import StringIO

from app.commands.bootstrap_first_admin import main
from app.db.schema import Role, RoleName, User
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


def clean_users():
    session = TestingSessionLocal()
    try:
        session.query(User).delete()
        session.commit()
    finally:
        session.close()


def test_bootstrap_first_admin_command_promotes_existing_user_and_returns_zero():
    clean_users()
    create_user(name="Ada", email="ada@example.com", role_name=RoleName.AGENTE)
    stdout = StringIO()
    stderr = StringIO()

    exit_code = main(
        ["--email", "ADA@example.com"],
        session_factory=TestingSessionLocal,
        stdout=stdout,
        stderr=stderr,
        init_db_fn=lambda: None,
    )

    assert exit_code == 0
    assert (
        "Usuario 'ada@example.com' promovido correctamente a ADMIN."
        in stdout.getvalue()
    )
    assert stderr.getvalue() == ""

    session = TestingSessionLocal()
    try:
        user = session.query(User).filter(User.email == "ada@example.com").first()
        assert user is not None
        assert user.role is not None
        assert user.role.name == RoleName.ADMIN
    finally:
        session.close()
        clean_users()


def test_bootstrap_first_admin_command_returns_error_when_user_does_not_exist():
    clean_users()
    stdout = StringIO()
    stderr = StringIO()

    exit_code = main(
        ["--email", "missing@example.com"],
        session_factory=TestingSessionLocal,
        stdout=stdout,
        stderr=stderr,
        init_db_fn=lambda: None,
    )

    assert exit_code == 1
    assert stdout.getvalue() == ""
    assert (
        stderr.getvalue().strip()
        == "Error: No existe un usuario registrado con el correo electrónico indicado"
    )
