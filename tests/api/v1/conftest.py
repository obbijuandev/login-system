import os
import pytest
from fastapi.testclient import TestClient

# Disable rate limiting in tests
os.environ["TESTING"] = "true"

from app.api.dependencies import get_db
from app.main import app
from app.db.schema import Role, RoleName, User
from tests.test_db import TestingSessionLocal


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


def override_get_db():
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture(autouse=True)
def override_db_dependency():
    app.dependency_overrides[get_db] = override_get_db
    try:
        yield
    finally:
        app.dependency_overrides.pop(get_db, None)


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def auth_headers(client: TestClient):
    def _auth_headers(
        *,
        name: str = "Ada",
        email: str = "ada@example.com",
        password: str = "secret-pass",
    ) -> dict[str, str]:
        register_response = client.post(
            "/api/v1/auth/register",
            json={"name": name, "email": email, "password": password},
        )
        assert register_response.status_code == 201

        login_response = client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": password},
        )
        assert login_response.status_code == 200

        token = login_response.json()["access_token"]
        return {"Authorization": f"Bearer {token}"}

    return _auth_headers


@pytest.fixture
def user_factory(client: TestClient, auth_headers):
    counter = 0

    def _user_factory(
        *,
        role_name: str | RoleName = RoleName.AGENTE,
        name: str | None = None,
    ):
        nonlocal counter
        counter += 1

        email = f"user{counter}@example.com"
        user_name = name or f"User {counter}"
        headers = auth_headers(
            name=user_name,
            email=email,
            password="secret-pass",
        )

        session = TestingSessionLocal()
        try:
            user = session.query(User).filter(User.email == email).first()
            role = session.query(Role).filter(Role.name == role_name).first()

            assert user is not None
            assert role is not None

            user.role = role
            session.commit()
            session.refresh(user)

            return {
                "id": user.id,
                "name": user.name,
                "email": user.email,
                "role": role.name,
                "headers": headers,
            }
        finally:
            session.close()

    return _user_factory
