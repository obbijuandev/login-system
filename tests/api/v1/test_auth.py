from datetime import timedelta

from app.core.security import create_access_token
from app.db.schema import RoleName, User
from tests.test_db import TestingSessionLocal


def test_register_creates_user_without_exposing_password_hash(client):
    response = client.post(
        "/api/v1/auth/register",
        json={
            "name": "Ada Lovelace",
            "email": "ADA@example.com",
            "password": "super-secret",
        },
    )

    assert response.status_code == 201
    payload = response.json()
    assert payload == {
        "id": 1,
        "name": "Ada Lovelace",
        "email": "ada@example.com",
        "role": {"id": 2, "name": RoleName.AGENTE},
    }
    assert "password_hash" not in payload

    session = TestingSessionLocal()
    try:
        user = session.query(User).filter(User.email == "ada@example.com").first()
        assert user is not None
        assert user.password_hash is not None
        assert user.password_hash != "super-secret"
        assert user.role is not None
        assert user.role.name == RoleName.AGENTE
    finally:
        session.close()


def test_register_rejects_duplicate_email(client):
    first_response = client.post(
        "/api/v1/auth/register",
        json={"name": "Ada", "email": "ada@example.com", "password": "secret-1"},
    )
    assert first_response.status_code == 201

    second_response = client.post(
        "/api/v1/auth/register",
        json={"name": "Grace", "email": "ADA@example.com", "password": "secret-2"},
    )

    assert second_response.status_code == 409
    assert second_response.json() == {"detail": "El correo electrónico ya existe"}


def test_register_rejects_invalid_email(client):
    response = client.post(
        "/api/v1/auth/register",
        json={
            "name": "Ada",
            "email": "invalid-email",
            "password": "super-secret",
        },
    )

    assert response.status_code == 422
    assert response.json()["detail"][0]["loc"] == ["body", "email"]
    assert (
        response.json()["detail"][0]["msg"]
        == "Dirección de correo electrónico inválida"
    )


def test_register_rejects_weak_password(client):
    response = client.post(
        "/api/v1/auth/register",
        json={
            "name": "Ada",
            "email": "ada@example.com",
            "password": "short",
        },
    )

    assert response.status_code == 422
    assert response.json()["detail"][0]["loc"] == ["body", "password"]
    assert (
        response.json()["detail"][0]["msg"]
        == "La contraseña debe tener al menos 8 caracteres"
    )


def test_register_requires_email_with_spanish_validation_message(client):
    response = client.post(
        "/api/v1/auth/register",
        json={
            "name": "Ada",
            "password": "super-secret",
        },
    )

    assert response.status_code == 422
    assert response.json()["detail"][0]["loc"] == ["body", "email"]
    assert response.json()["detail"][0]["msg"] == "Campo requerido"


def test_login_returns_bearer_token_and_me_returns_authenticated_user(client):
    register_response = client.post(
        "/api/v1/auth/register",
        json={
            "name": "Ada",
            "email": "ada@example.com",
            "password": "secret-pass",
        },
    )
    assert register_response.status_code == 201

    login_response = client.post(
        "/api/v1/auth/login",
        json={"email": "ada@example.com", "password": "secret-pass"},
    )

    assert login_response.status_code == 200
    token_payload = login_response.json()
    assert token_payload["token_type"] == "bearer"
    assert token_payload["access_token"]

    me_response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token_payload['access_token']}"},
    )

    assert me_response.status_code == 200
    assert me_response.json() == {
        "id": 1,
        "name": "Ada",
        "email": "ada@example.com",
        "role": {"id": 2, "name": RoleName.AGENTE},
    }


def test_legacy_user_without_password_hash_cannot_login(client):
    session = TestingSessionLocal()
    try:
        session.add(User(name="Legacy", email="legacy@example.com", password_hash=None))
        session.commit()
    finally:
        session.close()

    response = client.post(
        "/api/v1/auth/login",
        json={"email": "legacy@example.com", "password": "any-password"},
    )

    assert response.status_code == 401
    assert response.json() == {"detail": "Correo electrónico o contraseña inválidos"}


def test_me_requires_bearer_token(client):
    response = client.get("/api/v1/auth/me")

    assert response.status_code == 401
    assert response.json() == {"detail": "Credenciales de autenticación inválidas"}


def test_me_rejects_invalid_token(client):
    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer invalid.token.value"},
    )

    assert response.status_code == 401
    assert response.json() == {"detail": "Credenciales de autenticación inválidas"}


def test_me_rejects_expired_token(client):
    expired_token = create_access_token(
        subject="1",
        expires_delta=timedelta(minutes=-1),
    )

    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {expired_token}"},
    )

    assert response.status_code == 401
    assert response.json() == {"detail": "Credenciales de autenticación inválidas"}


def test_login_returns_both_access_and_refresh_token(client):
    """Test that login returns both access_token and refresh_token."""
    # Register a user
    client.post(
        "/api/v1/auth/register",
        json={
            "name": "Ada",
            "email": "ada@example.com",
            "password": "secret-pass",
        },
    )

    # Login
    login_response = client.post(
        "/api/v1/auth/login",
        json={"email": "ada@example.com", "password": "secret-pass"},
    )

    assert login_response.status_code == 200
    token_payload = login_response.json()

    # Verify both tokens are returned
    assert "access_token" in token_payload
    assert "refresh_token" in token_payload
    assert token_payload["token_type"] == "bearer"
    assert len(token_payload["access_token"]) > 0
    assert len(token_payload["refresh_token"]) > 0


def test_refresh_returns_new_access_and_refresh_token(client):
    """Test that refresh endpoint returns new token pair (rotation)."""
    # Register and login
    client.post(
        "/api/v1/auth/register",
        json={
            "name": "Ada",
            "email": "ada@example.com",
            "password": "secret-pass",
        },
    )

    login_response = client.post(
        "/api/v1/auth/login",
        json={"email": "ada@example.com", "password": "secret-pass"},
    )
    tokens = login_response.json()
    original_refresh_token = tokens["refresh_token"]

    # Refresh tokens
    refresh_response = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": original_refresh_token},
    )

    assert refresh_response.status_code == 200
    new_tokens = refresh_response.json()

    # Verify new tokens are returned
    assert "access_token" in new_tokens
    assert "refresh_token" in new_tokens
    assert len(new_tokens["access_token"]) > 0
    assert len(new_tokens["refresh_token"]) > 0

    # Verify new refresh token is different (rotation)
    assert new_tokens["refresh_token"] != original_refresh_token


def test_refresh_with_expired_token_returns_401(client):
    """Test that refresh with expired token returns 401."""
    # Create an expired refresh token
    from app.core.security import create_refresh_token

    expired_token = create_refresh_token(
        subject="1",
        expires_delta=timedelta(minutes=-1),
    )

    response = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": expired_token},
    )

    assert response.status_code == 401
    assert "expirado" in response.json()["detail"].lower()


def test_refresh_with_invalid_token_returns_401(client):
    """Test that refresh with invalid token returns 401."""
    response = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": "invalid.token.value"},
    )

    assert response.status_code == 401


def test_refresh_with_access_token_returns_401(client):
    """Test that refresh with access token (not refresh token) returns 401."""
    # Register and login to get an access token
    client.post(
        "/api/v1/auth/register",
        json={
            "name": "Ada",
            "email": "ada@example.com",
            "password": "secret-pass",
        },
    )

    login_response = client.post(
        "/api/v1/auth/login",
        json={"email": "ada@example.com", "password": "secret-pass"},
    )
    access_token = login_response.json()["access_token"]

    # Try to use access token as refresh token
    response = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": access_token},
    )

    assert response.status_code == 401


def test_logout_returns_200_with_message(client):
    """Test that logout returns 200 with message."""
    # Register and login
    client.post(
        "/api/v1/auth/register",
        json={
            "name": "Ada",
            "email": "ada@example.com",
            "password": "secret-pass",
        },
    )

    login_response = client.post(
        "/api/v1/auth/login",
        json={"email": "ada@example.com", "password": "secret-pass"},
    )
    refresh_token = login_response.json()["refresh_token"]

    # Logout
    logout_response = client.post(
        "/api/v1/auth/logout",
        json={"refresh_token": refresh_token},
    )

    assert logout_response.status_code == 200
    assert "message" in logout_response.json()
