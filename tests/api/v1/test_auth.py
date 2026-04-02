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


def test_verify_email_with_valid_token(client):
    """Test that verify_email endpoint works with valid token."""
    from app.core.security import create_email_verification_token
    from app.db.schema import User
    from tests.test_db import TestingSessionLocal

    # Register a user first
    client.post(
        "/api/v1/auth/register",
        json={
            "name": "Ada",
            "email": "ada@example.com",
            "password": "secret-pass",
        },
    )

    # Get the user ID
    session = TestingSessionLocal()
    try:
        user = session.query(User).filter(User.email == "ada@example.com").first()
        user_id = user.id
    finally:
        session.close()

    # Create a valid verification token
    token = create_email_verification_token(subject=str(user_id))

    # Verify email
    response = client.post(
        "/api/v1/auth/verify-email",
        json={"token": token},
    )

    assert response.status_code == 200
    assert response.json() == {"message": "Email verificado exitosamente"}

    # Verify user is marked as verified in DB
    session = TestingSessionLocal()
    try:
        user = session.query(User).filter(User.email == "ada@example.com").first()
        assert user.email_verified is True
    finally:
        session.close()


def test_verify_email_with_invalid_token(client):
    """Test that verify_email endpoint returns 400 for invalid token."""
    response = client.post(
        "/api/v1/auth/verify-email",
        json={"token": "invalid.token.value"},
    )

    assert response.status_code == 400
    assert "inválido" in response.json()["detail"].lower()


def test_verify_email_with_expired_token(client):
    """Test that verify_email endpoint returns 400 for expired token."""
    from datetime import timedelta
    from app.core.security import create_email_verification_token

    # Create an expired token
    expired_token = create_email_verification_token(
        subject="1",
        expires_delta=timedelta(minutes=-1),
    )

    response = client.post(
        "/api/v1/auth/verify-email",
        json={"token": expired_token},
    )

    assert response.status_code == 400
    assert "expirado" in response.json()["detail"].lower()


def test_resend_verification_returns_generic_message_no_token(client):
    """Test that resend_verification endpoint returns generic message, NOT a token.

    SECURITY: The verification token must NEVER be exposed in the HTTP response.
    It should only be sent via email or logged server-side in dev mode.
    """
    # Register a user first
    client.post(
        "/api/v1/auth/register",
        json={
            "name": "Ada",
            "email": "ada@example.com",
            "password": "secret-pass",
        },
    )

    # Request resend verification
    response = client.post(
        "/api/v1/auth/resend-verification",
        json={"email": "ada@example.com"},
    )

    assert response.status_code == 200
    data = response.json()

    # Security: token MUST NOT be in response
    assert "verification_token" not in data
    assert "token" not in data

    # Should return generic success message
    assert "message" in data
    assert "Si el correo existe" in data["message"]


def test_resend_verification_for_nonexistent_email(client):
    """Test that resend_verification returns generic message for non-existent email."""
    response = client.post(
        "/api/v1/auth/resend-verification",
        json={"email": "nonexistent@example.com"},
    )

    assert response.status_code == 200
    # Should return a generic message, not reveal that email doesn't exist
    assert (
        "verification_token" not in response.json()
        or response.json().get("verification_token") is None
    )


def test_resend_verification_for_already_verified_email(client):
    """Test that resend_verification returns generic message for already verified email."""
    from app.core.security import create_email_verification_token
    from app.db.schema import User
    from tests.test_db import TestingSessionLocal

    # Register and verify user first
    client.post(
        "/api/v1/auth/register",
        json={
            "name": "Ada",
            "email": "ada@example.com",
            "password": "secret-pass",
        },
    )

    # Get user ID and verify manually
    session = TestingSessionLocal()
    try:
        user = session.query(User).filter(User.email == "ada@example.com").first()
        user_id = user.id
        token = create_email_verification_token(subject=str(user_id))
        # Mark as verified directly in DB (simulating previous verification)
        user.email_verified = True
        session.commit()
    finally:
        session.close()

    # Now try to resend verification
    response = client.post(
        "/api/v1/auth/resend-verification",
        json={"email": "ada@example.com"},
    )

    assert response.status_code == 200
    # Should return generic message, not a new token
    assert (
        "verification_token" not in response.json()
        or response.json().get("verification_token") is None
    )


def test_resend_verification_integration_no_token_in_response(client, caplog):
    """Test 4.5: Integration test - POST /resend-verification returns 200 with generic message (no token).

    This test verifies the secure behavior at the integration level using TestClient.
    The token must be logged server-side but NEVER appear in the HTTP response.
    """
    import logging

    caplog.set_level(logging.INFO)

    # Register a user
    client.post(
        "/api/v1/auth/register",
        json={
            "name": "Integration Test",
            "email": "integration@example.com",
            "password": "secret-pass",
        },
    )

    # Resend verification
    response = client.post(
        "/api/v1/auth/resend-verification",
        json={"email": "integration@example.com"},
    )

    # Integration test: HTTP response must be 200 with generic message
    assert response.status_code == 200
    response_data = response.json()

    # Security: NO token in response body
    assert "verification_token" not in response_data
    assert "token" not in response_data
    assert "email" not in response_data

    # Should have generic message
    assert "message" in response_data
    assert "Si el correo existe" in response_data["message"]

    # But token SHOULD be logged server-side (dev mode)
    log_messages = [record.message for record in caplog.records]
    verification_log_found = any(
        "Verification token for integration@example.com" in msg for msg in log_messages
    )
    assert verification_log_found, "Token should be logged server-side in dev mode"


def test_verify_email_flow_integration_with_valid_token(client):
    """Test 4.6: Integration test - verify email flow still works with valid token.

    This test ensures the backward compatibility: existing tokens remain valid
    and the verify-email endpoint works correctly.
    """
    from app.core.security import create_email_verification_token
    from app.db.schema import User
    from tests.test_db import TestingSessionLocal

    # Register user
    client.post(
        "/api/v1/auth/register",
        json={
            "name": "Verify Test",
            "email": "verify@example.com",
            "password": "secret-pass",
        },
    )

    # Get user ID and create valid verification token
    session = TestingSessionLocal()
    try:
        user = session.query(User).filter(User.email == "verify@example.com").first()
        user_id = user.id
        assert user.email_verified is None  # Not verified yet (None means unverified)
    finally:
        session.close()

    # Create valid token
    token = create_email_verification_token(subject=str(user_id))

    # Verify email - should succeed
    verify_response = client.post(
        "/api/v1/auth/verify-email",
        json={"token": token},
    )

    assert verify_response.status_code == 200
    assert verify_response.json() == {"message": "Email verificado exitosamente"}

    # Verify user is now marked as verified in DB
    session = TestingSessionLocal()
    try:
        user = session.query(User).filter(User.email == "verify@example.com").first()
        assert user.email_verified is True
    finally:
        session.close()
