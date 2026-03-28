from datetime import timedelta

import pytest

from app.core.security import (
    InvalidTokenError,
    create_refresh_token,
    decode_refresh_token,
)


class TestCreateRefreshToken:
    def test_create_refresh_token_returns_valid_jwt(self):
        """Test that create_refresh_token returns a valid JWT with refresh claims."""
        token = create_refresh_token(subject="user123")

        # Token should have 3 parts (header.payload.signature)
        parts = token.split(".")
        assert len(parts) == 3

        # Decode and verify claims
        payload = decode_refresh_token(token)
        assert payload["sub"] == "user123"
        assert payload["typ"] == "refresh"
        assert "jti" in payload
        assert "exp" in payload

    def test_create_refresh_token_with_custom_expiration(self):
        """Test that custom expiration is respected."""
        custom_delta = timedelta(days=14)
        token = create_refresh_token(subject="user123", expires_delta=custom_delta)

        payload = decode_refresh_token(token)
        # The expiration should be approximately 14 days from now
        from datetime import datetime, timezone
        import time

        expected_exp = int((datetime.now(timezone.utc) + custom_delta).timestamp())
        # Allow 1 second tolerance
        assert abs(payload["exp"] - expected_exp) < 2

    def test_create_refresh_token_includes_jti(self):
        """Test that refresh token includes jti (JWT ID) for rotation tracking."""
        token = create_refresh_token(subject="user123")
        payload = decode_refresh_token(token)

        assert "jti" in payload
        assert len(payload["jti"]) > 0  # Should be a non-empty string (UUID hex)


class TestDecodeRefreshToken:
    def test_decode_refresh_token_validates_signature(self):
        """Test that decode_refresh_token validates the signature correctly."""
        token = create_refresh_token(subject="user123")

        # Tamper with the token
        tampered_token = token[:-5] + "xxxxx"

        with pytest.raises(InvalidTokenError):
            decode_refresh_token(tampered_token)

    def test_decode_refresh_token_rejects_expired_token(self):
        """Test that decode_refresh_token raises ExpiredTokenError for expired tokens."""
        # Create an already-expired token
        expired_token = create_refresh_token(
            subject="user123",
            expires_delta=timedelta(minutes=-1),
        )

        from app.core.security import ExpiredTokenError

        with pytest.raises(ExpiredTokenError) as exc_info:
            decode_refresh_token(expired_token)
        assert "ha expirado" in str(exc_info.value)

    def test_decode_refresh_token_rejects_invalid_typ_claim(self):
        """Test that decode_refresh_token rejects tokens without typ='refresh'."""
        # Create a regular access token and try to use it as refresh
        from app.core.security import create_access_token

        access_token = create_access_token(subject="user123")

        # Should fail because typ is not "refresh"
        with pytest.raises(InvalidTokenError):
            decode_refresh_token(access_token)

    def test_decode_refresh_token_rejects_malformed_token(self):
        """Test that decode_refresh_token rejects malformed tokens."""
        with pytest.raises(InvalidTokenError):
            decode_refresh_token("not-a-valid-jwt")

    def test_decode_refresh_token_rejects_empty_token(self):
        """Test that decode_refresh_token rejects empty tokens."""
        with pytest.raises(InvalidTokenError):
            decode_refresh_token("")

    def test_decode_refresh_token_accepts_valid_refresh_token(self):
        """Test that a valid refresh token is accepted."""
        token = create_refresh_token(subject="user123")

        # Should not raise any exception
        payload = decode_refresh_token(token)

        assert payload["sub"] == "user123"
        assert payload["typ"] == "refresh"
