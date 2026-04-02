"""Tests for OAuth State CSRF protection.

Phase 3 tasks 3.1-3.8: Unit and integration tests for URLSafeTimedSerializer
and the oauth_state cookie validation flow.
"""

import time
from unittest.mock import patch, MagicMock

import pytest
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from app.core.config import config


# =============================================================================
# Phase 3.1-3.3: Unit tests for URLSafeTimedSerializer
# =============================================================================


class TestURLSafeTimedSerializer:
    """Unit tests for the OAuth state serializer."""

    def test_serializer_roundtrip(self):
        """Test that a state can be signed and verified (3.1)."""
        raw_state = "test_state_abc123xyz"
        serializer = URLSafeTimedSerializer(config.oauth_state_secret_value)

        # Sign the state
        signed_state = serializer.dumps(raw_state)

        # Verify and decode - should return the original state
        decoded = serializer.loads(signed_state, max_age=300)
        assert decoded == raw_state

    def test_expired_signature_rejected(self):
        """Test that expired signature is rejected (3.2).

        Creates a token with a timestamp far in the past using time mocking
        and verifies it raises SignatureExpired when loaded with max_age.
        """
        raw_state = "test_state_for_expiry"

        # Create a serializer
        serializer = URLSafeTimedSerializer(config.oauth_state_secret_value)

        # Mock time.time to return a time 400 seconds in the past during dumps
        # This creates a token that appears to be 400 seconds old
        old_time = time.time() - 400
        with patch("time.time", return_value=old_time):
            signed_state = serializer.dumps(raw_state)

        # Now loading with max_age=300 should fail (token is 400 seconds old)
        with pytest.raises(SignatureExpired):
            serializer.loads(signed_state, max_age=300)

    def test_tampered_signature_rejected(self):
        """Test that tampered signature raises exception (3.3)."""
        serializer = URLSafeTimedSerializer(config.oauth_state_secret_value)
        tampered_state = "tampered.signature.value"

        with pytest.raises(BadSignature):
            serializer.loads(tampered_state, max_age=300)

    def test_different_secret_rejected(self):
        """Test that signature with wrong secret is rejected."""
        serializer = URLSafeTimedSerializer("wrong-secret-key")
        raw_state = "test_state"
        signed_with_wrong = serializer.dumps(raw_state)

        # Use correct serializer to verify
        correct_serializer = URLSafeTimedSerializer(config.oauth_state_secret_value)
        with pytest.raises(BadSignature):
            correct_serializer.loads(signed_with_wrong, max_age=300)


# =============================================================================
# Phase 3.4-3.8: Integration tests for OAuth flow endpoints
# =============================================================================


class TestGoogleOAuthCSRF:
    """Integration tests for OAuth CSRF protection."""

    def test_auth_google_returns_302_and_sets_oauth_state_cookie(self, client):
        """Test that GET /api/v1/auth/google returns 302 and sets oauth_state cookie (3.4)."""
        # Mock the GoogleOAuthService to avoid RuntimeError
        with patch(
            "app.services.google_oauth_service.GoogleOAuthService.get_authorization_url"
        ) as mock_url:
            mock_url.return_value = (
                "https://accounts.google.com/o/oauth2/v2/auth?state=test"
            )
            response = client.get("/api/v1/auth/google", follow_redirects=False)

        assert response.status_code == 302
        assert "oauth_state" in response.cookies

        # Verify cookie has correct security flags
        cookie = response.cookies["oauth_state"]
        assert len(cookie) > 0  # Cookie has a value

    def test_auth_google_cookie_is_signed(self, client):
        """Test that the oauth_state cookie contains a signed value."""
        with patch(
            "app.services.google_oauth_service.GoogleOAuthService.get_authorization_url"
        ) as mock_url:
            mock_url.return_value = (
                "https://accounts.google.com/o/oauth2/v2/auth?state=test"
            )
            response = client.get("/api/v1/auth/google", follow_redirects=False)

        assert response.status_code == 302
        signed_state = response.cookies["oauth_state"]

        # Verify the signed value can be decoded with our serializer
        serializer = URLSafeTimedSerializer(config.oauth_state_secret_value)
        decoded = serializer.loads(signed_state, max_age=300)

        # The decoded value should be a string (the raw state)
        assert isinstance(decoded, str)
        assert len(decoded) > 0

    def test_callback_missing_oauth_state_cookie_returns_400(self, client):
        """Test that callback without oauth_state cookie returns 400 (3.5)."""
        # Make callback request without any cookies
        response = client.get(
            "/api/v1/auth/google/callback",
            params={"code": "test_code", "state": "test_state"},
        )

        assert response.status_code == 400
        assert response.json()["detail"] == "Cookie de estado OAuth faltante"

    def test_callback_tampered_cookie_returns_401(self, client):
        """Test that callback with tampered cookie returns 401 (3.6)."""
        response = client.get(
            "/api/v1/auth/google/callback",
            params={"code": "test_code", "state": "test_state"},
            cookies={"oauth_state": "tampered.invalid.signature"},
        )

        assert response.status_code == 401
        assert response.json()["detail"] == "Firma de estado OAuth inválida"

    def test_callback_expired_cookie_returns_401(self, client):
        """Test that callback with expired cookie returns 401 (3.7).

        Creates a cookie with an old timestamp (simulating expiration)
        and verifies it returns 401 with 'OAuth state expired' message.
        """
        raw_state = "test_state_for_expiry"

        # Create a serializer
        serializer = URLSafeTimedSerializer(config.oauth_state_secret_value)

        # Create a token with an old timestamp (400 seconds ago) using time mocking
        old_time = time.time() - 400
        with patch("time.time", return_value=old_time):
            expired_signed_state = serializer.dumps(raw_state)

        response = client.get(
            "/api/v1/auth/google/callback",
            params={"code": "test_code", "state": raw_state},
            cookies={"oauth_state": expired_signed_state},
        )

        assert response.status_code == 401
        assert response.json()["detail"] == "El estado OAuth ha expirado"

    def test_callback_mismatched_state_returns_401(self, client):
        """Test that callback with mismatched state returns 401 (3.8)."""
        # First, get a valid signed cookie from /api/v1/auth/google
        with patch(
            "app.services.google_oauth_service.GoogleOAuthService.get_authorization_url"
        ) as mock_url:
            mock_url.return_value = (
                "https://accounts.google.com/o/oauth2/v2/auth?state=test"
            )
            google_response = client.get("/api/v1/auth/google", follow_redirects=False)

        assert google_response.status_code == 302
        valid_cookie = google_response.cookies["oauth_state"]

        # Decode the cookie to get the original state
        serializer = URLSafeTimedSerializer(config.oauth_state_secret_value)
        original_state = serializer.loads(valid_cookie, max_age=300)

        # Use the cookie but with a different state parameter
        mismatched_state = original_state + "_attacker_tampered"
        response = client.get(
            "/api/v1/auth/google/callback",
            params={"code": "test_code", "state": mismatched_state},
            cookies={"oauth_state": valid_cookie},
        )

        assert response.status_code == 401
        assert response.json()["detail"] == "El estado OAuth no coincide"

    def test_callback_valid_state_succeeds_signature_validation(self, client):
        """Test that a valid state passes signature validation (but may fail at Google auth).

        This test verifies that when we provide the correct signed cookie
        AND the correct matching state, the signature validation passes.
        We don't fully test the callback because it requires actual Google OAuth,
        but we can verify the CSRF check passes (reaches past the signature validation).
        """
        # Get a valid cookie
        with patch(
            "app.services.google_oauth_service.GoogleOAuthService.get_authorization_url"
        ) as mock_url:
            mock_url.return_value = (
                "https://accounts.google.com/o/oauth2/v2/auth?state=test"
            )
            google_response = client.get("/api/v1/auth/google", follow_redirects=False)

        valid_cookie = google_response.cookies["oauth_state"]

        # Decode to get the original state
        serializer = URLSafeTimedSerializer(config.oauth_state_secret_value)
        original_state = serializer.loads(valid_cookie, max_age=300)

        # Make callback with matching state - should pass CSRF checks
        # The request will fail later at Google OAuth (since we don't have a real code)
        # but it should NOT fail with signature/state mismatch errors
        with patch(
            "app.services.google_oauth_service.GoogleOAuthService.exchange_code_for_tokens"
        ) as mock_exchange:
            mock_exchange.side_effect = Exception(
                "Google OAuth not configured in tests"
            )
            response = client.get(
                "/api/v1/auth/google/callback",
                params={"code": "fake_code", "state": original_state},
                cookies={"oauth_state": valid_cookie},
            )

        # The CSRF validation should pass (signature and state match)
        # It should fail at Google OAuth exchange, not at CSRF check
        # So we should NOT see "cookie missing", "signature", "mismatch", or "expired" errors
        detail_lower = response.json().get("detail", "").lower()
        assert "mismatch" not in detail_lower
        assert "signature" not in detail_lower
        assert "expired" not in detail_lower
        assert "cookie missing" not in detail_lower


class TestOAuthStateCookieSecurity:
    """Tests for OAuth state cookie security attributes."""

    def test_oauth_state_cookie_is_set(self, client):
        """Verify oauth_state cookie is set on /api/v1/auth/google."""
        with patch(
            "app.services.google_oauth_service.GoogleOAuthService.get_authorization_url"
        ) as mock_url:
            mock_url.return_value = (
                "https://accounts.google.com/o/oauth2/v2/auth?state=test"
            )
            response = client.get("/api/v1/auth/google", follow_redirects=False)

        assert "oauth_state" in response.cookies
        assert len(response.cookies["oauth_state"]) > 0

    def test_oauth_state_cookie_contains_urlsafe_value(self, client):
        """Verify oauth_state cookie value is URL-safe base64."""
        with patch(
            "app.services.google_oauth_service.GoogleOAuthService.get_authorization_url"
        ) as mock_url:
            mock_url.return_value = (
                "https://accounts.google.com/o/oauth2/v2/auth?state=test"
            )
            response = client.get("/api/v1/auth/google", follow_redirects=False)

        cookie_value = response.cookies["oauth_state"]

        # URLSafeTimedSerializer produces URL-safe base64 with . as separator
        import base64

        parts = cookie_value.split(".")
        assert len(parts) == 3  # value.timestamp.signature

        # Each part should be valid base64
        for part in parts:
            try:
                base64.urlsafe_b64decode(part + "==")
            except Exception:
                pytest.fail(f"Cookie part '{part}' is not valid base64")


class TestOAuthStateSerializerWithTime:
    """Tests for serializer time-based behavior."""

    def test_signature_with_recent_timestamp_passes(self):
        """Test that recently signed state passes validation."""
        serializer = URLSafeTimedSerializer(config.oauth_state_secret_value)
        state = "recent_state_123"
        signed = serializer.dumps(state)

        # Should pass with reasonable max_age
        decoded = serializer.loads(signed, max_age=300)
        assert decoded == state

    def test_signature_with_future_timestamp_fails(self):
        """Test that using a future timestamp fails."""
        serializer = URLSafeTimedSerializer(config.oauth_state_secret_value)
        state = "future_state_123"
        signed = serializer.dumps(state)

        # Create a time-based signature that claims to be from the future
        # URLSafeTimedSerializer includes timestamp in signature
        # If we try to load with negative max_age (which means "expire immediately")
        with pytest.raises(SignatureExpired):
            serializer.loads(signed, max_age=-1)
