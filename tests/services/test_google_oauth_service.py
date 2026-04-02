"""Unit tests for GoogleOAuthService id_token validation.

Tests JWKS fetching, caching, and id_token validation including:
- fetch_jwks success/failure/cache behavior
- validate_id_token with valid/expired/invalid tokens
- Backward compatibility (fail-open behavior)
"""

import time
import pytest
from unittest.mock import Mock, patch, MagicMock
from sqlalchemy.orm import Session

from jwcrypto import jwk, jwt

from app.services.google_oauth_service import (
    GoogleOAuthService,
    _jwks_cache,
    _jwks_cache_timestamp,
)
from app.core.config import config
from tests.test_db import TestingSessionLocal


# ==============================================================================
# JWKS Test Fixtures and Helpers
# ==============================================================================


def create_test_rsa_key(kid: str = "test-key-id") -> tuple[jwk.JWK, jwk.JWK]:
    """Create a test RSA key pair. Returns (private_key, public_key)."""
    private_key = jwk.JWK.generate(kty="RSA", size=2048, kid=kid)
    public_key = jwk.JWK.from_json(private_key.export(private_key=False))
    return private_key, public_key


def create_test_jwks(public_key: jwk.JWK, kid: str = "test-key-id") -> dict:
    """Create a JWKS dict from a public key."""
    import json

    # Export public key as JSON and parse to get n, e values
    public_json = json.loads(public_key.export_public())
    return {
        "keys": [
            {
                "kty": "RSA",
                "kid": kid,
                "n": public_json["n"],
                "e": public_json["e"],
                "use": "sig",
                "alg": "RS256",
            }
        ]
    }


def sign_id_token(
    private_key: jwk.JWK,
    kid: str,
    email: str,
    sub: str,
    issuer: str = "https://accounts.google.com",
    audience: str = None,
    expiration: int = None,
) -> str:
    """Create a signed id_token with specified claims."""
    if audience is None:
        audience = config.google_client_id
    if expiration is None:
        expiration = int(time.time()) + 3600  # 1 hour from now

    claims = {
        "iss": issuer,
        "aud": audience,
        "email": email,
        "sub": sub,
        "exp": expiration,
        "iat": int(time.time()) - 60,  # issued 1 minute ago
    }

    token = jwt.JWT(
        header={"kid": kid, "alg": "RS256"},
        claims=claims,
    )
    token.make_signed_token(private_key)
    return token.serialize()


# ==============================================================================
# Test Class: fetch_jwks
# ==============================================================================


class TestFetchJwks:
    """Unit tests for GoogleOAuthService.fetch_jwks method."""

    @pytest.fixture
    def session(self):
        """Create a test database session."""
        session = TestingSessionLocal()
        try:
            yield session
        finally:
            session.close()

    @pytest.fixture
    def service(self, session: Session) -> GoogleOAuthService:
        """Create a GoogleOAuthService instance with test session."""
        return GoogleOAuthService(session=session)

    @pytest.fixture(autouse=True)
    def reset_jwks_cache(self):
        """Reset the JWKS cache before each test."""
        import app.services.google_oauth_service as google_module

        google_module._jwks_cache = None
        google_module._jwks_cache_timestamp = 0
        yield
        google_module._jwks_cache = None
        google_module._jwks_cache_timestamp = 0

    def test_fetch_jwks_returns_keys_on_success(self, service: GoogleOAuthService):
        """Test 5.1: fetch_jwks returns keys on success."""
        _, public_key = create_test_rsa_key()
        mock_jwks = create_test_jwks(public_key)

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_jwks

        with patch("httpx.get") as mock_get:
            mock_get.return_value.__enter__ = Mock(return_value=mock_response)
            mock_get.return_value.__exit__ = Mock(return_value=False)

            result = service.fetch_jwks()

        assert result is not None
        assert "keys" in result
        assert len(result["keys"]) == 1
        assert result["keys"][0]["kid"] == "test-key-id"

    def test_fetch_jwks_returns_stale_cache_on_network_failure(
        self, service: GoogleOAuthService
    ):
        """Test 5.2: fetch_jwks returns stale cache on network failure."""
        import app.services.google_oauth_service as google_module

        # Pre-populate cache with stale keys
        _, public_key = create_test_rsa_key()
        stale_jwks = create_test_jwks(public_key)
        google_module._jwks_cache = stale_jwks
        google_module._jwks_cache_timestamp = time.time() - 7200  # 2 hours old

        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"

        with patch("httpx.get") as mock_get:
            mock_get.return_value.__enter__ = Mock(return_value=mock_response)
            mock_get.return_value.__exit__ = Mock(return_value=False)

            result = service.fetch_jwks()

        # Should return stale cache when network fails
        assert result is not None
        assert result == stale_jwks

    def test_fetch_jwks_respects_cache_ttl(self, service: GoogleOAuthService):
        """Test 5.3: fetch_jwks respects cache TTL (returns cached keys within TTL)."""
        import app.services.google_oauth_service as google_module

        # Pre-populate cache
        _, public_key = create_test_rsa_key()
        cached_jwks = create_test_jwks(public_key, kid="cached-key")
        google_module._jwks_cache = cached_jwks
        google_module._jwks_cache_timestamp = time.time() - 1800  # 30 minutes old

        # Create fresh keys that would be returned on a new fetch
        _, fresh_public_key = create_test_rsa_key()
        fresh_jwks = create_test_jwks(fresh_public_key, kid="fresh-key")

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = fresh_jwks

        with patch("httpx.get") as mock_get:
            mock_get.return_value.__enter__ = Mock(return_value=mock_response)
            mock_get.return_value.__exit__ = Mock(return_value=False)

            result = service.fetch_jwks()

        # Should return cached keys, not fresh ones (TTL is 1 hour = 3600s)
        assert result is not None
        assert result["keys"][0]["kid"] == "cached-key"

    def test_fetch_jwks_returns_none_when_cache_empty_and_network_fails(
        self, service: GoogleOAuthService
    ):
        """Test: fetch_jwks returns None when no cache and network fails."""
        import app.services.google_oauth_service as google_module

        # Ensure no cache
        google_module._jwks_cache = None
        google_module._jwks_cache_timestamp = 0

        with patch("httpx.get") as mock_get:
            mock_get.side_effect = Exception("Network error")

            result = service.fetch_jwks()

        # Should return None when no cache available
        assert result is None

    def test_fetch_jwks_timeout_returns_stale_cache(self, service: GoogleOAuthService):
        """Test: fetch_jwks returns stale cache on timeout."""
        import app.services.google_oauth_service as google_module
        import httpx

        # Pre-populate cache
        _, public_key = create_test_rsa_key()
        stale_jwks = create_test_jwks(public_key)
        google_module._jwks_cache = stale_jwks
        google_module._jwks_cache_timestamp = (
            time.time() - 100
        )  # recent but still fresh

        with patch("httpx.get") as mock_get:
            mock_get.side_effect = httpx.TimeoutException("Request timed out")

            result = service.fetch_jwks()

        # Should return stale cache on timeout
        assert result is not None
        assert result == stale_jwks


# ==============================================================================
# Test Class: validate_id_token
# ==============================================================================


class TestValidateIdToken:
    """Unit tests for GoogleOAuthService.validate_id_token method."""

    @pytest.fixture
    def session(self):
        """Create a test database session."""
        session = TestingSessionLocal()
        try:
            yield session
        finally:
            session.close()

    @pytest.fixture
    def service(self, session: Session) -> GoogleOAuthService:
        """Create a GoogleOAuthService instance with test session."""
        return GoogleOAuthService(session=session)

    @pytest.fixture(autouse=True)
    def reset_jwks_cache(self):
        """Reset the JWKS cache before each test."""
        import app.services.google_oauth_service as google_module

        google_module._jwks_cache = None
        google_module._jwks_cache_timestamp = 0
        yield
        google_module._jwks_cache = None
        google_module._jwks_cache_timestamp = 0

    @pytest.fixture
    def valid_jwks(self):
        """Create a valid JWKS with test keys."""
        private_key, public_key = create_test_rsa_key(kid="valid-key-id")
        return create_test_jwks(public_key, kid="valid-key-id"), private_key

    def test_validate_id_token_accepts_valid_token(
        self, service: GoogleOAuthService, valid_jwks
    ):
        """Test 5.4: validate_id_token accepts valid token."""
        mock_jwks, private_key = valid_jwks

        # Create a valid id_token
        valid_token = sign_id_token(
            private_key=private_key,
            kid="valid-key-id",
            email="test@example.com",
            sub="google-123",
        )

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_jwks

        with patch("httpx.get") as mock_get:
            mock_get.return_value.__enter__ = Mock(return_value=mock_response)
            mock_get.return_value.__exit__ = Mock(return_value=False)

            result = service.validate_id_token(valid_token)

        assert result is not None
        email, sub = result
        assert email == "test@example.com"
        assert sub == "google-123"

    def test_validate_id_token_rejects_expired_token(
        self, service: GoogleOAuthService, valid_jwks
    ):
        """Test 5.5: validate_id_token rejects expired token."""
        mock_jwks, private_key = valid_jwks

        # Create an expired token (expired 1 hour ago)
        expired_token = sign_id_token(
            private_key=private_key,
            kid="valid-key-id",
            email="test@example.com",
            sub="google-123",
            expiration=int(time.time()) - 3600,
        )

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_jwks

        with patch("httpx.get") as mock_get:
            mock_get.return_value.__enter__ = Mock(return_value=mock_response)
            mock_get.return_value.__exit__ = Mock(return_value=False)

            result = service.validate_id_token(expired_token)

        # Should return None for expired token (fail-open)
        assert result is None

    def test_validate_id_token_rejects_wrong_issuer(
        self, service: GoogleOAuthService, valid_jwks
    ):
        """Test 5.6: validate_id_token rejects wrong issuer."""
        mock_jwks, private_key = valid_jwks

        # Create token with wrong issuer
        wrong_issuer_token = sign_id_token(
            private_key=private_key,
            kid="valid-key-id",
            email="test@example.com",
            sub="google-123",
            issuer="https://evil.google.com",
        )

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_jwks

        with patch("httpx.get") as mock_get:
            mock_get.return_value.__enter__ = Mock(return_value=mock_response)
            mock_get.return_value.__exit__ = Mock(return_value=False)

            result = service.validate_id_token(wrong_issuer_token)

        # Should return None for wrong issuer (fail-open)
        assert result is None

    def test_validate_id_token_rejects_wrong_audience(
        self, service: GoogleOAuthService, valid_jwks
    ):
        """Test 5.7: validate_id_token rejects wrong audience."""
        mock_jwks, private_key = valid_jwks

        # Create token with wrong audience
        wrong_audience_token = sign_id_token(
            private_key=private_key,
            kid="valid-key-id",
            email="test@example.com",
            sub="google-123",
            audience="wrong-client-id.apps.googleusercontent.com",
        )

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_jwks

        with patch("httpx.get") as mock_get:
            mock_get.return_value.__enter__ = Mock(return_value=mock_response)
            mock_get.return_value.__exit__ = Mock(return_value=False)

            result = service.validate_id_token(wrong_audience_token)

        # Should return None for wrong audience (fail-open)
        assert result is None

    def test_validate_id_token_rejects_tampered_signature(
        self, service: GoogleOAuthService, valid_jwks
    ):
        """Test 5.8: validate_id_token rejects tampered signature."""
        mock_jwks, private_key = valid_jwks

        # Create a valid token
        valid_token = sign_id_token(
            private_key=private_key,
            kid="valid-key-id",
            email="test@example.com",
            sub="google-123",
        )

        # Tamper with the signature (change last character)
        parts = valid_token.rsplit(".", 1)
        tampered_signature = parts[1][:-1] + ("X" if parts[1][-1] != "X" else "Y")
        tampered_token = f"{parts[0]}.{tampered_signature}"

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_jwks

        with patch("httpx.get") as mock_get:
            mock_get.return_value.__enter__ = Mock(return_value=mock_response)
            mock_get.return_value.__exit__ = Mock(return_value=False)

            result = service.validate_id_token(tampered_token)

        # Should return None for tampered token (fail-open)
        assert result is None

    def test_validate_id_token_returns_none_on_any_validation_failure(
        self, service: GoogleOAuthService
    ):
        """Test 5.9: validate_id_token returns None on any validation failure (fail-open)."""
        # Test cases that should all return None
        failure_cases = [
            ("missing kid", self._create_token_without_kid()),
            ("missing email", self._create_token_without_email()),
            ("missing sub", self._create_token_without_sub()),
        ]

        for case_name, token in failure_cases:
            # Reset cache
            import app.services.google_oauth_service as google_module

            google_module._jwks_cache = None
            google_module._jwks_cache_timestamp = 0

            _, public_key = create_test_rsa_key(kid="valid-key-id")
            mock_jwks = create_test_jwks(public_key, kid="valid-key-id")

            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = mock_jwks

            with patch("httpx.get") as mock_get:
                mock_get.return_value.__enter__ = Mock(return_value=mock_response)
                mock_get.return_value.__exit__ = Mock(return_value=False)

                result = service.validate_id_token(token)

            assert result is None, f"Expected None for case: {case_name}"

    def _create_token_without_kid(self) -> str:
        """Helper: Create a token without kid in header."""
        private_key, _ = create_test_rsa_key()
        claims = {
            "iss": "https://accounts.google.com",
            "aud": config.google_client_id,
            "email": "test@example.com",
            "sub": "google-123",
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()) - 60,
        }
        token = jwt.JWT(
            header={"alg": "RS256"},  # No kid
            claims=claims,
        )
        token.make_signed_token(private_key)
        return token.serialize()

    def _create_token_without_email(self) -> str:
        """Helper: Create a token without email claim."""
        private_key, public_key = create_test_rsa_key(kid="valid-key-id")
        claims = {
            "iss": "https://accounts.google.com",
            "aud": config.google_client_id,
            "sub": "google-123",
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()) - 60,
        }
        token = jwt.JWT(
            header={"kid": "valid-key-id", "alg": "RS256"},
            claims=claims,
        )
        token.make_signed_token(private_key)
        return token.serialize()

    def _create_token_without_sub(self) -> str:
        """Helper: Create a token without sub claim."""
        private_key, public_key = create_test_rsa_key(kid="valid-key-id")
        claims = {
            "iss": "https://accounts.google.com",
            "aud": config.google_client_id,
            "email": "test@example.com",
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()) - 60,
        }
        token = jwt.JWT(
            header={"kid": "valid-key-id", "alg": "RS256"},
            claims=claims,
        )
        token.make_signed_token(private_key)
        return token.serialize()

    def test_validate_id_token_returns_none_when_jwks_unavailable(
        self, service: GoogleOAuthService
    ):
        """Test: validate_id_token returns None when JWKS fetch fails (fail-open)."""
        import app.services.google_oauth_service as google_module

        google_module._jwks_cache = None

        with patch("httpx.get") as mock_get:
            mock_get.side_effect = Exception("Network error")

            result = service.validate_id_token("some-token")

        # Should return None, not raise
        assert result is None

    def test_validate_id_token_returns_none_when_kid_not_in_jwks(
        self, service: GoogleOAuthService
    ):
        """Test: validate_id_token returns None when token's kid is not in JWKS."""
        # Create a JWKS with a different key
        _, public_key = create_test_rsa_key(kid="other-key-id")
        mock_jwks = create_test_jwks(public_key, kid="other-key-id")

        # Create token signed with a key whose kid is NOT in JWKS
        wrong_private_key, _ = create_test_rsa_key(kid="missing-key-id")
        token = sign_id_token(
            private_key=wrong_private_key,
            kid="missing-key-id",
            email="test@example.com",
            sub="google-123",
        )

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_jwks

        with patch("httpx.get") as mock_get:
            mock_get.return_value.__enter__ = Mock(return_value=mock_response)
            mock_get.return_value.__exit__ = Mock(return_value=False)

            result = service.validate_id_token(token)

        assert result is None


# ==============================================================================
# Test Class: Backward Compatibility
# ==============================================================================


class TestBackwardCompatibility:
    """Tests for backward compatibility of id_token validation."""

    @pytest.fixture
    def session(self):
        """Create a test database session."""
        session = TestingSessionLocal()
        try:
            yield session
        finally:
            session.close()

    @pytest.fixture
    def service(self, session: Session) -> GoogleOAuthService:
        """Create a GoogleOAuthService instance with test session."""
        return GoogleOAuthService(session=session)

    @pytest.fixture(autouse=True)
    def reset_jwks_cache(self):
        """Reset the JWKS cache before each test."""
        import app.services.google_oauth_service as google_module

        google_module._jwks_cache = None
        google_module._jwks_cache_timestamp = 0
        yield
        google_module._jwks_cache = None
        google_module._jwks_cache_timestamp = 0

    def test_validate_id_token_never_raises(self, service: GoogleOAuthService):
        """Test: validate_id_token never raises exceptions (fail-open)."""
        # Test various invalid inputs
        invalid_inputs = [
            None,
            "",
            "not.a.valid.jwt",
            "definitely.tampered.signature",
        ]

        for invalid_input in invalid_inputs:
            try:
                result = service.validate_id_token(invalid_input)
                # Should return None, not raise
                assert result is None or isinstance(result, tuple)
            except Exception as e:
                pytest.fail(
                    f"validate_id_token raised {type(e).__name__} for input: {invalid_input}"
                )
