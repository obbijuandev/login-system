"""Unit tests for AuthService.resend_verification method.

Tests the secure behavior where:
- Token is NEVER exposed in HTTP response
- Email service is called when provided
- Dev mode logs token when email_service is None
- Email service exceptions are handled gracefully
"""

import pytest
from unittest.mock import Mock, MagicMock
from sqlalchemy.orm import Session

from app.services.auth_service import AuthService
from app.db.schema import User, Role, RoleName
from tests.test_db import TestingSessionLocal


class TestResendVerificationUnit:
    """Unit tests for AuthService.resend_verification method."""

    @pytest.fixture
    def session(self):
        """Create a test database session."""
        session = TestingSessionLocal()
        session.query(User).delete()
        session.commit()
        try:
            yield session
        finally:
            session.query(User).delete()
            session.commit()
            session.close()

    @pytest.fixture
    def auth_service(self, session: Session) -> AuthService:
        """Create an AuthService instance with test session."""
        return AuthService(session=session)

    @pytest.fixture
    def unverified_user(self, session: Session) -> User:
        """Create an unverified user for testing."""
        role = session.query(Role).filter(Role.name == RoleName.AGENTE).first()
        user = User(
            name="Test User",
            email="unverified@example.com",
            password_hash="fake_hash",
            role=role,
            email_verified=False,
        )
        session.add(user)
        session.commit()
        session.refresh(user)
        return user

    def test_resend_verification_returns_sent_true_when_email_service_is_none(
        self, auth_service: AuthService, unverified_user: User
    ):
        """Test 4.2: resend_verification returns {"sent": True} when email_service is None (dev mode)."""
        # Call resend_verification without email_service (dev mode)
        result = auth_service.resend_verification(
            email=unverified_user.email, email_service=None
        )

        # Should return {"sent": True}
        assert result == {"sent": True}
        assert "sent" in result
        assert result["sent"] is True
        # Token must NOT be in response
        assert "verification_token" not in result
        assert "token" not in result

    def test_resend_verification_calls_email_service_send_verification_email(
        self, auth_service: AuthService, unverified_user: User
    ):
        """Test 4.3: resend_verification calls email_service.send_verification_email when provided."""
        # Create a mock email service
        mock_email_service = Mock()
        mock_email_service.send_verification_email.return_value = True

        # Call resend_verification with mock email service
        result = auth_service.resend_verification(
            email=unverified_user.email, email_service=mock_email_service
        )

        # Verify email_service.send_verification_email was called
        mock_email_service.send_verification_email.assert_called_once()

        # Verify the call was made with correct email
        call_args = mock_email_service.send_verification_email.call_args
        assert call_args[0][0] == unverified_user.email  # First positional arg is email

        # Verify return value
        assert result == {"sent": True}
        # Token must NOT be in response
        assert "verification_token" not in result
        assert "token" not in result

    def test_resend_verification_calls_email_service_with_correct_token(
        self, auth_service: AuthService, unverified_user: User
    ):
        """Test 4.3 (extended): Verify the token passed to email service is valid."""
        mock_email_service = Mock()
        mock_email_service.send_verification_email.return_value = True

        # Call resend_verification
        result = auth_service.resend_verification(
            email=unverified_user.email, email_service=mock_email_service
        )

        # Get the token that was passed to the email service
        call_args = mock_email_service.send_verification_email.call_args
        token_passed = call_args[0][1]  # Second positional arg is token

        # Token should be a non-empty string (JWT format)
        assert isinstance(token_passed, str)
        assert len(token_passed) > 0
        # JWT format: header.payload.signature
        assert token_passed.count(".") == 2

    def test_resend_verification_handles_email_service_exception_gracefully(
        self, auth_service: AuthService, unverified_user: User
    ):
        """Test 4.4: resend_verification handles email service exception gracefully."""
        # Create a mock email service that raises an exception
        mock_email_service = Mock()
        mock_email_service.send_verification_email.side_effect = Exception("SMTP error")

        # Call resend_verification - should NOT raise
        result = auth_service.resend_verification(
            email=unverified_user.email, email_service=mock_email_service
        )

        # Should still return success to prevent email enumeration
        assert result == {"sent": True}
        # Token must NOT be in response
        assert "verification_token" not in result
        assert "token" not in result

    def test_resend_verification_returns_sent_true_for_nonexistent_email(
        self, auth_service: AuthService
    ):
        """Test that resend_verification returns {"sent": True} for non-existent email (security)."""
        result = auth_service.resend_verification(
            email="nonexistent@example.com", email_service=None
        )

        # Should return success (no email enumeration)
        assert result == {"sent": True}
        assert "sent" in result

    def test_resend_verification_returns_sent_true_for_already_verified_user(
        self, auth_service: AuthService, session: Session
    ):
        """Test that resend_verification returns {"sent": True} for already verified user."""
        # Create a verified user
        role = session.query(Role).filter(Role.name == RoleName.AGENTE).first()
        verified_user = User(
            name="Verified User",
            email="verified@example.com",
            password_hash="fake_hash",
            role=role,
            email_verified=True,
        )
        session.add(verified_user)
        session.commit()

        result = auth_service.resend_verification(
            email=verified_user.email, email_service=None
        )

        # Should return success (no enumeration)
        assert result == {"sent": True}
        assert "sent" in result
