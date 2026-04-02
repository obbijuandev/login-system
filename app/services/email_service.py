"""
Email Service Interface

This module defines the contract for email services used in the application.
The email service is responsible for sending verification emails to users.

## Protocol

Implement `EmailServiceProtocol` to create a custom email service:

```python
from app.services.email_service import EmailServiceProtocol

class MyEmailService(EmailServiceProtocol):
    def send_verification_email(self, to: str, token: str) -> bool:
        # Your implementation here
        # Return True if email was sent successfully, False otherwise
        ...
```

## Dev Implementation

For development without a real email service, use `LoggingEmailService`:

```python
from app.services.email_service import LoggingEmailService

email_service = LoggingEmailService()
email_service.send_verification_email("user@example.com", "token123")
# Logs: [DEV] Verification email for user@example.com: token123
"""

import logging
from typing import Protocol


class EmailServiceProtocol(Protocol):
    """Protocol for email services that can send verification emails."""

    def send_verification_email(self, to: str, token: str) -> bool:
        """
        Send a verification email to the given address.

        Args:
            to: The recipient email address.
            token: The verification token to include in the email.

        Returns:
            True if the email was sent successfully, False otherwise.
        """
        ...


class LoggingEmailService:
    """
    Development-only email service that logs the verification token.

    This implementation does NOT send real emails. Instead, it logs the
    verification token to the console/server logs for development purposes.

    WARNING: Do NOT use in production!
    """

    def send_verification_email(self, to: str, token: str) -> bool:
        """
        Log the verification email details for development.

        Args:
            to: The recipient email address.
            token: The verification token.

        Returns:
            Always returns True (logging succeeds).
        """
        logging.getLogger(__name__).info(f"[DEV] Verification email for {to}: {token}")
        return True
