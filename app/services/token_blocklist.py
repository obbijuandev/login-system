"""Token blocklist service for invalidating refresh tokens on logout."""

from typing import Set


class TokenBlocklist:
    """Simple in-memory token blocklist using a set of JTIs."""

    def __init__(self) -> None:
        self._blocklist: Set[str] = set()

    def add(self, jti: str) -> None:
        """Add a token JTI to the blocklist."""
        self._blocklist.add(jti)

    def is_blocked(self, jti: str) -> bool:
        """Check if a token JTI is blocked."""
        return jti in self._blocklist

    def remove(self, jti: str) -> None:
        """Remove a token JTI from the blocklist (for cleanup or allowlist)."""
        self._blocklist.discard(jti)

    def clear(self) -> None:
        """Clear all blocked tokens. Use with caution."""
        self._blocklist.clear()


# Global instance for use across the application
token_blocklist = TokenBlocklist()
