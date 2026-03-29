"""Servicio de blocklist de tokens para invalidar refresh tokens al hacer logout."""

from typing import Set


class TokenBlocklist:
    """Blocklist de tokens en memoria usando un set de JTIs."""

    def __init__(self) -> None:
        self._blocklist: Set[str] = set()

    def add(self, jti: str) -> None:
        """Agrega un JTI de token a la blocklist."""
        self._blocklist.add(jti)

    def is_blocked(self, jti: str) -> bool:
        """Verifica si un JTI de token está bloqueado."""
        return jti in self._blocklist

    def remove(self, jti: str) -> None:
        """Elimina un JTI de token de la blocklist (para limpieza o allowlist)."""
        self._blocklist.discard(jti)

    def clear(self) -> None:
        """Limpia todos los tokens bloqueados. Usar con precaución."""
        self._blocklist.clear()


# Instancia global para usar en toda la aplicación
token_blocklist = TokenBlocklist()
