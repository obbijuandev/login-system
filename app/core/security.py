from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from app.core.config import config
from app.services.token_blocklist import token_blocklist

PASSWORD_HASH_SCHEME = "pbkdf2_sha256"
PASSWORD_HASH_ITERATIONS = 600_000
MIN_PASSWORD_LENGTH = 8
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
JWT_ALGORITHMS = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}


class InvalidTokenError(ValueError):
    pass


class ExpiredTokenError(InvalidTokenError):
    pass


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("utf-8")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(f"{value}{padding}".encode("utf-8"))


def _get_jwt_hash() -> Any:
    try:
        return JWT_ALGORITHMS[config.jwt_algorithm]
    except KeyError as exc:
        raise ValueError(f"Algoritmo JWT no soportado: {config.jwt_algorithm}") from exc


def normalize_email(email: str) -> str:
    normalized_email = email.strip().lower()
    if not normalized_email:
        raise ValueError("El correo electrónico no puede estar vacío")
    if not EMAIL_PATTERN.fullmatch(normalized_email):
        raise ValueError("Dirección de correo electrónico inválida")
    return normalized_email


def validate_password_strength(password: str) -> str:
    if not password:
        raise ValueError("La contraseña no puede estar vacía")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(
            f"La contraseña debe tener al menos {MIN_PASSWORD_LENGTH} caracteres"
        )
    return password


def hash_password(password: str) -> str:
    validate_password_strength(password)

    salt = secrets.token_hex(16)
    password_digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        PASSWORD_HASH_ITERATIONS,
    )
    encoded_digest = base64.urlsafe_b64encode(password_digest).decode("utf-8")
    return f"{PASSWORD_HASH_SCHEME}${PASSWORD_HASH_ITERATIONS}${salt}${encoded_digest}"


def verify_password(password: str, password_hash: str | None) -> bool:
    if not password or not password_hash:
        return False

    try:
        scheme, iterations, salt, encoded_digest = password_hash.split("$", maxsplit=3)
        candidate_digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            int(iterations),
        )
        expected_digest = base64.urlsafe_b64decode(encoded_digest.encode("utf-8"))
    except (ValueError, TypeError):
        return False

    if scheme != PASSWORD_HASH_SCHEME:
        return False

    return hmac.compare_digest(candidate_digest, expected_digest)


def create_access_token(
    subject: str,
    expires_delta: timedelta | None = None,
    additional_claims: dict[str, Any] | None = None,
) -> str:
    expire_at = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=config.jwt_access_token_expire_minutes)
    )
    header = {"alg": config.jwt_algorithm, "typ": "JWT"}
    payload: dict[str, Any] = {"sub": subject, "exp": int(expire_at.timestamp())}
    if additional_claims:
        payload.update(additional_claims)

    encoded_header = _b64url_encode(
        json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )
    encoded_payload = _b64url_encode(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )
    signing_input = f"{encoded_header}.{encoded_payload}"
    signature = hmac.new(
        config.jwt_secret.encode("utf-8"),
        signing_input.encode("utf-8"),
        _get_jwt_hash(),
    ).digest()
    return f"{signing_input}.{_b64url_encode(signature)}"


def decode_access_token(token: str) -> dict[str, Any]:
    try:
        encoded_header, encoded_payload, encoded_signature = token.split(".")
    except ValueError as exc:
        raise InvalidTokenError("Estructura de JWT inválida") from exc

    try:
        signing_input = f"{encoded_header}.{encoded_payload}"
        expected_signature = hmac.new(
            config.jwt_secret.encode("utf-8"),
            signing_input.encode("utf-8"),
            _get_jwt_hash(),
        ).digest()
        provided_signature = _b64url_decode(encoded_signature)
        if not hmac.compare_digest(expected_signature, provided_signature):
            raise InvalidTokenError("Firma JWT inválida")

        header = json.loads(_b64url_decode(encoded_header))
        if header.get("alg") != config.jwt_algorithm:
            raise InvalidTokenError("Algoritmo JWT inválido")

        payload = json.loads(_b64url_decode(encoded_payload))
        exp = payload.get("exp")
        if exp is not None and datetime.now(timezone.utc).timestamp() >= exp:
            raise ExpiredTokenError("El JWT ha expirado")
    except ExpiredTokenError:
        raise
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise InvalidTokenError("JWT inválido") from exc

    return payload


def create_refresh_token(
    subject: str,
    expires_delta: timedelta | None = None,
) -> str:
    """Crea JWT refresh token con ID de rotación (jti) y claim typ."""
    expire_at = datetime.now(timezone.utc) + (
        expires_delta or timedelta(days=config.jwt_refresh_token_expire_days)
    )
    header = {"alg": config.jwt_algorithm, "typ": "JWT"}
    payload: dict[str, Any] = {
        "sub": subject,
        "exp": int(expire_at.timestamp()),
        "typ": "refresh",
        "jti": uuid.uuid4().hex,
    }

    encoded_header = _b64url_encode(
        json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )
    encoded_payload = _b64url_encode(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )
    signing_input = f"{encoded_header}.{encoded_payload}"
    signature = hmac.new(
        config.jwt_secret.encode("utf-8"),
        signing_input.encode("utf-8"),
        _get_jwt_hash(),
    ).digest()
    return f"{signing_input}.{_b64url_encode(signature)}"


def decode_refresh_token(token: str) -> dict[str, Any]:
    """Decodifica y valida refresh token con validación de typ="refresh"."""
    try:
        encoded_header, encoded_payload, encoded_signature = token.split(".")
    except ValueError as exc:
        raise InvalidTokenError("Estructura de JWT inválida") from exc

    try:
        signing_input = f"{encoded_header}.{encoded_payload}"
        expected_signature = hmac.new(
            config.jwt_secret.encode("utf-8"),
            signing_input.encode("utf-8"),
            _get_jwt_hash(),
        ).digest()
        provided_signature = _b64url_decode(encoded_signature)
        if not hmac.compare_digest(expected_signature, provided_signature):
            raise InvalidTokenError("Firma JWT inválida")

        header = json.loads(_b64url_decode(encoded_header))
        if header.get("alg") != config.jwt_algorithm:
            raise InvalidTokenError("Algoritmo JWT inválido")

        payload = json.loads(_b64url_decode(encoded_payload))

        # Validar que el claim typ sea "refresh"
        if payload.get("typ") != "refresh":
            raise InvalidTokenError("Tipo de token inválido: se esperaba 'refresh'")

        # Verificar si el token está bloqueado
        jti = payload.get("jti")
        if jti and token_blocklist.is_blocked(jti):
            raise InvalidTokenError("Token ha sido invalidado")

        exp = payload.get("exp")
        if exp is not None and datetime.now(timezone.utc).timestamp() >= exp:
            raise ExpiredTokenError("El JWT ha expirado")
    except ExpiredTokenError:
        raise
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise InvalidTokenError("JWT inválido") from exc

    return payload


def create_email_verification_token(
    subject: str,
    expires_delta: timedelta | None = None,
) -> str:
    """Crea JWT para verificación de email con claim typ='email_verification'."""
    expire_at = datetime.now(timezone.utc) + (
        expires_delta
        or timedelta(hours=config.jwt_email_verification_token_expire_hours)
    )
    header = {"alg": config.jwt_algorithm, "typ": "JWT"}
    payload: dict[str, Any] = {
        "sub": subject,
        "exp": int(expire_at.timestamp()),
        "typ": "email_verification",
        "jti": uuid.uuid4().hex,
    }

    encoded_header = _b64url_encode(
        json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )
    encoded_payload = _b64url_encode(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )
    signing_input = f"{encoded_header}.{encoded_payload}"
    signature = hmac.new(
        config.jwt_secret.encode("utf-8"),
        signing_input.encode("utf-8"),
        _get_jwt_hash(),
    ).digest()
    return f"{signing_input}.{_b64url_encode(signature)}"


def decode_email_verification_token(token: str) -> dict[str, Any]:
    """Decodifica y valida token de verificación de email con typ='email_verification'."""
    try:
        encoded_header, encoded_payload, encoded_signature = token.split(".")
    except ValueError as exc:
        raise InvalidTokenError("Estructura de JWT inválida") from exc

    try:
        signing_input = f"{encoded_header}.{encoded_payload}"
        expected_signature = hmac.new(
            config.jwt_secret.encode("utf-8"),
            signing_input.encode("utf-8"),
            _get_jwt_hash(),
        ).digest()
        provided_signature = _b64url_decode(encoded_signature)
        if not hmac.compare_digest(expected_signature, provided_signature):
            raise InvalidTokenError("Firma JWT inválida")

        header = json.loads(_b64url_decode(encoded_header))
        if header.get("alg") != config.jwt_algorithm:
            raise InvalidTokenError("Algoritmo JWT inválido")

        payload = json.loads(_b64url_decode(encoded_payload))

        # Validar que el claim typ sea "email_verification"
        if payload.get("typ") != "email_verification":
            raise InvalidTokenError(
                "Tipo de token inválido: se esperaba 'email_verification'"
            )

        exp = payload.get("exp")
        if exp is not None and datetime.now(timezone.utc).timestamp() >= exp:
            raise ExpiredTokenError("El token de verificación ha expirado")
    except ExpiredTokenError:
        raise
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise InvalidTokenError("JWT inválido") from exc

    return payload
