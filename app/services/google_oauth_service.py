"""Servicio de autenticación OAuth con Google."""

import httpx
import json
import logging
import time
from datetime import datetime, timezone
from urllib.parse import urlencode

from jwcrypto import jwk, jws, jwt

from app.core.config import config
from app.db.schema import LinkedAccount, User

logger = logging.getLogger(__name__)

# Module-level JWKS cache
_jwks_cache: dict | None = None
_jwks_cache_timestamp: float = 0


class GoogleOAuthService:
    """Servicio para autenticación OAuth con Google."""

    TOKEN_URL = "https://oauth2.googleapis.com/token"
    USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"
    EXPECTED_ISSUER = "https://accounts.google.com"

    def __init__(self, session):
        self._db = session

    def get_authorization_url(self, state: str) -> str:
        """Genera URL de autorización de Google."""
        if not config.google_client_id:
            raise RuntimeError("Google OAuth no está configurado")

        params = {
            "client_id": config.google_client_id,
            "redirect_uri": config.google_oauth_redirect_uri,
            "response_type": "code",
            "scope": "openid email profile",
            "state": state,
        }
        return f"https://accounts.google.com/o/oauth2/v2/auth?{urlencode(params)}"

    def exchange_code_for_tokens(self, code: str) -> dict:
        """Intercambia authorization code por tokens de Google."""
        data = {
            "code": code,
            "client_id": config.google_client_id,
            "client_secret": config.google_client_secret.get_secret_value(),
            "redirect_uri": config.google_oauth_redirect_uri,
            "grant_type": "authorization_code",
        }

        with httpx.post(self.TOKEN_URL, data=data, timeout=10) as response:
            if response.status_code != 200:
                raise Exception("Error al intercambiar código con Google")
            return response.json()

    def get_user_info(self, access_token: str) -> dict:
        """Obtiene información del usuario desde Google."""
        headers = {"Authorization": f"Bearer {access_token}"}
        with httpx.get(self.USERINFO_URL, headers=headers, timeout=10) as response:
            if response.status_code != 200:
                raise Exception("Error al obtener información del usuario")
            return response.json()

    def fetch_jwks(self) -> dict | None:
        """
        Fetches Google's JWKS public keys with caching (1 hour TTL).

        Returns:
            dict with JWKS keys on success, None on failure.
        """
        global _jwks_cache, _jwks_cache_timestamp

        current_time = time.time()
        cache_age = current_time - _jwks_cache_timestamp

        # Return cached keys if fresh
        if _jwks_cache is not None and cache_age < config.google_jwks_cache_ttl:
            return _jwks_cache

        # Fetch fresh keys
        try:
            with httpx.get(config.google_jwks_uri, timeout=5) as response:
                if response.status_code != 200:
                    logger.warning(
                        "JWKS fetch failed with status %s: %s",
                        response.status_code,
                        response.text,
                    )
                    return _jwks_cache  # Return stale cache if available

                jwks_data = response.json()
                _jwks_cache = jwks_data
                _jwks_cache_timestamp = current_time
                logger.info("JWKS cache refreshed successfully")
                return jwks_data

        except httpx.TimeoutException:
            logger.warning("JWKS fetch timed out after 5 seconds")
            return _jwks_cache  # Return stale cache if available
        except Exception as e:
            logger.warning("JWKS fetch failed: %s", str(e))
            return _jwks_cache  # Return stale cache if available

    def validate_id_token(self, id_token: str) -> tuple[str, str] | None:
        """
        Validates Google id_token and extracts claims.

        Args:
            id_token: The JWT id_token from Google.

        Returns:
            (email, sub) tuple on success
            None when validation fails (caller should fall back to /userinfo)
        """
        jwks_data = self.fetch_jwks()
        if jwks_data is None:
            logger.warning("id_token validation skipped: JWKS unavailable")
            return None

        try:
            # Parse the token header to get the key ID (kid)
            jws_token = jws.JWS()
            jws_token.deserialize(id_token)
            unverified_header = jws_token.jose_header
            kid = unverified_header.get("kid")

            if not kid:
                logger.warning(
                    "id_token validation failed: missing kid in token header"
                )
                return None

            # Find the matching key in JWKS
            key = None
            for key_data in jwks_data.get("keys", []):
                if key_data.get("kid") == kid:
                    key = jwk.JWK.from_json(json.dumps(key_data))
                    break

            if key is None:
                logger.warning(
                    "id_token validation failed: no matching key found for kid %s",
                    kid,
                )
                return None

            # Verify and decode the token using JWS for proper signature verification
            try:
                jws_token = jws.JWS()
                jws_token.deserialize(id_token)
                jws_token.verify(key)  # This actually verifies the signature
                claims_dict = json.loads(jws_token.payload)
            except Exception as e:
                logger.warning("id_token signature verification failed: %s", str(e))
                return None

            # Validate issuer
            if claims_dict.get("iss") != self.EXPECTED_ISSUER:
                logger.warning(
                    "id_token validation failed: invalid issuer '%s', expected '%s'",
                    claims_dict.get("iss"),
                    self.EXPECTED_ISSUER,
                )
                return None

            # Validate audience
            aud = claims_dict.get("aud")
            if aud != config.google_client_id:
                logger.warning(
                    "id_token validation failed: invalid audience '%s', expected '%s'",
                    aud,
                    config.google_client_id,
                )
                return None

            # Validate expiration
            exp = claims_dict.get("exp")
            if exp is None or exp < time.time():
                logger.warning("id_token validation failed: token expired")
                return None

            # Extract required claims
            email = claims_dict.get("email")
            sub = claims_dict.get("sub")

            if not email or not sub:
                logger.warning(
                    "id_token validation failed: missing email or sub claims"
                )
                return None

            logger.info("id_token validated successfully for email: %s", email)
            return (email, sub)

        except Exception as e:
            logger.warning(
                "id_token validation failed unexpectedly: %s - %s",
                type(e).__name__,
                str(e),
            )
            import traceback

            logger.warning("Traceback: %s", traceback.format_exc())
            return None

    def authenticate_or_create_user(self, code: str) -> User:
        """Autentica con Google y crea/vincula usuario."""
        # Intercambiar code por tokens
        tokens = self.exchange_code_for_tokens(code)
        access_token = tokens.get("access_token")
        id_token = tokens.get("id_token")

        if not access_token:
            raise Exception("No se recibió access_token de Google")

        # Try to validate id_token first for cryptographic verification
        email = None
        google_sub = None
        user_name = None
        id_token_validated = False

        if id_token:
            validated = self.validate_id_token(id_token)
            if validated:
                email, google_sub = validated
                # Note: name from id_token is optional, we'll get it from user_info if needed
                id_token_validated = True
                logger.info("Using email/sub from validated id_token for user lookup")

        # Fall back to /userinfo if id_token validation failed or was skipped
        if not id_token_validated:
            user_info = self.get_user_info(access_token)
            email = user_info.get("email")
            google_sub = user_info.get("sub")
            user_name = user_info.get("name")
            if id_token:
                logger.warning(
                    "id_token validation failed, fell back to /userinfo endpoint"
                )

        if not email:
            raise Exception("Google no proporcionó email")

        # Buscar si ya existe un LinkedAccount con este email
        linked_account = (
            self._db.query(LinkedAccount).filter(LinkedAccount.email == email).first()
        )

        if linked_account:
            # Usuario ya existe, retornarlo
            user = (
                self._db.query(User).filter(User.id == linked_account.user_id).first()
            )
            return user

        # Verificar si el email existe como usuario local sin LinkedAccount
        existing_user = self._db.query(User).filter(User.email == email).first()

        if existing_user:
            from app.services.auth_service import EmailAlreadyExistsError

            raise EmailAlreadyExistsError(
                "El email ya está registrado. Por favor iniciá sesión con tu contraseña."
            )

        # Crear nuevo usuario
        from app.db.schema import DEFAULT_ROLE_NAME, Role

        default_role = (
            self._db.query(Role).filter(Role.name == DEFAULT_ROLE_NAME).first()
        )

        if not default_role:
            raise Exception(f"No existe el rol por defecto: {DEFAULT_ROLE_NAME}")

        new_user = User(
            name=user_name or email.split("@")[0],
            email=email,
            email_verified=True,  # Google ya verificó el email
            role=default_role,
        )
        self._db.add(new_user)
        self._db.flush()  # Get the user ID

        # Crear LinkedAccount
        linked = LinkedAccount(
            user_id=new_user.id,
            provider="google",
            provider_user_id=google_sub,
            email=email,
            created_at=datetime.now(timezone.utc),
        )
        self._db.add(linked)
        self._db.commit()
        self._db.refresh(new_user)

        return new_user
