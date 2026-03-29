"""Servicio de autenticación OAuth con Google."""

import httpx
from datetime import datetime, timezone
from urllib.parse import urlencode

from app.core.config import config
from app.db.schema import LinkedAccount, User


class GoogleOAuthService:
    """Servicio para autenticación OAuth con Google."""

    TOKEN_URL = "https://oauth2.googleapis.com/token"
    USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"

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

    def authenticate_or_create_user(self, code: str) -> User:
        """Autentica con Google y crea/vincula usuario."""
        # Intercambiar code por tokens
        tokens = self.exchange_code_for_tokens(code)
        access_token = tokens.get("access_token")
        id_token = tokens.get("id_token")

        if not access_token:
            raise Exception("No se recibió access_token de Google")

        # Obtener info del usuario
        user_info = self.get_user_info(access_token)
        email = user_info.get("email")
        google_sub = user_info.get("sub")

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
            name=user_info.get("name", email.split("@")[0]),
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
