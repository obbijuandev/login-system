from dotenv import load_dotenv
from pydantic import SecretStr
from pydantic_settings import BaseSettings

load_dotenv()


class Config(BaseSettings):
    app_name: str = "LoginSystem"
    debug: bool = False
    db_user: str = ""
    db_password: str = ""
    db_name: str = "test.db"
    jwt_secret_key: SecretStr = SecretStr("dev-insecure-change-me")
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 30
    jwt_refresh_token_expire_days: int = 7
    jwt_email_verification_token_expire_hours: int = 24

    google_client_id: str = ""
    google_client_secret: SecretStr = SecretStr("")
    google_oauth_redirect_uri: str = "http://localhost:8000/api/v1/auth/google/callback"
    google_jwks_uri: str = "https://www.googleapis.com/oauth2/v3/certs"
    google_jwks_cache_ttl: int = 3600  # 1 hour in seconds

    @property
    def db_url(self) -> str:
        return f"sqlite:///./{self.db_name}"

    @property
    def jwt_secret(self) -> str:
        return self.jwt_secret_key.get_secret_value()

    @property
    def oauth_state_secret_value(self) -> str:
        """Derive OAuth state signing secret from JWT secret."""
        return self.jwt_secret


config = Config()
