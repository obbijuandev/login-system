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

    @property
    def db_url(self) -> str:
        return f"sqlite:///./{self.db_name}"

    @property
    def jwt_secret(self) -> str:
        return self.jwt_secret_key.get_secret_value()


config = Config()
