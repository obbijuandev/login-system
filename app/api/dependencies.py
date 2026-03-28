from collections.abc import Generator

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.core.security import ExpiredTokenError, InvalidTokenError, decode_access_token
from app.db.schema import RoleName, SessionLocal, User
from app.models.auth import TokenPayload
from app.services.auth_service import AuthService
from app.services.user_service import UserService

bearer_scheme = HTTPBearer(auto_error=False)
FORBIDDEN_DETAIL = "No autorizado para realizar esta acción"


def get_db() -> Generator[Session, None, None]:
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def get_user_service(db: Session = Depends(get_db)) -> UserService:
    return UserService(session=db)


def get_auth_service(db: Session = Depends(get_db)) -> AuthService:
    return AuthService(session=db)


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    auth_service: AuthService = Depends(get_auth_service),
) -> User:
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Credenciales de autenticación inválidas",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if credentials is None or credentials.scheme.lower() != "bearer":
        raise unauthorized

    try:
        payload = TokenPayload.model_validate(
            decode_access_token(credentials.credentials)
        )
    except (InvalidTokenError, ExpiredTokenError, ValidationError) as exc:
        raise unauthorized from exc

    user = auth_service.get_user_from_subject(payload.sub)
    if user is None:
        raise unauthorized

    return user


def _get_role_name(user: User) -> str | None:
    return None if user.role is None else user.role.name


def require_roles(*role_names: str | RoleName):
    allowed_roles = set(role_names)

    def dependency(current_user: User = Depends(get_current_user)) -> User:
        if _get_role_name(current_user) not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=FORBIDDEN_DETAIL,
            )
        return current_user

    return dependency


def require_same_user_or_roles(*role_names: str | RoleName):
    allowed_roles = set(role_names)

    def dependency(
        user_id: int,
        current_user: User = Depends(get_current_user),
    ) -> User:
        if current_user.id == user_id or _get_role_name(current_user) in allowed_roles:
            return current_user

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=FORBIDDEN_DETAIL,
        )

    return dependency
