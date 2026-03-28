from fastapi import APIRouter, Depends, HTTPException, status

from app.api.dependencies import get_auth_service, get_current_user
from app.db.schema import User
from app.models.auth import (
    LoginRequest,
    LogoutRequest,
    RefreshRequest,
    RegisterRequest,
    Token,
)
from app.models.user import UserRead
from app.services.auth_service import (
    AuthService,
    EmailAlreadyExistsError,
    ExpiredTokenError,
    InvalidCredentialsError,
    InvalidTokenError,
)

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def register(
    payload: RegisterRequest,
    auth_service: AuthService = Depends(get_auth_service),
):
    try:
        return auth_service.register_user(
            name=payload.name,
            email=payload.email,
            password=payload.password,
        )
    except EmailAlreadyExistsError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="El correo electrónico ya existe",
        ) from exc


@router.post("/login", response_model=Token)
def login(
    payload: LoginRequest,
    auth_service: AuthService = Depends(get_auth_service),
):
    try:
        return auth_service.login(email=payload.email, password=payload.password)
    except InvalidCredentialsError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Correo electrónico o contraseña inválidos",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


@router.get("/me", response_model=UserRead)
def me(current_user: User = Depends(get_current_user)):
    return current_user


@router.post("/refresh", response_model=Token)
def refresh(
    payload: RefreshRequest,
    auth_service: AuthService = Depends(get_auth_service),
):
    """Exchange refresh token for new access + refresh token (rotation)."""
    try:
        return auth_service.refresh_access_token(refresh_token=payload.refresh_token)
    except ExpiredTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="El token de refresh ha expirado",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    except InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token de refresh inválido",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


@router.post("/logout", response_model=dict)
def logout(
    payload: LogoutRequest,
    auth_service: AuthService = Depends(get_auth_service),
):
    """Client-side logout - discards refresh token."""
    return auth_service.logout(refresh_token=payload.refresh_token)
