import secrets

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import RedirectResponse
from itsdangerous import URLSafeTimedSerializer, SignatureExpired

from app.core.config import config

from app.api.dependencies import (
    get_auth_service,
    get_current_user,
    get_google_oauth_service,
)
from app.db.schema import User
from app.models.auth import (
    LoginRequest,
    LogoutRequest,
    RefreshRequest,
    RegisterRequest,
    ResendVerificationRequest,
    Token,
    VerifyEmailRequest,
)
from app.models.user import UserRead
from app.services.auth_service import (
    AuthService,
    EmailAlreadyExistsError,
    ExpiredTokenError,
    InvalidCredentialsError,
    InvalidTokenError,
)
from app.services.google_oauth_service import GoogleOAuthService

router = APIRouter(prefix="/auth", tags=["auth"])

# OAuth state serializer for CSRF protection
oauth_state_serializer = URLSafeTimedSerializer(config.oauth_state_secret_value)


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


@router.post("/verify-email", status_code=status.HTTP_200_OK)
def verify_email(
    payload: VerifyEmailRequest,
    auth_service: AuthService = Depends(get_auth_service),
):
    """Verify user's email with token from verification email."""
    try:
        auth_service.verify_email(token=payload.token)
        return {"message": "Email verificado exitosamente"}
    except ExpiredTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El token de verificación ha expirado",
        ) from exc
    except InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token de verificación inválido",
        ) from exc


@router.post("/resend-verification", response_model=dict)
def resend_verification(
    payload: ResendVerificationRequest,
    auth_service: AuthService = Depends(get_auth_service),
):
    """
    Resend verification email for unverified users.

    The verification token is sent via email when an email service is configured.
    In development mode without an email service, the token is logged server-side.
    The token is NEVER exposed in the HTTP response.

    Returns:
        A generic success message regardless of whether the email exists,
        to prevent email enumeration attacks.
    """
    # email_service would be injected here when configured
    # For now, passes None to enable dev logging
    auth_service.resend_verification(email=payload.email, email_service=None)

    # Always return success to prevent email enumeration
    return {"message": "Si el correo existe, se envió el correo de verificación"}


@router.get("/google")
def google_login(
    google_oauth: GoogleOAuthService = Depends(get_google_oauth_service),
):
    """Inicia flujo OAuth con Google. Retorna 302 redirect."""
    try:
        raw_state = secrets.token_urlsafe(32)
        signed_state = oauth_state_serializer.dumps(raw_state)
        url = google_oauth.get_authorization_url(raw_state)
        response = RedirectResponse(url, status_code=302)
        response.set_cookie(
            key="oauth_state",
            value=signed_state,
            httponly=True,
            secure=not config.debug,
            samesite="lax",
            max_age=300,
        )
        return response
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Google OAuth no está configurado",
        )


@router.get("/google/callback")
def google_callback(
    request: Request,
    code: str = Query(...),
    state: str = Query(...),
    auth_service: AuthService = Depends(get_auth_service),
    google_oauth: GoogleOAuthService = Depends(get_google_oauth_service),
):
    """Maneja callback de Google OAuth."""
    # Validate OAuth state CSRF token
    oauth_state_cookie = request.cookies.get("oauth_state")
    if not oauth_state_cookie:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OAuth state cookie missing",
        )

    try:
        decoded_state = oauth_state_serializer.loads(oauth_state_cookie, max_age=300)
    except SignatureExpired:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="OAuth state expired",
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid OAuth state signature",
        )

    if decoded_state != state:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="OAuth state mismatch",
        )

    try:
        user = google_oauth.authenticate_or_create_user(code)
    except EmailAlreadyExistsError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc.args[0]) if exc.args else "El email ya está registrado",
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Error al autenticar con Google",
        )

    # Generar tokens JWT
    return auth_service._create_tokens_for_user(user)
