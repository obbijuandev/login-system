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

# Serializador de estado OAuth para protección CSRF
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
    """Intercambia token de refresh por nuevo access + refresh token (rotación)."""
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
    """Logout del lado del cliente - descarta el refresh token."""
    return auth_service.logout(refresh_token=payload.refresh_token)


@router.post("/verify-email", status_code=status.HTTP_200_OK)
def verify_email(
    payload: VerifyEmailRequest,
    auth_service: AuthService = Depends(get_auth_service),
):
    """Verifica el email del usuario con el token del correo de verificación."""
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
    Reenvía correo de verificación para usuarios no verificados.

    El token de verificación se envía por email cuando un servicio de email está configurado.
    En modo desarrollo sin servicio de email, el token se loguea en el servidor.
    El token NUNCA se expone en la respuesta HTTP.

    Retorna:
        Un mensaje de éxito genérico independientemente de si el email existe,
        para prevenir ataques de enumeración de emails.
    """
    # email_service se inyectaría aquí cuando esté configurado
    # Por ahora, pasa None para habilitar logging en desarrollo
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
    # Validar token CSRF de estado OAuth
    oauth_state_cookie = request.cookies.get("oauth_state")
    if not oauth_state_cookie:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cookie de estado OAuth faltante",
        )

    try:
        decoded_state = oauth_state_serializer.loads(oauth_state_cookie, max_age=300)
    except SignatureExpired:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="El estado OAuth ha expirado",
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Firma de estado OAuth inválida",
        )

    if decoded_state != state:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="El estado OAuth no coincide",
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
