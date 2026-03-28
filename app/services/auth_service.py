from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, joinedload

from app.core.security import (
    create_access_token,
    create_email_verification_token,
    create_refresh_token,
    decode_email_verification_token,
    decode_refresh_token,
    hash_password,
    normalize_email,
    verify_password,
)
from app.core.security import InvalidTokenError as SecurityInvalidTokenError
from app.core.security import ExpiredTokenError as SecurityExpiredTokenError
from app.db.schema import DEFAULT_ROLE_NAME, Role, User
from app.models.auth import Token
from app.services.token_blocklist import token_blocklist


class EmailAlreadyExistsError(ValueError):
    pass


class InvalidCredentialsError(ValueError):
    pass


class ExpiredTokenError(ValueError):
    pass


class InvalidTokenError(ValueError):
    pass


class AuthService:
    def __init__(self, session: Session):
        self._db = session

    def get_user_by_email(self, email: str) -> User | None:
        return (
            self._db.query(User)
            .options(joinedload(User.role))
            .filter(User.email == self._normalize_email(email))
            .first()
        )

    def get_user_by_id(self, user_id: int) -> User | None:
        return (
            self._db.query(User)
            .options(joinedload(User.role))
            .filter(User.id == user_id)
            .first()
        )

    def get_role_by_name(self, role_name: str) -> Role | None:
        return self._db.query(Role).filter(Role.name == role_name).first()

    def register_user(self, name: str, email: str, password: str) -> User:
        normalized_email = self._normalize_email(email)
        if self.get_user_by_email(normalized_email):
            raise EmailAlreadyExistsError("El correo electrónico ya existe")

        default_role = self.get_role_by_name(DEFAULT_ROLE_NAME)
        if default_role is None:
            raise RuntimeError(
                f"No existe el rol por defecto requerido: {DEFAULT_ROLE_NAME}"
            )

        user = User(
            name=name,
            email=normalized_email,
            password_hash=hash_password(password),
            role=default_role,
        )
        self._db.add(user)

        try:
            self._db.commit()
        except IntegrityError as exc:
            self._db.rollback()
            raise EmailAlreadyExistsError("El correo electrónico ya existe") from exc

        self._db.refresh(user)
        return user

    def authenticate_user(self, email: str, password: str) -> User | None:
        user = self.get_user_by_email(email)
        if not user or not verify_password(password, user.password_hash):
            return None
        return user

    def login(self, email: str, password: str) -> Token:
        user = self.authenticate_user(email, password)
        if not user:
            raise InvalidCredentialsError("Correo electrónico o contraseña inválidos")

        return Token(
            access_token=create_access_token(subject=str(user.id)),
            refresh_token=create_refresh_token(subject=str(user.id)),
        )

    def get_user_from_subject(self, subject: str) -> User | None:
        if not subject.isdigit():
            return None
        return self.get_user_by_id(int(subject))

    def refresh_access_token(self, refresh_token: str) -> Token:
        """Exchange refresh token for new access + refresh token (rotation)."""
        try:
            payload = decode_refresh_token(refresh_token)
        except SecurityExpiredTokenError as exc:
            raise ExpiredTokenError("El token de refresh ha expirado") from exc
        except SecurityInvalidTokenError as exc:
            raise InvalidTokenError("Token de refresh inválido") from exc

        subject = payload.get("sub")
        if not subject:
            raise InvalidTokenError("Token de refresh sin subject")

        # Create new tokens with new jti (rotation)
        return Token(
            access_token=create_access_token(subject=subject),
            refresh_token=create_refresh_token(subject=subject),
        )

    def logout(self, refresh_token: str) -> dict:
        """Logout - invalidate refresh token by adding to blocklist."""
        try:
            payload = decode_refresh_token(refresh_token)
            jti = payload.get("jti")
            if jti:
                token_blocklist.add(jti)
        except SecurityExpiredTokenError:
            pass  # Token already expired, still considered logged out
        except SecurityInvalidTokenError:
            pass  # Invalid token, still considered logged out

        return {"message": "Sesión cerrada exitosamente"}

    def verify_email(self, token: str) -> bool:
        """Verify user's email with token. Returns True on success."""
        try:
            payload = decode_email_verification_token(token)
        except SecurityExpiredTokenError as exc:
            raise ExpiredTokenError("El token de verificación ha expirado") from exc
        except SecurityInvalidTokenError as exc:
            raise InvalidTokenError("Token de verificación inválido") from exc

        subject = payload.get("sub")
        if not subject:
            raise InvalidTokenError("Token sin subject")

        user = self.get_user_from_subject(subject)
        if user is None:
            raise InvalidTokenError("Usuario no encontrado")

        if user.email_verified:
            return True  # Already verified, no-op

        user.email_verified = True
        self._db.commit()
        return True

    def resend_verification(self, email: str) -> dict:
        """Create and return new verification token for email.

        Note: Email sending is OUT of scope - token is created and returned
        for integration with external email service.
        """
        normalized_email = self._normalize_email(email)
        user = self.get_user_by_email(normalized_email)

        if user is None:
            # Security: don't reveal if email exists
            return {"verification_token": None}

        if user.email_verified:
            # Already verified - still return success to avoid enumeration
            return {"verification_token": None}

        # Create new token
        token = create_email_verification_token(subject=str(user.id))

        return {"verification_token": token}

    @staticmethod
    def _normalize_email(email: str) -> str:
        return normalize_email(email)
