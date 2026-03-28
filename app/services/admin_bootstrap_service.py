from sqlalchemy.orm import Session, joinedload

from app.core.security import normalize_email
from app.db.schema import Role, RoleName, User


class AdminBootstrapError(ValueError):
    pass


class AdminAlreadyExistsError(AdminBootstrapError):
    pass


class UserNotFoundForAdminBootstrapError(AdminBootstrapError):
    pass


class AdminRoleNotFoundError(AdminBootstrapError):
    pass


class AdminBootstrapService:
    def __init__(self, session: Session):
        self._db = session

    def promote_first_admin_by_email(self, email: str) -> User:
        normalized_email = normalize_email(email)

        try:
            if self._admin_exists():
                raise AdminAlreadyExistsError(
                    "Ya existe al menos un usuario con rol ADMIN"
                )

            user = self._get_user_by_email(normalized_email)
            if user is None:
                raise UserNotFoundForAdminBootstrapError(
                    "No existe un usuario registrado con el correo electrónico indicado"
                )

            admin_role = self._get_role_by_name(RoleName.ADMIN)
            if admin_role is None:
                raise AdminRoleNotFoundError("No existe el rol ADMIN requerido")

            user.role = admin_role
            self._db.commit()
        except Exception:
            self._db.rollback()
            raise

        refreshed_user = self._get_user_by_email(normalized_email)
        if refreshed_user is None:
            raise UserNotFoundForAdminBootstrapError(
                "No se pudo recuperar el usuario promovido a ADMIN"
            )
        return refreshed_user

    def _admin_exists(self) -> bool:
        return (
            self._db.query(User).join(Role).filter(Role.name == RoleName.ADMIN).first()
            is not None
        )

    def _get_user_by_email(self, email: str) -> User | None:
        return (
            self._db.query(User)
            .options(joinedload(User.role))
            .filter(User.email == email)
            .first()
        )

    def _get_role_by_name(self, role_name: str | RoleName) -> Role | None:
        return self._db.query(Role).filter(Role.name == role_name).first()
