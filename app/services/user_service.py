from sqlalchemy.orm import Session, joinedload, selectinload

from app.db.schema import Role, RoleName, User


class LastAdminDemotionError(ValueError):
    pass


class LastAdminDeletionError(ValueError):
    pass


class UserService:
    def __init__(self, session: Session):
        self._db = session

    def list_users(self) -> list[User]:
        return self._db.query(User).options(selectinload(User.role)).all()

    def get_user(self, user_id: int) -> User | None:
        return (
            self._db.query(User)
            .options(joinedload(User.role))
            .filter(User.id == user_id)
            .first()
        )

    def update_user(self, user_id: int, name: str) -> User | None:
        user = self.get_user(user_id)
        if not user:
            return None
        user.name = name
        self._db.commit()
        return self.get_user(user_id)

    def delete_user(self, user_id: int) -> bool:
        user = self.get_user(user_id)
        if not user:
            return False

        if self._is_last_admin(user):
            raise LastAdminDeletionError(
                "No se puede eliminar al último ADMIN del sistema"
            )

        self._db.delete(user)
        self._db.commit()
        return True

    def update_user_role(self, user_id: int, role_name: str | RoleName) -> User | None:
        user = self.get_user(user_id)
        if not user:
            return None

        if self._is_last_admin_demotion(user, role_name):
            raise LastAdminDemotionError(
                "No se puede cambiar el rol del último ADMIN del sistema"
            )

        role = self._db.query(Role).filter(Role.name == role_name).first()
        if role is None:
            return None

        user.role = role
        self._db.commit()
        return self.get_user(user_id)

    def _is_last_admin_demotion(
        self, user: User, next_role_name: str | RoleName
    ) -> bool:
        current_role_name = None if user.role is None else user.role.name
        if current_role_name != RoleName.ADMIN or next_role_name == RoleName.ADMIN:
            return False

        return self._is_last_admin(user)

    def _is_last_admin(self, user: User) -> bool:
        current_role_name = None if user.role is None else user.role.name
        if current_role_name != RoleName.ADMIN:
            return False

        another_admin = (
            self._db.query(User)
            .join(Role)
            .filter(Role.name == RoleName.ADMIN, User.id != user.id)
            .first()
        )
        return another_admin is None
