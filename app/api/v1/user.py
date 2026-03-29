from fastapi import APIRouter, Depends, HTTPException

from app.api.dependencies import (
    get_current_user,
    get_user_service,
    require_roles,
    require_same_user_or_roles,
)
from app.db.schema import RoleName, User
from app.models.user import UserCreate, UserRead, UserRoleUpdate
from app.services.user_service import (
    LastAdminDeletionError,
    LastAdminDemotionError,
    UserService,
)

router = APIRouter(tags=["users"], dependencies=[Depends(get_current_user)])


@router.get("/users", response_model=list[UserRead])
def get_users(
    service: UserService = Depends(get_user_service),
    _: User = Depends(require_roles(RoleName.ADMIN, RoleName.SUPERVISOR)),
):
    return service.list_users()


@router.get("/users/{user_id}", response_model=UserRead)
def get_user(
    user_id: int,
    service: UserService = Depends(get_user_service),
    _: User = Depends(require_same_user_or_roles(RoleName.ADMIN, RoleName.SUPERVISOR)),
):
    user = service.get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    return user


@router.put("/users/{user_id}", response_model=UserRead)
def update_user(
    user_id: int,
    user: UserCreate,
    service: UserService = Depends(get_user_service),
    _: User = Depends(require_same_user_or_roles(RoleName.ADMIN, RoleName.SUPERVISOR)),
):
    updated = service.update_user(user_id, user.name)
    if not updated:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    return updated


@router.patch("/users/{user_id}/role", response_model=UserRead)
def update_user_role(
    user_id: int,
    payload: UserRoleUpdate,
    service: UserService = Depends(get_user_service),
    _: User = Depends(require_roles(RoleName.ADMIN)),
):
    try:
        updated = service.update_user_role(user_id, payload.role)
    except LastAdminDemotionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    if not updated:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    return updated


@router.delete("/users/{user_id}")
def delete_user(
    user_id: int,
    service: UserService = Depends(get_user_service),
    _: User = Depends(require_roles(RoleName.ADMIN)),
):
    try:
        success = service.delete_user(user_id)
    except LastAdminDeletionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    if not success:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    return {"success": True}
