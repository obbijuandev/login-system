from pydantic import BaseModel, ConfigDict, Field

from app.db.schema import RoleName


class UserBase(BaseModel):
    name: str
    email: str | None = None


class RoleRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str


class UserCreate(UserBase):
    password: str | None = Field(default=None, exclude=True)


class UserRoleUpdate(BaseModel):
    role: RoleName


class UserRead(UserBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    role: RoleRead | None = None


class UserInDB(UserRead):
    password_hash: str | None = Field(default=None, exclude=True)
