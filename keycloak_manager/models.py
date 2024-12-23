from typing import Dict, List, Optional
from pydantic import BaseModel, EmailStr, Field


class UserAttributes(BaseModel):
    """Custom user attributes"""
    attributes: Dict[str, List[str]] = Field(default_factory=dict)


class UserAccess(BaseModel):
    """User access permissions"""
    manage_group_membership: bool = Field(default=False, alias="manageGroupMembership")
    view: bool = Field(default=True)
    map_roles: bool = Field(default=False, alias="mapRoles")
    impersonate: bool = Field(default=False)
    manage: bool = Field(default=False)


class UserCreate(BaseModel):
    """User creation request model"""
    username: str
    email: EmailStr
    first_name: str = Field(alias="firstName")
    last_name: str = Field(alias="lastName")
    enabled: bool = True
    email_verified: bool = Field(default=False, alias="emailVerified")
    realm_roles: List[str] = Field(default_factory=lambda: ["mb-user"], alias="realmRoles")
    required_actions: List[str] = Field(default_factory=list, alias="requiredActions")
    attributes: Dict[str, List[str]] = Field(default_factory=dict)
    groups: List[str] = Field(default_factory=list)
    access: Optional[UserAccess] = None

    class Config:
        populate_by_name = True


class PasswordUpdate(BaseModel):
    """Password update request model"""
    type: str = "password"
    value: str
    temporary: bool = False
    hash_iterations: Optional[int] = Field(None, alias="hashIterations")
    algorithm: Optional[str] = None


class TokenResponse(BaseModel):
    """Token response model"""
    access_token: str
    expires_in: int
    refresh_expires_in: int
    refresh_token: str
    token_type: str
    session_state: str
    scope: str
