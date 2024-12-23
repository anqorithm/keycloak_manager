import requests
import json
from typing import Dict, List, Optional, Any

from .models import UserAttributes, UserCreate, UserAccess, PasswordUpdate, TokenResponse


class KeycloakManager:
    def __init__(
        self,
        base_url: str = "http://localhost:8080",
        realm: str = "KeycloakAuthFlow",
        admin_username: str = "admin",
        admin_password: str = "admin",
        client_id: str = "keycloak-auth-flow",
        client_secret: str = "POrF8AsCgX4NL7QErSA6UZzfY2X66nHK",
    ):
        """
        Initialize KeycloakManager with configurable parameters

        Args:
            base_url: Keycloak server URL
            realm: Keycloak realm name
            admin_username: Admin username
            admin_password: Admin password
            client_id: Client ID for authentication
            client_secret: Client secret
        """
        self.base_url = base_url
        self.realm = realm
        self.admin_username = admin_username
        self.admin_password = admin_password
        self.client_id = client_id
        self.client_secret = client_secret
        self.access_token = None

    def get_admin_token(self, scope: str = "openid") -> str:
        """
        Get admin access token with configurable scope

        Args:
            scope: OAuth scope (default: openid)

        Returns:
            str: Access token
        """
        url = f"{self.base_url}/realms/{self.realm}/protocol/openid-connect/token"

        data = {
            "username": self.admin_username,
            "password": self.admin_password,
            "grant_type": "password",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": scope,
        }

        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        response = requests.post(url, data=data, headers=headers)
        response.raise_for_status()

        self.access_token = response.json()["access_token"]
        return self.access_token

    def create_user(
        self,
        username: str,
        email: str,
        first_name: str,
        last_name: str,
        enabled: bool = True,
        email_verified: bool = False,
        realm_roles: Optional[List[str]] = None,
        required_actions: Optional[List[str]] = None,
        attributes: Optional[Dict[str, List[str]]] = None,
        groups: Optional[List[str]] = None,
        access: Optional[Dict[str, bool]] = None,
    ) -> str:
        """
        Create a new user with configurable parameters

        Args:
            username: Username
            email: Email address
            first_name: First name
            last_name: Last name
            enabled: Whether the user is enabled
            email_verified: Whether the email is verified
            realm_roles: List of realm roles
            required_actions: List of required actions
            attributes: Custom attributes
            groups: List of groups
            access: Access permissions

        Returns:
            str: User ID
        """
        url = f"{self.base_url}/admin/realms/{self.realm}/users"

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.access_token}",
        }

        user_data = UserCreate(
            username=username,
            email=email,
            firstName=first_name,
            lastName=last_name,
            enabled=enabled,
            emailVerified=email_verified,
            realmRoles=realm_roles or ["mb-user"],
            requiredActions=required_actions or [],
            attributes=attributes or {},
            groups=groups or [],
            access=UserAccess(**access) if access else None,
        )

        response = requests.post(url, headers=headers, json=user_data.model_dump(by_alias=True))
        response.raise_for_status()

        user_id = response.headers["Location"].split("/")[-1]
        return user_id

    def set_user_password(
        self,
        user_id: str,
        password: str,
        temporary: bool = False,
        hash_iterations: Optional[int] = None,
        hash_algorithm: Optional[str] = None,
    ) -> bool:
        """
        Set password for a user with configurable password options

        Args:
            user_id: User ID
            password: New password
            temporary: Whether the password is temporary
            hash_iterations: Number of hash iterations
            hash_algorithm: Hash algorithm to use

        Returns:
            bool: Success status
        """
        url = (
            f"{self.base_url}/admin/realms/{self.realm}/users/{user_id}/reset-password"
        )

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.access_token}",
        }

        password_data = PasswordUpdate(
            value=password,
            temporary=temporary,
            hashIterations=hash_iterations,
            algorithm=hash_algorithm,
        )

        response = requests.put(
            url, headers=headers, json=password_data.model_dump(by_alias=True)
        )
        response.raise_for_status()
        return True

    def get_user_token(
        self,
        username: str,
        password: str,
        client_id: Optional[str] = None,
        grant_type: str = "password",
        scope: Optional[str] = None,
    ) -> TokenResponse:
        """
        Get token for a regular user with configurable parameters

        Args:
            username: Username
            password: Password
            client_id: Client ID (defaults to self.client_id)
            grant_type: Grant type
            scope: OAuth scope

        Returns:
            TokenResponse: Token response object
        """
        url = f"{self.base_url}/realms/{self.realm}/protocol/openid-connect/token"

        data = {
            "client_id": client_id or "admin-cli",
            "username": username,
            "password": password,
            "grant_type": grant_type,
        }

        if scope:
            data["scope"] = scope

        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        response = requests.post(url, data=data, headers=headers)
        response.raise_for_status()
        return TokenResponse(**response.json())

    def get_user_info(self, user_id: str) -> Dict[str, Any]:
        """
        Get user information

        Args:
            user_id: User ID

        Returns:
            dict: User information
        """
        url = f"{self.base_url}/admin/realms/{self.realm}/users/{user_id}"

        headers = {"Authorization": f"Bearer {self.access_token}"}

        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()

    def update_user(self, user_id: str, user_data: Dict[str, Any]) -> bool:
        """
        Update user information

        Args:
            user_id: User ID
            user_data: Updated user data

        Returns:
            bool: Success status
        """
        url = f"{self.base_url}/admin/realms/{self.realm}/users/{user_id}"

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.access_token}",
        }

        response = requests.put(url, headers=headers, json=user_data)
        response.raise_for_status()
        return True
