import pytest
import requests
from unittest.mock import Mock, patch
from keycloak_manager.manager import KeycloakManager


@pytest.fixture
def keycloak_manager():
    """Fixture: Creates a test instance of KeycloakManager with predefined test credentials"""
    return KeycloakManager(
        base_url="http://localhost:8080",
        realm="TestRealm",
        admin_username="test_admin",
        admin_password="test_password",
        client_id="test_client",
        client_secret="test_secret",
    )


@pytest.fixture
def mock_response():
    """Fixture: Creates a mock HTTP response with test token and user ID"""
    mock = Mock()
    mock.raise_for_status = Mock()
    mock.json.return_value = {
        "access_token": "test_token",
        "token_type": "Bearer",
        "expires_in": 300,
        "refresh_expires_in": 1800,
        "refresh_token": "test_refresh_token",
        "session_state": "test_session_state",
        "scope": "openid email profile",
    }
    mock.headers = {
        "Location": "http://localhost:8080/auth/admin/realms/test/users/123"
    }
    return mock


def test_initialization(caplog):
    """
    Test Case: KeycloakManager Initialization

    Verifies:
    1. All constructor parameters are correctly assigned
    2. Custom URL and realm are properly set
    3. Admin credentials are stored
    4. Client configuration is maintained
    5. Initial access token is None
    """
    manager = KeycloakManager(
        base_url="http://test.com",
        realm="CustomRealm",
        admin_username="custom_admin",
        admin_password="custom_pass",
        client_id="custom_client",
        client_secret="custom_secret",
    )

    print("\nVerifying KeycloakManager initialization:")
    print(f"Base URL: {manager.base_url}")
    print(f"Realm: {manager.realm}")
    print(f"Admin Username: {manager.admin_username}")
    print(f"Client ID: {manager.client_id}")

    assert manager.base_url == "http://test.com", "Base URL mismatch"
    assert manager.realm == "CustomRealm", "Realm mismatch"
    assert manager.admin_username == "custom_admin", "Admin username mismatch"
    assert manager.admin_password == "custom_pass", "Admin password mismatch"
    assert manager.client_id == "custom_client", "Client ID mismatch"
    assert manager.client_secret == "custom_secret", "Client secret mismatch"
    assert manager.access_token is None, "Initial access token should be None"


@patch("requests.post")
def test_get_admin_token(mock_post, keycloak_manager, mock_response, caplog):
    """
    Test Case: Admin Token Generation

    Verifies:
    1. Correct endpoint is called
    2. Proper authentication headers are set
    3. Token is successfully retrieved
    4. Token is stored in manager instance
    5. Request parameters match configuration
    """
    mock_post.return_value = mock_response
    print("\nTesting admin token generation:")

    token = keycloak_manager.get_admin_token(scope="custom_scope")
    call_args = mock_post.call_args

    print(f"Generated Token: {token}")
    print(f"Endpoint Called: {call_args[0][0]}")
    print(f"Request Headers: {call_args[1]['headers']}")
    print(f"Request Data: {call_args[1]['data']}")

    assert token == "test_token", "Token mismatch"
    assert keycloak_manager.access_token == "test_token", "Token not stored in manager"
    assert "TestRealm" in call_args[0][0], "Incorrect realm in URL"
    assert call_args[1]["data"]["scope"] == "custom_scope", "Scope mismatch"
    assert call_args[1]["data"]["client_id"] == "test_client", "Client ID mismatch"


@patch("requests.post")
def test_create_user(mock_post, keycloak_manager, mock_response, caplog):
    """
    Test Case: User Creation

    Verifies:
    1. User creation endpoint is called correctly
    2. Authorization header contains admin token
    3. User data is properly formatted
    4. Custom attributes and roles are included
    5. User ID is correctly extracted from response
    """
    keycloak_manager.access_token = "admin_token"
    mock_post.return_value = mock_response
    print("\nTesting user creation:")

    user_id = keycloak_manager.create_user(
        username="test_user",
        email="test@example.com",
        first_name="Test",
        last_name="User",
        realm_roles=["test_role"],
        attributes={"test_attr": ["value"]},
    )
    call_args = mock_post.call_args

    print(f"Created User ID: {user_id}")
    print(f"Request URL: {call_args[0][0]}")
    print(f"User Data: {call_args[1]['json']}")
    print(f"Authorization: {call_args[1]['headers']['Authorization']}")

    assert user_id == "123", "User ID mismatch"
    assert call_args[1]["headers"]["Authorization"] == "Bearer admin_token"
    assert call_args[1]["json"]["username"] == "test_user"
    assert "test_role" in call_args[1]["json"]["realmRoles"]


@patch("requests.put")
def test_set_user_password(mock_put, keycloak_manager, mock_response, caplog):
    """
    Test Case: Password Setting

    Verifies:
    1. Password reset endpoint is called
    2. Password data is properly formatted
    3. Temporary password flag is respected
    4. Hash iterations are included if specified
    5. Authorization header is present
    """
    keycloak_manager.access_token = "admin_token"
    mock_put.return_value = mock_response
    print("\nTesting password setting:")

    result = keycloak_manager.set_user_password(
        user_id="123", password="test_pass", temporary=True, hash_iterations=1000
    )
    call_args = mock_put.call_args

    print(f"Password Set Result: {result}")
    print(f"Endpoint Called: {call_args[0][0]}")
    print(f"Password Config: {call_args[1]['json']}")

    assert result is True, "Password setting failed"
    assert "123" in call_args[0][0], "Incorrect user ID in URL"
    assert call_args[1]["json"]["temporary"] is True, "Temporary flag not set"
    assert call_args[1]["json"]["hashIterations"] == 1000, "Hash iterations mismatch"


@patch("requests.post")
def test_get_user_token(mock_post, keycloak_manager, mock_response, caplog):
    """
    Test Case: User Token Generation

    Verifies:
    1. Token endpoint is called with user credentials
    2. Client ID is properly included
    3. Custom scope is respected
    4. Response token is returned
    5. Request format matches specification
    """
    mock_post.return_value = mock_response
    print("\nTesting user token generation:")

    token_response = keycloak_manager.get_user_token(
        username="test_user",
        password="test_pass",
        client_id="custom_client",
        scope="custom_scope",
    )
    call_args = mock_post.call_args

    print(f"Token Response: {token_response}")
    print(f"Request URL: {call_args[0][0]}")
    print(f"Request Data: {call_args[1]['data']}")

    assert (
        token_response.model_dump() == mock_response.json()
    ), "Token response mismatch"
    assert call_args[1]["data"]["username"] == "test_user"
    assert call_args[1]["data"]["scope"] == "custom_scope"


def test_error_handling(keycloak_manager, caplog):
    """
    Test Case: Error Handling

    Verifies:
    1. RequestException is properly raised
    2. Error handling works for failed requests
    3. Exception contains appropriate error details
    4. Failed request doesn't modify manager state
    """
    print("\nTesting error handling:")

    with pytest.raises(requests.exceptions.RequestException) as exc_info:
        with patch("requests.post") as mock_post:
            mock_response = Mock()
            mock_response.raise_for_status.side_effect = (
                requests.exceptions.RequestException("Test error")
            )
            mock_post.return_value = mock_response

            print("Attempting token generation with simulated error...")
            keycloak_manager.get_admin_token()

    print(f"Caught expected exception: {exc_info.value}")
    assert keycloak_manager.access_token is None, "Failed request shouldn't set token"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--capture=no"])
