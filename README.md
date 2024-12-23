# Keycloak Manager

[![PyPI version](https://img.shields.io/pypi/v/keycloak-manager.svg)](https://pypi.org/project/keycloak-manager)
[![Python Versions](https://img.shields.io/pypi/pyversions/keycloak-manager.svg)](https://pypi.org/project/keycloak-manager)
[![License](https://img.shields.io/pypi/l/keycloak-manager.svg)](https://pypi.org/project/keycloak-manager/)

A simple Python package to work with Keycloak users and login systems. Makes it easy to create and manage users, handle logins, and work with user tokens - all through clean and easy-to-use Python code.

## Features

- 🔐 User Management (Create, Update, Delete)
- 🎫 Token Generation and Validation
- 👤 User Authentication
- 🔑 Password Management
- 📝 Custom Attributes Support
- 🔄 Realm Role Management
- 📊 Token Decoding and Verification

## Installation

```bash
# Using Poetry (recommended)
poetry add keycloak-manager

# Using pip
pip install keycloak-manager
```

## Quick Start

```python
from keycloak_manager import KeycloakManager

# Initialize the manager
manager = KeycloakManager(
    base_url="http://localhost:8080",
    realm="YourRealm",
    admin_username="admin",
    admin_password="admin",
    client_id="your-client",
    client_secret="your-secret"
)

# Create a new user
user_id = manager.create_user(
    username="abdullah",
    email="abdullah@anqorithm.com",
    first_name="John",
    last_name="Doe",
    enabled=True,
    email_verified=True,
    realm_roles=["user"]
)

# Set user password
manager.set_user_password(user_id, "secure_password")

# Get user token
token_response = manager.get_user_token(
    username="abdullah",
    password="secure_password"
)
```

## Configuration

The KeycloakManager requires the following configuration:

- `base_url`: Keycloak server URL
- `realm`: Keycloak realm name
- `admin_username`: Admin username
- `admin_password`: Admin password
- `client_id`: Client ID
- `client_secret`: Client secret (optional)

## Development Setup

1. Clone the repository:

```bash
git clone https://github.com/anqorithm/keycloak-manager.git
cd keycloak-manager
```

2. Install dependencies:

```bash
poetry install
```

3. Run tests:

```bash
poetry run pytest
```

## Testing

The package includes comprehensive tests. Run them using:

```bash
poetry run pytest -v
```

For development, you can use the example script:

```bash
python app.py
```

## Project Structure

```
keycloak_manager/
├── keycloak_manager/
│   ├── __init__.py
│   ├── manager.py     # Main manager class
│   └── models.py      # Pydantic models
├── tests/
│   └── test_manager.py
├── app.py            # Example usage
├── pyproject.toml
└── README.md
```

## Models

### UserCreate

```python
class UserCreate(BaseModel):
    username: str
    email: EmailStr
    first_name: str
    last_name: str
    enabled: bool = True
    email_verified: bool = False
    realm_roles: List[str]
    attributes: Dict[str, List[str]] = Field(default_factory=dict)
```

### TokenResponse

```python
class TokenResponse(BaseModel):
    access_token: str
    expires_in: int
    refresh_expires_in: int
    refresh_token: str
    token_type: str
    session_state: str
    scope: str
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

**Abdullah Alqahtani**  
Email: abdullah@anqorithm.com  
GitHub: [@anqorithm](https://github.com/anqorithm)

## Acknowledgments

- Keycloak Team for their excellent authentication server
- Pydantic for data validation
- FastAPI community for inspiration

## Support

For support, please open an issue in the GitHub repository or contact the maintainers at abdullah@anqorithm.com
