# Airflow AD Auth Manager

The `airflow_ad_auth_manager` is an authentication manager for Airflow 3, designed to integrate with Azure Active Directory (Azure AD). It provides secure authentication for both the Airflow UI and API using Azure AD access tokens and supports role-based access control (RBAC) by mapping Azure AD groups to a built-in set of role levels.

## Features

- **Azure AD OAuth2 Authentication**: Authenticate users via Azure AD using OAuth2.
- **Role Mapping**: Map Azure AD group GUIDs to Airflow roles.
- **UI and API Support**: Authenticate users for both the Airflow UI and API endpoints.
- **JWT Token Generation**: Issue JWT tokens for authenticated users.
- **API Key Support**: Authenticate programmatic access using API keys.

## Installation

Installation can be done via pip:
```bash
pip install airflow_azure_auth_manager
```

## Configuration

The following parameters must be added to the `[azure_auth_manager]` section of your `airflow.cfg` file:

```ini
[azure_auth_manager]
tenant_id = <your-azure-ad-tenant-id>
client_id = <your-azure-ad-client-id>
client_secret = <your-azure-ad-client-secret>
api_secret_key = <your-api-secret-key>
jwks_uri = https://login.microsoftonline.com/common/discovery/v2.0/keys
default_role = user
group_role_map = <group-guid-1>:<role-1>,<group-guid-2>:<role-2>,...
```

### Parameter Descriptions

- **`tenant_id`**: The Azure AD tenant ID for your organization.
- **`client_id`**: The Azure AD application (client) ID.
- **`client_secret`**: The client secret for the Azure AD application.
- **`api_secret_key`**: A secret key used to validate API keys for the `/auth/api_login` endpoint. Leave blank to disable API key authentication.
- **`jwks_uri`**: The URI for the JSON Web Key Set (JWKS) used to validate Azure AD tokens. Defaults to the common endpoint.
- **`default_role`**: The default Airflow role assigned to users if no group matches are found. Defaults to `user`.
- **`group_role_map`**: A comma-separated list of mappings between Azure AD group GUIDs and Airflow roles. Each mapping is in the format `<group-guid>:<role>`. For example:
  ```
  group_role_map = 12345:user,67890:admin
  ```

  In this example:
  - Users in the Azure AD group with GUID `12345` will be assigned the `user` role.
  - Users in the Azure AD group with GUID `67890` will be assigned the `admin` role.

## Endpoints

### `/auth/login`

Redirects users to the Azure AD login page for authentication. After successful login, users are redirected back to the Airflow UI with a JWT token set as a cookie.

### `/auth/callback`

Handles the callback from Azure AD after authentication. Exchanges the authorization code for access and ID tokens, validates the tokens, and assigns the appropriate Airflow role based on the `group_role_map`.

### `/auth/api_login`

An API endpoint for authenticating users using a username and API key. This is useful for programmatic access to Airflow.

#### Request

```json
POST /auth/api_login
Content-Type: application/json

{
  "username": "example_user",
  "api_key": "example_api_key"
}
```

- **`username`**: The username of the user.
- **`api_key`**: The API key.

#### Response

If authentication is successful, the endpoint returns a JWT token in a cookie. This token can be used for subsequent requests to Airflow.

## Role Hierarchy

The following role hierarchy is used to determine access levels:

1. **viewer**: Read-only access.
2. **user**: Read and limited write access.
3. **op**: Operational access.
4. **admin**: Full administrative access.

## Example Usage

### UI Login

1. Navigate to `/auth/login` in your Airflow instance.
2. Log in using your Azure AD credentials.
3. After successful login, you will be redirected to the Airflow UI.

### API Login

1. Generate an API key using the formula:
   ```
   sha256(username + api_secret_key + role).hexdigest()
   ```
   Replace `username`, `api_secret_key`, and `role` with the appropriate values.
2. Send a `POST` request to `/auth/api_login` with the `username` and `api_key`.
3. Use the returned JWT token for subsequent API requests.

## Development

To contribute to this project, clone the repository and create a new branch for your feature or bug fix. Submit a pull request when ready.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
