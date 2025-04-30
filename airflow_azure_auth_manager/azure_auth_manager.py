import logging
import urllib.parse
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

import jwt
import requests
from airflow.api_fastapi.auth.managers.base_auth_manager import COOKIE_NAME_JWT_TOKEN, BaseAuthManager
from airflow.api_fastapi.auth.managers.models.base_user import BaseUser
from airflow.configuration import conf
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.routing import APIRouter
from jwt import InvalidTokenError, PyJWKClient

logger = logging.getLogger(__name__)


@dataclass
class AuthUser:
    username: str
    email: str
    role: str


class AzureAuthManagerUser(BaseUser):
    def __init__(self, username: str, email: str, role: str):
        self.username = username
        self.email = email
        self.role = role

    def get_user_id(self):
        return self.username

    def get_role(self):
        return self.role


class AzureADAuthManager(BaseAuthManager):
    """
    Airflow 3 Auth Manager for Azure AD authentication using access tokens.
    - Maps Azure AD group GUIDs to Airflow roles via config.
    - Supports both UI and API (Bearer token) authentication.
    """

    def __init__(self):
        self.tenant_id = conf.get("azure_auth_manager", "tenant_id")
        self.client_id = conf.get("azure_auth_manager", "client_id")
        self.client_secret = conf.get("azure_auth_manager", "client_secret")
        self.jwks_uri = conf.get(
            "azure_auth_manager", "jwks_uri", fallback="https://login.microsoftonline.com/common/discovery/v2.0/keys"
        )
        self.default_role = conf.get("azure_auth_manager", "default_role", fallback="user")
        self.group_role_map = self._parse_group_role_map(conf.get("azure_auth_manager", "group_role_map", fallback=""))
        self.jwk_client = PyJWKClient(self.jwks_uri)

    def _parse_group_role_map(self, raw: str) -> Dict[str, str]:
        """
        Parse group_role_map config string into a dict: {group_guid: role}
        """
        mapping = {}
        if raw:
            for pair in raw.split(","):
                if ":" in pair:
                    group, role = pair.split(":", 1)
                    mapping[group.strip()] = role.strip()
        return mapping

    def get_fastapi_app(self) -> FastAPI:
        """
        FastAPI sub-app for UI login/logout with Azure AD OAuth2.
        """
        app = FastAPI(title="Azure AD Auth Manager Login App")
        router = APIRouter()

        @router.get("/login")
        async def login(request: Request):
            """
            Redirect to Azure AD authorize endpoint.
            """
            redirect_uri = str(request.url_for("callback"))
            params = {
                "client_id": self.client_id,
                "response_type": "code",
                "redirect_uri": redirect_uri,
                "response_mode": "query",
                "scope": "openid email profile User.Read",
                "state": "airflow-login",
            }
            authorize_url = (
                f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/authorize?"
                + urllib.parse.urlencode(params)
            )
            return RedirectResponse(authorize_url)

        @router.get("/callback")
        async def callback(request: Request, code: str = None, state: str = None):  # noqa: PLR0911
            if not code:
                return HTMLResponse("Missing code", status_code=400)
            redirect_uri = str(request.url_for("callback"))
            token_url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
            data = {
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
            }
            resp = requests.post(token_url, data=data)
            if resp.status_code != 200:  # noqa: PLR2004
                return HTMLResponse("Token exchange failed", status_code=400)

            tokens = resp.json()
            access_token = tokens.get("access_token")
            if not access_token:
                return HTMLResponse("No access token", status_code=400)
            id_token = tokens.get("id_token")
            if not id_token:
                return HTMLResponse("No ID token", status_code=400)

            # Try tenant-specific JWKS first
            jwks_urls = [
                f"https://login.microsoftonline.com/{self.tenant_id}/discovery/v2.0/keys",
                "https://login.microsoftonline.com/common/discovery/v2.0/keys",
            ]
            validated = False
            for jwks_url in jwks_urls:
                logger.info(f"Trying JWKS URL: {jwks_url}")
                jwk_client = PyJWKClient(jwks_url)

                try:
                    signing_key = jwk_client.get_signing_key_from_jwt(id_token)
                    claims = jwt.decode(
                        id_token,
                        signing_key.key,
                        algorithms=["RS256"],
                        audience=self.client_id,
                        options={"verify_exp": True, "verify_aud": True},
                    )
                    validated = True
                    logger.info("Azure token validated")
                    break
                except InvalidTokenError as e:
                    logger.error(f"Azure token validation failed with JWKS {jwks_url}: {e}")
                except Exception:
                    logger.exception("Unexpected error during token validation")

            if not validated:
                return HTMLResponse("Azure token validation failed: Signature verification failed", status_code=400)

            try:
                group_guids = self._fetch_group_ids(access_token)
            except Exception as e:
                return HTMLResponse(str(e), status_code=400)

            username, email, _ = self._extract_user_info(claims)
            role = self.get_user_role(group_guids)
            user = AzureAuthManagerUser(username=username, email=email, role=role)

            jwt_token = self.generate_jwt(user)
            response = RedirectResponse(url="/")
            secure = bool(conf.get("api", "ssl_cert", fallback=""))
            response.set_cookie(
                COOKIE_NAME_JWT_TOKEN,
                jwt_token,
                secure=secure,
                httponly=False,  # Must be False so UI can read it
                samesite="lax",
                path="/",
            )
            return response

        app.include_router(router)
        return app

    def _fetch_group_ids(self, access_token: str) -> List[str]:
        """
        Fetch group IDs from Microsoft Graph API using the provided access token.
        """
        graph_url = "https://graph.microsoft.com/v1.0/me/memberOf"
        headers = {"Authorization": f"Bearer {access_token}"}
        resp = requests.get(graph_url, headers=headers)
        if resp.status_code != 200:  # noqa: PLR2004
            logger.error(f"Failed to fetch groups from Microsoft Graph: {resp.text}")
            raise Exception("Failed to fetch user groups")
        group_data = resp.json()
        return [group["id"] for group in group_data.get("value", []) if "id" in group]

    def get_user_role(self, group_guids: List[str]) -> str:
        """
        Map Azure AD group GUIDs to Airflow role using config. Return default_role if no match.
        """
        for group in group_guids:
            if group in self.group_role_map:
                return self.group_role_map[group]
        return self.default_role

    def _validate_jwt(self, token: str) -> Dict[str, Any]:
        """
        Validate JWT using Azure AD JWKS. Returns claims if valid, raises if not.
        """
        signing_key = self.jwk_client.get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=self.client_id,
            options={"verify_exp": True, "verify_aud": True},
        )
        return claims

    def _extract_user_info(self, claims: Dict[str, Any]) -> Tuple[str, str, List[str]]:
        """
        Extract username, email, and group GUIDs from JWT claims.
        """
        username = claims.get("preferred_username") or claims.get("upn") or claims.get("email")
        email = claims.get("email") or claims.get("preferred_username") or claims.get("upn")
        group_guids = claims.get("groups", [])
        if not isinstance(group_guids, list):
            group_guids = []
        return username, email, group_guids

    # --- Abstract method implementations for Airflow 3 Auth Manager API ---

    def serialize_user(self, user: AzureAuthManagerUser) -> dict:
        return {
            "username": user.username,
            "email": user.email,
            "role": user.role,
        }

    def deserialize_user(self, token: dict) -> AzureAuthManagerUser:
        print("deserialize_user called", token)
        user = AzureAuthManagerUser(
            username=token.get("username"),
            email=token.get("email"),
            role=token.get("role"),
        )
        print("Restored user:", user.username, user.email, user.role)
        return user

    def filter_authorized_menu_items(self, menu_items, *, user):
        # For now, return all menu items (customize as needed)
        return menu_items

    def get_url_login(self, **kwargs):
        # Return the login URL for the FastAPI sub-app
        return "/auth/login"

    # --- Role hierarchy ---
    _role_order = {"viewer": 0, "user": 1, "op": 2, "admin": 3}

    def _has_role(self, user, min_role):
        user_role = (user.role or "viewer").lower()
        return self._role_order.get(user_role, 0) >= self._role_order.get(min_role, 0)

    def is_authorized_asset(self, *, method, details=None, user=None):
        return self._has_role(user, "op")

    def is_authorized_asset_alias(self, *, method, details=None, user=None):
        return self._has_role(user, "op")

    def is_authorized_backfill(self, *, method, details=None, user=None):
        return self._has_role(user, "user")

    def is_authorized_configuration(self, *, method, details=None, user=None):
        return self._has_role(user, "admin")

    def is_authorized_connection(self, *, method, details=None, user=None):
        return self._has_role(user, "op")

    def is_authorized_custom_view(self, *, method, resource_name, user=None):
        return self._has_role(user, "viewer")

    def is_authorized_dag(self, *, method, access_entity=None, details=None, user=None):
        # Allow 'user' and above for write, 'viewer' and above for read
        if method == "GET":
            return self._has_role(user, "viewer")
        return self._has_role(user, "user")

    def is_authorized_pool(self, *, method, details=None, user=None):
        return self._has_role(user, "op")

    def is_authorized_variable(self, *, method, details=None, user=None):
        return self._has_role(user, "op")

    def is_authorized_view(self, *, access_view, user=None):
        return self._has_role(user, "viewer")

    # TODO: Add logging and error handling


# TODO: Add helper functions for JWT validation, JWKS fetching, etc.
