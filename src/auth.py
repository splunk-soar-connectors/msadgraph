# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import secrets
import urllib.parse
from copy import deepcopy

import httpx
from soar_sdk.auth import (
    AuthorizationCodeFlow,
    ClientCredentialsFlow,
    OAuthBearerAuth,
)
from soar_sdk.auth.models import OAuthState, OAuthToken
from soar_sdk.shims.phantom.encryption_helper import encryption_helper

from .asset import Asset
from .consts import (
    ADMIN_CONSENT_COMPLETE_STATE_KEY,
    ADMIN_CONSENT_NONCE_STATE_KEY,
    ADMIN_CONSENT_STATE_KEY,
    AUTH_FLOW_MODE_ADMIN_CONSENT,
    AUTH_FLOW_MODE_DELEGATED,
    AUTH_FLOW_MODE_STATE_KEY,
    AUTHORIZATION_ERROR_STATE_KEY,
    AUTHORIZATION_URL_STATE_KEY,
    MICROSOFT_GRAPH_BASE_URLS,
    MICROSOFT_GRAPH_DELEGATED_SCOPE,
    MICROSOFT_LOGIN_BASE_URLS,
    REDIRECT_URI_STATE_KEY,
)


def get_authorization_code_flow(
    asset: Asset,
    asset_id: str,
    *,
    redirect_uri: str,
) -> AuthorizationCodeFlow:
    tenant_id = asset.tenant_id.strip()
    login_url = MICROSOFT_LOGIN_BASE_URLS[asset.region or "Global"]
    return AuthorizationCodeFlow(
        asset.auth_state,
        asset_id,
        client_id=asset.client_id,
        client_secret=asset.client_secret,
        authorization_endpoint=(f"{login_url}/{tenant_id}/oauth2/v2.0/authorize"),
        token_endpoint=(f"{login_url}/{tenant_id}/oauth2/v2.0/token"),
        redirect_uri=redirect_uri,
        scope=MICROSOFT_GRAPH_DELEGATED_SCOPE,
        extra_token_params={"scope": MICROSOFT_GRAPH_DELEGATED_SCOPE},
        use_pkce=False,
    )


def get_client_credentials_flow(asset: Asset) -> ClientCredentialsFlow:
    tenant_id = asset.tenant_id.strip()
    region = asset.region or "Global"
    login_url = MICROSOFT_LOGIN_BASE_URLS[region]
    graph_root = MICROSOFT_GRAPH_BASE_URLS[region].removesuffix("/v1.0")
    return ClientCredentialsFlow(
        asset.auth_state,
        client_id=asset.client_id,
        client_secret=asset.client_secret,
        token_endpoint=(f"{login_url}/{tenant_id}/oauth2/v2.0/token"),
        scope=f"{graph_root}/.default",
    )


def get_delegated_redirect_uri(asset: Asset, asset_id: str) -> str:
    """Migrate an authorized legacy asset before using its delegated session."""
    state = asset.auth_state.get_all()
    if "oauth" not in state:
        legacy_state = asset.auth_state.backend.load_state() or {}
        redirect_uri = legacy_state.get(REDIRECT_URI_STATE_KEY)
        legacy_token = deepcopy(legacy_state.get("token") or {})
        code = legacy_state.get("code")
        if isinstance(redirect_uri, str) and redirect_uri and (legacy_token or code):
            if legacy_state.get("is_encrypted"):
                try:
                    for key in ("access_token", "refresh_token"):
                        if legacy_token.get(key):
                            legacy_token[key] = encryption_helper.decrypt(
                                legacy_token[key], asset_id
                            )
                    if code and not legacy_token:
                        code = encryption_helper.decrypt(code, asset_id)
                except Exception as error:
                    raise ValueError(
                        "Unable to decrypt the legacy OAuth session. Run test connectivity again."
                    ) from error
            if legacy_token:
                # Legacy stores relative expires_in without the acquisition time.
                # Refresh rather than treating an old access token as newly issued.
                legacy_token["expires_at"] = 0
                token = OAuthToken.model_validate(legacy_token)
                state["oauth"] = OAuthState(
                    token=token, client_id=asset.client_id
                ).model_dump(mode="json", exclude_none=True)
            else:
                flow = get_authorization_code_flow(
                    asset, asset_id, redirect_uri=redirect_uri
                )
                token = flow.exchange_code_for_token(code)
                flow.client._store_token(token)
                state = asset.auth_state.get_all()
            state.setdefault(REDIRECT_URI_STATE_KEY, redirect_uri)
            asset.auth_state.put_all(state)

    redirect_uri = state.get(REDIRECT_URI_STATE_KEY)
    if not isinstance(redirect_uri, str) or not redirect_uri:
        raise ValueError(
            "No delegated OAuth session is available. Run test connectivity first."
        )
    return redirect_uri


def get_graph_client(asset: Asset, asset_id: str) -> httpx.Client:
    """Return an authenticated Microsoft Graph HTTP client for the asset."""

    base_url = MICROSOFT_GRAPH_BASE_URLS[asset.region or "Global"].rstrip("/")

    if asset.admin_access_required:
        token = get_client_credentials_flow(asset).get_token()
        return httpx.Client(
            base_url=base_url,
            headers={
                "Authorization": (
                    f"{token.token_type or 'Bearer'} {token.access_token}"
                )
            },
            timeout=30.0,
        )

    redirect_uri = get_delegated_redirect_uri(asset, asset_id)
    flow = get_authorization_code_flow(
        asset,
        asset_id,
        redirect_uri=redirect_uri,
    )
    return httpx.Client(
        base_url=base_url,
        auth=OAuthBearerAuth(flow.client),
        timeout=30.0,
    )


def build_admin_consent_url(
    tenant_id: str,
    client_id: str,
    redirect_uri: str,
    state: str,
    region: str = "Global",
) -> str:
    query = urllib.parse.urlencode(
        {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "state": state,
        }
    )
    login_url = MICROSOFT_LOGIN_BASE_URLS[region]
    return f"{login_url}/{tenant_id}/adminconsent?{query}"


def begin_delegated_authorization(
    asset: Asset,
    asset_id: str,
    *,
    redirect_uri: str,
) -> AuthorizationCodeFlow:
    clear_authorization_handoff(asset)
    flow = get_authorization_code_flow(asset, asset_id, redirect_uri=redirect_uri)
    authorization_url = flow.get_authorization_url()
    state = asset.auth_state.get_all()
    state.update(
        {
            AUTH_FLOW_MODE_STATE_KEY: AUTH_FLOW_MODE_DELEGATED,
            AUTHORIZATION_URL_STATE_KEY: authorization_url,
            REDIRECT_URI_STATE_KEY: redirect_uri,
        }
    )
    asset.auth_state.put_all(state)
    return flow


def begin_admin_consent(
    asset: Asset,
    asset_id: str,
    *,
    redirect_uri: str,
) -> str:
    clear_authorization_handoff(asset)
    nonce = secrets.token_urlsafe(32)
    state_value = urllib.parse.urlencode({"asset_id": asset_id, "nonce": nonce})
    authorization_url = build_admin_consent_url(
        asset.tenant_id.strip(),
        asset.client_id,
        redirect_uri,
        state_value,
        asset.region or "Global",
    )
    state = asset.auth_state.get_all()
    state.update(
        {
            AUTH_FLOW_MODE_STATE_KEY: AUTH_FLOW_MODE_ADMIN_CONSENT,
            AUTHORIZATION_URL_STATE_KEY: authorization_url,
            REDIRECT_URI_STATE_KEY: redirect_uri,
            ADMIN_CONSENT_NONCE_STATE_KEY: state_value,
            ADMIN_CONSENT_COMPLETE_STATE_KEY: False,
            ADMIN_CONSENT_STATE_KEY: False,
        }
    )
    asset.auth_state.put_all(state)
    return authorization_url


def clear_authorization_handoff(asset: Asset) -> None:
    state = asset.auth_state.get_all()
    for key in (
        AUTHORIZATION_ERROR_STATE_KEY,
        AUTHORIZATION_URL_STATE_KEY,
        REDIRECT_URI_STATE_KEY,
        AUTH_FLOW_MODE_STATE_KEY,
        ADMIN_CONSENT_NONCE_STATE_KEY,
        ADMIN_CONSENT_COMPLETE_STATE_KEY,
    ):
        state.pop(key, None)
    asset.auth_state.put_all(state)
