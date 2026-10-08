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

from soar_sdk.auth import AuthorizationCodeFlow, ClientCredentialsFlow

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
    MICROSOFT_GRAPH_APPLICATION_SCOPE,
    MICROSOFT_GRAPH_DELEGATED_SCOPE,
    MICROSOFT_LOGIN_BASE_URL,
    REDIRECT_URI_STATE_KEY,
)


def is_client_credentials_auth(asset: Asset) -> bool:
    return bool(asset.admin_access_required)


def get_authorization_code_flow(
    asset: Asset,
    asset_id: str,
    *,
    redirect_uri: str,
) -> AuthorizationCodeFlow:
    tenant_id = asset.tenant_id.strip()
    return AuthorizationCodeFlow(
        asset.auth_state,
        asset_id,
        client_id=asset.client_id,
        client_secret=asset.client_secret,
        authorization_endpoint=(
            f"{MICROSOFT_LOGIN_BASE_URL}/{tenant_id}/oauth2/v2.0/authorize"
        ),
        token_endpoint=(f"{MICROSOFT_LOGIN_BASE_URL}/{tenant_id}/oauth2/v2.0/token"),
        redirect_uri=redirect_uri,
        scope=MICROSOFT_GRAPH_DELEGATED_SCOPE,
        extra_token_params={"scope": MICROSOFT_GRAPH_DELEGATED_SCOPE},
        use_pkce=False,
    )


def get_client_credentials_flow(asset: Asset) -> ClientCredentialsFlow:
    tenant_id = asset.tenant_id.strip()
    return ClientCredentialsFlow(
        asset.auth_state,
        client_id=asset.client_id,
        client_secret=asset.client_secret,
        token_endpoint=(f"{MICROSOFT_LOGIN_BASE_URL}/{tenant_id}/oauth2/v2.0/token"),
        scope=MICROSOFT_GRAPH_APPLICATION_SCOPE,
    )


def build_admin_consent_url(
    tenant_id: str,
    client_id: str,
    redirect_uri: str,
    state: str,
) -> str:
    query = urllib.parse.urlencode(
        {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "state": state,
        }
    )
    return f"{MICROSOFT_LOGIN_BASE_URL}/{tenant_id}/adminconsent?{query}"


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
