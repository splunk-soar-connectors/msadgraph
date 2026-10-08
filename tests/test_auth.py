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
import urllib.parse

from soar_sdk.asset_state import AssetState
from soar_sdk.shims.phantom.base_connector import BaseConnector
from soar_sdk.webhooks.models import WebhookRequest

from src.asset import Asset
from src.auth import (
    begin_admin_consent,
    begin_delegated_authorization,
    build_admin_consent_url,
    is_client_credentials_auth,
)
from src.client import get_graph_base_url
from src.consts import (
    ADMIN_CONSENT_COMPLETE_STATE_KEY,
    ADMIN_CONSENT_STATE_KEY,
    OAUTH_CALLBACK_ROUTE,
)
from src.webhooks.oauth import oauth_callback


def build_asset(*, admin_access_required: bool = False) -> Asset:
    asset = Asset(
        tenant_id="tenant.example",
        client_id="client-id",
        client_secret="client-secret",  # pragma: allowlist secret
        region="Global",
        admin_access_required=admin_access_required,
        admin_access_granted=False,
    )
    asset._auth_state = AssetState(
        BaseConnector(),
        "auth",
        "123",
        encrypted=False,
    )
    return asset


def build_callback_request(asset: Asset, query: dict[str, list[str]]) -> WebhookRequest:
    return WebhookRequest(
        method="GET",
        headers={},
        path_parts=[OAUTH_CALLBACK_ROUTE],
        query=query,
        body=None,
        asset=asset,
        soar_base_url="https://soar.example",
        soar_auth_token="",
        asset_id=123,
    )


def test_auth_mode_preserves_legacy_admin_access_switch() -> None:
    assert is_client_credentials_auth(build_asset(admin_access_required=True))
    assert not is_client_credentials_auth(build_asset(admin_access_required=False))


def test_delegated_callback_validates_sdk_session_and_stores_code() -> None:
    asset = build_asset()
    flow = begin_delegated_authorization(
        asset,
        "123",
        redirect_uri="https://soar.example/oauth_callback",
    )
    session = flow.client.get_pending_session()
    assert session is not None

    response = oauth_callback(
        build_callback_request(
            asset,
            {"state": [session.state], "code": ["authorization-code"]},
        )
    )

    assert response.status_code == 200
    assert flow.client.get_authorization_code() == "authorization-code"


def test_admin_consent_callback_persists_success() -> None:
    asset = build_asset(admin_access_required=True)
    authorization_url = begin_admin_consent(
        asset,
        "123",
        redirect_uri="https://soar.example/oauth_callback",
    )
    query = urllib.parse.parse_qs(urllib.parse.urlparse(authorization_url).query)

    response = oauth_callback(
        build_callback_request(
            asset,
            {"state": query["state"], "admin_consent": ["True"]},
        )
    )

    assert response.status_code == 200
    assert asset.auth_state[ADMIN_CONSENT_COMPLETE_STATE_KEY] is True
    assert asset.auth_state[ADMIN_CONSENT_STATE_KEY] is True


def test_admin_consent_url_encodes_all_values() -> None:
    url = build_admin_consent_url(
        "tenant/name",
        "client id",
        "https://soar.example/callback?one=two",
        "asset_id=123&nonce=nonce-value",
    )
    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qs(parsed.query)

    assert parsed.path == "/tenant/name/adminconsent"
    assert query == {
        "client_id": ["client id"],
        "redirect_uri": ["https://soar.example/callback?one=two"],
        "state": ["asset_id=123&nonce=nonce-value"],
    }


def test_graph_base_url_preserves_legacy_tenant_path() -> None:
    asset = build_asset()
    asset.tenant_id = "tenant/name"

    assert get_graph_base_url(asset) == (
        "https://graph.microsoft.com/v1.0/tenant%2Fname"
    )


def test_client_secret_is_emitted_as_password() -> None:
    assert Asset.to_json_schema()["client_secret"]["data_type"] == "password"
