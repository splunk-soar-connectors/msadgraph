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
from typing import Any

import httpx
from soar_sdk.auth import OAuthToken, StaticTokenAuth

from .asset import Asset
from .auth import (
    get_authorization_code_flow,
    get_client_credentials_flow,
    is_client_credentials_auth,
)
from .consts import MICROSOFT_GRAPH_BASE_URLS, REDIRECT_URI_STATE_KEY


GRAPH_PAGE_SIZE = 999


class GraphAPIError(RuntimeError):
    """An error response or invalid payload returned by Microsoft Graph."""


def get_graph_base_url(asset: Asset) -> str:
    region = asset.region or "Global"
    return MICROSOFT_GRAPH_BASE_URLS[region].rstrip("/")


def get_graph_token(asset: Asset, asset_id: str) -> OAuthToken:
    """Return a valid token for the asset's configured OAuth grant."""

    if is_client_credentials_auth(asset):
        return get_client_credentials_flow(asset).get_token()

    redirect_uri = asset.auth_state.get(REDIRECT_URI_STATE_KEY)
    if not isinstance(redirect_uri, str) or not redirect_uri:
        raise ValueError(
            "No delegated OAuth session is available. Run test connectivity first."
        )
    return get_authorization_code_flow(
        asset,
        asset_id,
        redirect_uri=redirect_uri,
    ).get_token()


def get_graph_client(asset: Asset, token: OAuthToken) -> httpx.Client:
    return httpx.Client(
        base_url=get_graph_base_url(asset),
        auth=StaticTokenAuth(token),
        timeout=30.0,
    )


def get_graph_collection(
    client: httpx.Client,
    endpoint: str,
    *,
    headers: dict[str, str] | None = None,
    params: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Read every page of a Microsoft Graph collection."""

    items: list[dict[str, Any]] = []
    next_url: str | None = endpoint
    next_params = params

    while next_url:
        response = client.get(next_url, headers=headers, params=next_params)
        payload = _graph_json(response)
        page = payload.get("value")
        if not isinstance(page, list):
            raise GraphAPIError("Microsoft Graph response did not contain a list value")
        if not all(isinstance(item, dict) for item in page):
            raise GraphAPIError("Microsoft Graph returned an invalid collection item")
        items.extend(page)

        raw_next_url = payload.get("@odata.nextLink") or payload.get("odata.nextLink")
        if raw_next_url is not None and not isinstance(raw_next_url, str):
            raise GraphAPIError("Microsoft Graph returned an invalid next page URL")
        next_url = raw_next_url
        next_params = None

    return items


def _graph_json(response: httpx.Response) -> dict[str, Any]:
    try:
        payload = response.json()
    except ValueError as error:
        if response.is_success:
            raise GraphAPIError(
                "Unable to parse JSON response from Microsoft Graph"
            ) from error
        response.raise_for_status()
        raise

    if not response.is_success:
        error_detail: object = payload
        graph_error = payload.get("error") if isinstance(payload, dict) else None
        if isinstance(graph_error, dict) and graph_error.get("message"):
            error_detail = graph_error["message"]
        elif graph_error:
            error_detail = graph_error
        raise GraphAPIError(
            "Error from server. "
            f"Status Code: {response.status_code}. "
            f"Data from server: \n{error_detail}\n"
        )

    if not isinstance(payload, dict):
        raise GraphAPIError("Microsoft Graph returned a non-object JSON response")
    return payload
