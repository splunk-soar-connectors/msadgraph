# Copyright (c) 2026 Splunk Inc.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
import json
from urllib.parse import urlsplit

import httpx
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import MakeRequestOutput
from soar_sdk.auth import OAuthClientError
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import MakeRequestParams, Param

from ..asset import Asset
from ..auth import get_graph_client
from ..consts import MICROSOFT_GRAPH_BASE_URLS


class MSADGraphMakeRequestParams(MakeRequestParams):
    endpoint: str = Param(
        description="Microsoft Graph path beginning with /v1.0/ or /beta/. Do not include the base URL.",
        required=True,
    )


def _json_object(value: str, name: str) -> dict:
    try:
        parsed = json.loads(value)
    except ValueError as error:
        raise ActionFailure(f"{name} must be a JSON object") from error
    if not isinstance(parsed, dict):
        raise ActionFailure(f"{name} must be a JSON object")
    return parsed


def _build_request(params: MSADGraphMakeRequestParams, region: str) -> httpx.Request:
    """Build the real request without acquiring credentials or sending it."""
    endpoint = params.endpoint.strip()
    parts = urlsplit(endpoint)
    if (
        parts.scheme
        or parts.netloc
        or parts.fragment
        or "#" in endpoint
        or "\\" in endpoint
        or any(ord(char) < 32 or ord(char) == 127 for char in endpoint)
    ):
        raise ActionFailure("Endpoint must be a relative Microsoft Graph path")
    endpoint = "/" + endpoint.lstrip("/")
    if not endpoint.startswith(("/v1.0/", "/beta/")):
        raise ActionFailure("Endpoint must begin with /v1.0/ or /beta/")
    method = params.http_method.upper()
    if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
        raise ActionFailure("Unsupported HTTP method")
    if params.timeout is not None and params.timeout <= 0:
        raise ActionFailure("Timeout must be greater than zero")

    headers = httpx.Headers(
        {"Accept": "application/json", "Content-Type": "application/json"}
    )
    if params.headers:
        custom = _json_object(params.headers, "Headers")
        if not all(isinstance(value, str) for value in custom.values()):
            raise ActionFailure("Header values must be strings")
        reserved = {
            "authorization",
            "proxy-authorization",
            "host",
            "content-length",
            "transfer-encoding",
            "connection",
        }
        if any(key.lower() in reserved for key in custom):
            raise ActionFailure(
                "Authentication, routing and framing headers cannot be overridden"
            )
        headers.update(custom)

    root = MICROSOFT_GRAPH_BASE_URLS[region].removesuffix("/v1.0")
    url = httpx.URL(root + endpoint)
    if params.query_parameters:
        raw_query = params.query_parameters
        try:
            query = json.loads(raw_query)
        except ValueError as error:
            if raw_query.lstrip().startswith(("{", "[")):
                raise ActionFailure("Query parameters contain invalid JSON") from error
            query = httpx.QueryParams(raw_query.lstrip("?"))
        if not isinstance(query, dict | httpx.QueryParams):
            raise ActionFailure(
                "Query parameters must be a JSON object or query string"
            )
        url = url.copy_merge_params(query)

    body = params.body
    if body == "":
        body = None
    if body is not None and "json" in headers.get("Content-Type", "").lower():
        try:
            body = json.dumps(json.loads(body))
        except ValueError as error:
            raise ActionFailure("Body contains invalid JSON") from error
    return httpx.Request(
        method,
        url,
        headers=headers,
        content=body.encode() if body is not None else None,
    )


def make_request(
    params: MSADGraphMakeRequestParams, soar: SOARClient, asset: Asset
) -> MakeRequestOutput:
    """Call Microsoft Graph with the asset's authentication; return its HTTP status and raw body.

    Uses the asset's configured Microsoft cloud. Supply an explicit /v1.0/ or
    /beta/ path. Redirects are not followed. HTTP errors are returned as data;
    invalid inputs, authentication and transport failures fail the action.
    One response is returned; pagination is not followed automatically.
    """
    try:
        request = _build_request(params, asset.region or "Global")
        with get_graph_client(
            asset, str(soar.get_asset_id()), verify=params.verify_ssl
        ) as client:
            response = client.request(
                request.method,
                request.url,
                headers=request.headers,
                content=request.content,
                timeout=params.timeout or 30,
                follow_redirects=False,
            )
        return MakeRequestOutput(
            status_code=response.status_code, response_body=response.text
        )
    except ActionFailure:
        raise
    except (httpx.HTTPError, OAuthClientError, ValueError) as error:
        # Do not echo request URLs, bodies, custom headers or token responses.
        raise ActionFailure(
            f"Microsoft Graph request failed ({type(error).__name__})"
        ) from None
