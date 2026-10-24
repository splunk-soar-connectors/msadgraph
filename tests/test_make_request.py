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
"""Real input models, request serialization and registration; no HTTP substitutes.

These checks do not establish Graph behavior. Packaged action coverage lives in
app-tests/suite/apps/msadgraph/make_request_actions.py.
"""

import json

import httpx
import pytest
from soar_sdk.action_results import MakeRequestOutput
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import MakeRequestParams

from src.actions.make_request import MSADGraphMakeRequestParams, _build_request
from src.app import create_msadgraph_app
from src.consts import MICROSOFT_GRAPH_BASE_URLS


def request(**overrides):
    return _build_request(
        MSADGraphMakeRequestParams(
            **{"http_method": "GET", "endpoint": "/v1.0/users", **overrides}
        ),
        "Global",
    )


@pytest.mark.parametrize("region,base", MICROSOFT_GRAPH_BASE_URLS.items())
@pytest.mark.parametrize("version", ["v1.0", "beta"])
def test_versioned_url_uses_configured_cloud(region, base, version):
    params = MSADGraphMakeRequestParams(http_method="GET", endpoint=f"/{version}/users")
    actual = _build_request(params, region)
    assert str(actual.url) == base.removesuffix("/v1.0") + f"/{version}/users"


@pytest.mark.parametrize("endpoint", ["/v1.0/users", "v1.0/users", " /v1.0/users "])
def test_optional_leading_slash_and_outer_whitespace(endpoint):
    assert (
        str(request(endpoint=endpoint).url) == "https://graph.microsoft.com/v1.0/users"
    )


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://example.com/v1.0/users",
        "http://example.com/",
        "//example.com/v1.0/users",
        "https://graph.microsoft.com/v1.0/users",
        "/users",
        "/v2.0/users",
        "",
        "/beta",
        "/v1.0/users#fragment",
        "/v1.0/users#",
        "/v1.0/\\example.com",
        "/v1.0/users\r\nHost: example.com",
    ],
)
def test_rejects_unversioned_and_unsafe_endpoints(endpoint):
    with pytest.raises(ActionFailure):
        request(endpoint=endpoint)


@pytest.mark.parametrize(
    "method", ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "get"]
)
def test_standard_methods(method):
    assert request(http_method=method).method == method.upper()


def test_unsupported_method_is_rejected():
    with pytest.raises(ActionFailure, match="Unsupported HTTP method"):
        request(http_method="TRACE")


@pytest.mark.parametrize("timeout", [0, -1])
def test_nonpositive_timeout_is_rejected(timeout):
    with pytest.raises(ActionFailure, match="Timeout"):
        request(timeout=timeout)


@pytest.mark.parametrize(
    "query",
    ['{"$top": 1, "$select": "id,displayName"}', "?$top=1&$select=id%2CdisplayName"],
)
def test_query_merges_with_existing_endpoint_query(query):
    actual = request(endpoint="/v1.0/users?$count=true", query_parameters=query)
    assert actual.url.params == httpx.QueryParams(
        {"$count": "true", "$top": "1", "$select": "id,displayName"}
    )


def test_query_string_preserves_repetition_and_blank_values():
    actual = request(query_parameters="key=one&key=two&blank=")
    assert actual.url.params.get_list("key") == ["one", "two"]
    assert actual.url.params["blank"] == ""


@pytest.mark.parametrize("query", ["[]", "null", "1", '{"$top":'])
def test_invalid_query_shapes_are_rejected(query):
    with pytest.raises(ActionFailure, match="Query parameters"):
        request(query_parameters=query)


def test_custom_headers_are_case_insensitive():
    actual = request(
        headers='{"content-type": "text/plain", "ConsistencyLevel": "eventual"}',
        body="hello",
    )
    assert actual.headers["Content-Type"] == "text/plain"
    assert actual.headers["ConsistencyLevel"] == "eventual"
    assert actual.content == b"hello"


@pytest.mark.parametrize(
    "header",
    [
        "Authorization",
        "aUtHoRiZaTiOn",
        "Proxy-Authorization",
        "Host",
        "Content-Length",
        "Transfer-Encoding",
        "Connection",
    ],
)
def test_reserved_headers_are_rejected(header):
    with pytest.raises(ActionFailure, match="cannot be overridden"):
        request(headers=json.dumps({header: "secret-not-to-be-echoed"}))


@pytest.mark.parametrize("headers", ["[]", '"string"', "null", '{"Accept": 1}', "{bad"])
def test_invalid_headers_are_rejected_without_echoing_input(headers):
    with pytest.raises(ActionFailure) as error:
        request(headers=headers)
    assert headers not in str(error.value)


@pytest.mark.parametrize(
    "body", ['{"displayName": "你好"}', "[]", "false", "0", "null", '"text"', '""']
)
def test_json_body_preserves_values_including_falsy_and_scalar(body):
    actual = request(http_method="POST", body=body)
    assert json.loads(actual.content) == json.loads(body)


def test_absent_body_is_not_json_null():
    assert request().content == b""
    assert request(body="").content == b""
    assert request(body="null").content == b"null"


@pytest.mark.parametrize("body", ["{bad", "not-json"])
def test_invalid_json_body_is_rejected_without_echoing_input(body):
    with pytest.raises(ActionFailure, match="Body contains invalid JSON"):
        request(body=body)


def test_non_json_body_is_encoded_as_utf8():
    actual = request(
        headers='{"Content-Type": "text/plain; charset=utf-8"}', body="你好"
    )
    assert actual.content == "你好".encode()


def test_registration_uses_native_sdk_contract():
    action = create_msadgraph_app().actions_manager.get_action("make_request")
    assert issubclass(action.params_class, MakeRequestParams)
    assert action.meta.output is MakeRequestOutput
    assert action.meta.read_only is False
    assert action.meta.action == "make request"
    params = MSADGraphMakeRequestParams(http_method="GET", endpoint="/v1.0/users")
    assert params.verify_ssl is True
    assert params.timeout is None
