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
"""Configuration and scope-change checks only; no substituted OAuth services.

Token issuance, refresh, persisted sessions, callbacks and Graph authorization
require live delegated app-tests and are not established by these checks.
"""

import pytest
from soar_sdk.auth.client import AuthorizationRequiredError

from src.asset import Asset
from src.auth import get_delegated_scopes, require_matching_delegated_scopes
from src.consts import MICROSOFT_GRAPH_DELEGATED_SCOPE


def asset(**overrides):
    return Asset(
        tenant_id="tenant",
        client_id="client",
        client_secret="not-a-live-credential",  # pragma: allowlist secret
        **overrides,
    )


@pytest.mark.parametrize("value", [None, "", " ", "\t\n"])
def test_blank_configuration_preserves_exact_legacy_scope_list(value):
    assert get_delegated_scopes(asset(delegated_oauth_scopes=value)) == (
        MICROSOFT_GRAPH_DELEGATED_SCOPE
    )


def test_existing_asset_without_new_field_preserves_defaults():
    assert asset().delegated_oauth_scopes is None
    assert get_delegated_scopes(asset()) == MICROSOFT_GRAPH_DELEGATED_SCOPE


def test_scope_setting_is_optional_connectivity_configuration_in_sdk_manifest():
    field = Asset.to_json_schema()["delegated_oauth_scopes"]
    assert field["data_type"] == "string"
    assert field["required"] is False
    assert field["category"] == "connectivity"


@pytest.mark.parametrize(
    "configured,expected",
    [
        ("Policy.Read.All", "Policy.Read.All"),
        ("offline_access User.Read.All", "offline_access User.Read.All"),
        ("  offline_access\nUser.Read.All\t", "offline_access User.Read.All"),
    ],
)
def test_custom_scopes_replace_defaults_without_adding_permissions(
    configured, expected
):
    assert get_delegated_scopes(asset(delegated_oauth_scopes=configured)) == expected


def test_unmarked_existing_session_is_compatible_with_default_configuration():
    require_matching_delegated_scopes(MICROSOFT_GRAPH_DELEGATED_SCOPE, None)


def test_order_whitespace_and_repeated_scopes_do_not_require_reauthorization():
    require_matching_delegated_scopes(
        "User.Read.All offline_access User.Read.All", "offline_access\nUser.Read.All"
    )


@pytest.mark.parametrize(
    "requested,authorized",
    [
        ("User.Read.All", None),
        ("User.Read.All", MICROSOFT_GRAPH_DELEGATED_SCOPE),
        (MICROSOFT_GRAPH_DELEGATED_SCOPE, "User.Read.All"),
        ("User.Read.All Group.Read.All", "User.Read.All"),
        ("User.Read.All", "User.Read.All Group.Read.All"),
        ("User.Read.All", "user.read.all"),
        ("User.Read.All", []),
        ("User.Read.All", ""),
    ],
)
def test_changed_or_invalid_scope_binding_requires_explicit_authorization(
    requested, authorized
):
    with pytest.raises(AuthorizationRequiredError, match="Run test connectivity"):
        require_matching_delegated_scopes(requested, authorized)
