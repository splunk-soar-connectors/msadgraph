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
"""Real diagnostic formatting and schema checks, not Graph behavior tests."""

import json
import shlex

import httpx
import pytest

from src.actions.reset_password import (
    DIAGNOSTIC_PROBE_VALUE,
    ResetPasswordParams,
    ResetPasswordSummary,
    _password_shape,
    _redacted_reset_curl,
)
from src.app import create_msadgraph_app


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        pytest.param(
            "Aa1!",
            "length=4, ascii=True, ascii_letters=2, digits=1, non_ascii=0",
            id="mixed-ascii",
        ),
        pytest.param(
            "!@#",
            "length=3, ascii=True, ascii_letters=0, digits=0, non_ascii=0",
            id="punctuation",
        ),
        pytest.param(
            "\u2603\u2602",
            "length=2, ascii=False, ascii_letters=0, digits=0, non_ascii=2",
            id="unicode",
        ),
    ],
)
def test_password_diagnostics_only_report_shape(value, expected):
    actual = _password_shape(value)
    assert actual == expected
    assert value not in actual


def test_diagnostic_summary_is_registered_without_changing_sensitive_input():
    action = create_msadgraph_app().actions_manager.get_action("reset_password")
    fields = {field["data_path"] for field in action.meta.model_dump()["output"]}
    assert "action_result.summary.status" in fields
    assert "action_result.summary.diagnostics" in fields
    assert (
        ResetPasswordParams._to_json_schema()["temp_password"]["data_type"]
        == "password"
    )


def test_summary_preserves_multiline_diagnostics():
    summary = ResetPasswordSummary(
        status="Diagnostic action failed",
        diagnostics="Handler entered\nGraph response: HTTP 400",
    )
    assert summary.model_dump()["diagnostics"] == (
        "Handler entered\nGraph response: HTTP 400"
    )


def test_curl_uses_real_request_without_password_or_authentication():
    request = httpx.Request(
        "PATCH",
        "https://graph.microsoft.com/v1.0/users/diagnostic-user",
        headers={
            "Authorization": "Bearer diagnostic-token",
            "Cookie": "diagnostic-cookie",
        },
        json={
            "passwordProfile": {
                "forceChangePasswordNextSignIn": True,
                "password": DIAGNOSTIC_PROBE_VALUE,
            }
        },
    )
    actual = _redacted_reset_curl(request)
    arguments = shlex.split(actual)
    assert arguments[:3] == ["curl", "--request", "PATCH"]
    assert arguments[arguments.index("--url") + 1] == str(request.url)
    assert arguments.count("--header") == 1
    assert (
        arguments[arguments.index("--header") + 1] == "Content-Type: application/json"
    )
    assert json.loads(arguments[arguments.index("--data-raw") + 1]) == {
        "passwordProfile": {
            "forceChangePasswordNextSignIn": True,
            "password": "<REDACTED>",
        }
    }
    for value in (DIAGNOSTIC_PROBE_VALUE, "diagnostic-token", "diagnostic-cookie"):
        assert value not in actual
    assert (
        json.loads(request.content)["passwordProfile"]["password"]
        == DIAGNOSTIC_PROBE_VALUE
    )
