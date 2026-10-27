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
"""Test trace redaction only; this does not emulate SOAR storage or Graph."""

import json

from src.oauth_trace import state_labels


def test_trace_labels_exclude_credentials_and_codes():
    labels = state_labels(
        {
            "auth": {
                "authorization_nonce": "public-nonce-marker",
                "authorization_url": "https://example.test/authorize?state=public-nonce-marker",
                "oauth": {
                    "token": {
                        "access_token": "public-access-marker",
                        "refresh_token": "public-refresh-marker",
                    },
                    "session": {
                        "state": "public-session-marker",
                        "auth_code": "public-code-marker",
                    },
                },
            }
        },
        "1",
    )
    assert set(labels) == {"nonce", "session", "url"}
    assert labels["nonce"] == labels["url"]
    assert labels["session"] != labels["nonce"]
    assert "marker" not in json.dumps(labels)
    assert all(len(value) == 16 for value in labels.values())
