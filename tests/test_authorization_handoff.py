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
"""Local handoff-record validity, not a substitute for live callback validation."""

import time

import pytest

from src.auth import authorization_handoff_is_active
from src.consts import AUTHORIZATION_EXPIRES_AT_STATE_KEY, AUTHORIZATION_NONCE_STATE_KEY


@pytest.mark.parametrize(
    "deadline", [None, 0, True, "future", float("inf"), float("nan")]
)
def test_expired_or_invalid_deadlines_are_rejected(deadline):
    state = {
        AUTHORIZATION_NONCE_STATE_KEY: "public-handoff",
        AUTHORIZATION_EXPIRES_AT_STATE_KEY: deadline,
    }
    assert not authorization_handoff_is_active(state)


def test_missing_deadline_fails_closed():
    assert not authorization_handoff_is_active(
        {AUTHORIZATION_NONCE_STATE_KEY: "public-handoff"}
    )


def test_current_handoff_is_distinguished_from_a_superseded_flow():
    state = {
        AUTHORIZATION_NONCE_STATE_KEY: "current-public-handoff",
        AUTHORIZATION_EXPIRES_AT_STATE_KEY: time.time() + 60,
    }
    assert authorization_handoff_is_active(state, "current-public-handoff")
    assert not authorization_handoff_is_active(state, "previous-public-handoff")


@pytest.mark.parametrize("nonce", [None, "", 12])
def test_missing_or_invalid_nonce_is_rejected(nonce):
    state = {
        AUTHORIZATION_NONCE_STATE_KEY: nonce,
        AUTHORIZATION_EXPIRES_AT_STATE_KEY: time.time() + 60,
    }
    assert not authorization_handoff_is_active(state)
