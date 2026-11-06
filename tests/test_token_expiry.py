# Copyright (c) 2026 Splunk Inc.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
"""Real SDK token-model checks, without HTTP substitutes or live credentials.

These checks do not establish token-endpoint outage or live upgrade behavior.
"""

import time
from copy import deepcopy

import pytest
from soar_sdk.auth.models import OAuthToken

from src.auth import _cached_token_is_usable, _migrate_legacy_token


@pytest.mark.parametrize("refresh_token", [None, "public-refresh-marker"])
def test_final_seconds_remain_usable_despite_sdk_early_expiry(refresh_token):
    token = OAuthToken(
        access_token="public-access-marker",
        refresh_token=refresh_token,
        expires_at=time.time() + 20,
    )

    assert token.is_expired()  # The SDK's default leeway would refresh early.
    assert _cached_token_is_usable(token)


def test_actually_expired_and_missing_tokens_are_not_reused():
    token = OAuthToken(access_token="public-access-marker", expires_at=time.time() - 1)

    assert not _cached_token_is_usable(token)
    assert not _cached_token_is_usable(None)


@pytest.mark.parametrize(
    "expiry", [None, "invalid", True, {}, float("nan"), float("inf")]
)
@pytest.mark.parametrize("refresh_token", [None, "public-refresh-marker"])
def test_unknown_legacy_expiry_does_not_invent_a_fresh_lifetime(expiry, refresh_token):
    legacy = {
        "access_token": "public-access-marker",
        "expires_at": expiry,
        "expires_in": 3600,
        "refresh_token": refresh_token,
    }
    original = deepcopy(legacy)

    token = _migrate_legacy_token(legacy)

    assert token.expires_at is None
    assert token.expires_in is None
    assert token.refresh_token == refresh_token
    assert _cached_token_is_usable(token)
    assert legacy.keys() == original.keys()
    assert legacy["expires_in"] == original["expires_in"]


def test_legacy_token_without_any_expiry_retains_unknown_age():
    token = _migrate_legacy_token({"access_token": "public-access-marker"})

    assert token.expires_at is None
    assert _cached_token_is_usable(token)


@pytest.mark.parametrize("offset", [-1, 20, 3600])
def test_legacy_absolute_expiry_is_preserved(offset):
    expiry = time.time() + offset
    token = _migrate_legacy_token(
        {
            "access_token": "public-access-marker",
            "expires_at": expiry,
            "expires_in": 3600,
        }
    )

    assert token.expires_at == expiry
    assert _cached_token_is_usable(token) is (offset > 0)


def test_stored_zero_expiry_is_not_reinterpreted_as_unknown():
    token = _migrate_legacy_token(
        {"access_token": "public-access-marker", "expires_at": 0, "expires_in": 3600}
    )

    assert token.expires_at == 0
    assert not _cached_token_is_usable(token)
