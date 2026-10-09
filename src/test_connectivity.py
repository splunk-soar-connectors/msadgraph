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
import time

import httpx
from soar_sdk import logging
from soar_sdk.abstract import SOARClient
from soar_sdk.auth import AuthorizationCodeFlow

from .asset import Asset
from .auth import (
    begin_admin_consent,
    begin_delegated_authorization,
    get_client_credentials_flow,
    get_graph_client,
)
from .consts import (
    ADMIN_CONSENT_COMPLETE_STATE_KEY,
    ADMIN_CONSENT_ERROR_MESSAGE,
    ADMIN_CONSENT_STATE_KEY,
    AUTHORIZATION_ERROR_MESSAGE,
    AUTHORIZATION_ERROR_STATE_KEY,
    TEST_CONNECTIVITY_FAILED,
    TEST_CONNECTIVITY_PASSED,
)


AUTHORIZE_WAIT_TIME = 5
AUTHORIZATION_POLL_ATTEMPTS = 40
AUTHORIZATION_POLL_INTERVAL = 3
ADMIN_CONSENT_SETTLE_SECONDS = 30


def run_test_connectivity(
    soar: SOARClient,
    asset: Asset,
    *,
    oauth_callback_url: str,
    oauth_start_url: str,
) -> None:
    if asset.admin_access_required:
        _run_client_credentials_authentication(
            soar,
            asset,
            oauth_callback_url=oauth_callback_url,
            oauth_start_url=oauth_start_url,
        )
    else:
        _run_delegated_authentication(
            soar,
            asset,
            oauth_callback_url=oauth_callback_url,
            oauth_start_url=oauth_start_url,
        )

    logging.info("Getting info about a single user to verify token")
    try:
        with get_graph_client(asset, str(soar.get_asset_id())) as graph_client:
            response = graph_client.get("/users", params={"$top": "1"})
            response.raise_for_status()
    except httpx.HTTPError:
        logging.info("API to get users failed")
        logging.info(TEST_CONNECTIVITY_FAILED)
        raise

    if response.json().get("value"):
        logging.info("Got user info")
    logging.info(TEST_CONNECTIVITY_PASSED)


def _run_client_credentials_authentication(
    soar: SOARClient,
    asset: Asset,
    *,
    oauth_callback_url: str,
    oauth_start_url: str,
) -> None:
    if not asset.admin_access_granted:
        _run_admin_consent(
            soar,
            asset,
            oauth_callback_url=oauth_callback_url,
            oauth_start_url=oauth_start_url,
        )

    logging.info("Generating access token")
    get_client_credentials_flow(asset).authenticate()


def _run_delegated_authentication(
    soar: SOARClient,
    asset: Asset,
    *,
    oauth_callback_url: str,
    oauth_start_url: str,
) -> None:
    flow = begin_delegated_authorization(
        asset,
        str(soar.get_asset_id()),
        redirect_uri=oauth_callback_url,
    )
    _log_authorization_request(soar, oauth_callback_url, oauth_start_url)
    authorization_code = _wait_for_authorization_code(asset, flow)
    if not authorization_code:
        logging.info(AUTHORIZATION_ERROR_MESSAGE)
        logging.info(TEST_CONNECTIVITY_FAILED)
        raise ValueError(AUTHORIZATION_ERROR_MESSAGE)

    logging.info("Code Received")
    logging.info("Generating access token")
    flow.exchange_code_for_token(authorization_code)


def _run_admin_consent(
    soar: SOARClient,
    asset: Asset,
    *,
    oauth_callback_url: str,
    oauth_start_url: str,
) -> None:
    begin_admin_consent(
        asset,
        str(soar.get_asset_id()),
        redirect_uri=oauth_callback_url,
    )
    _log_authorization_request(soar, oauth_callback_url, oauth_start_url)
    _wait_for_admin_consent(asset)

    if not asset.auth_state.get(ADMIN_CONSENT_STATE_KEY, False):
        logging.info(ADMIN_CONSENT_ERROR_MESSAGE)
        logging.info(TEST_CONNECTIVITY_FAILED)
        raise ValueError(ADMIN_CONSENT_ERROR_MESSAGE)

    logging.info("Admin consent received")
    logging.info(
        "Waiting for 30 seconds before generating token. If action fails with "
        "'403: AccessDenied' error, please check permissions and re-run the "
        "'test connectivity' after some time."
    )
    logging.info(
        "Admin consent is already received. You can mark 'Admin Consent Already "
        "Provided' to True, unless you make changes in the permissions."
    )
    time.sleep(ADMIN_CONSENT_SETTLE_SECONDS)


def _log_authorization_request(
    soar: SOARClient, oauth_callback_url: str, oauth_start_url: str
) -> None:
    logging.info("Getting App REST endpoint URL")
    logging.info("Using OAuth URL:")
    logging.info(oauth_callback_url)
    logging.info(
        "Please connect to the following URL from a different tab to continue "
        "the connectivity process"
    )
    logging.info(f"{oauth_start_url}?asset_id={soar.get_asset_id()}&")  # nosemgrep
    logging.info(
        "If authorization URL fails to communicate with your SOAR instance, "
        "check the configured redirect URL and SOAR base URL."
    )
    time.sleep(AUTHORIZE_WAIT_TIME)


def _wait_for_authorization_code(
    asset: Asset, flow: AuthorizationCodeFlow
) -> str | None:
    logging.info("Waiting for authorization to complete")
    for index in range(AUTHORIZATION_POLL_ATTEMPTS):
        logging.progress("." * (index % 10))
        if authorization_error := asset.auth_state.get(AUTHORIZATION_ERROR_STATE_KEY):
            raise ValueError(authorization_error)
        if authorization_code := flow.client.get_authorization_code(force_reload=True):
            return authorization_code
        time.sleep(AUTHORIZATION_POLL_INTERVAL)
    logging.info("Authentication process does not seem to be completed. Timing out")
    logging.info(TEST_CONNECTIVITY_FAILED)
    raise TimeoutError(
        "Authentication process does not seem to be completed. Timing out"
    )


def _wait_for_admin_consent(asset: Asset) -> None:
    logging.info("Waiting for authorization to complete")
    for index in range(AUTHORIZATION_POLL_ATTEMPTS):
        logging.progress("." * (index % 10))
        if authorization_error := asset.auth_state.get(AUTHORIZATION_ERROR_STATE_KEY):
            raise ValueError(authorization_error)
        if asset.auth_state.get(ADMIN_CONSENT_COMPLETE_STATE_KEY, False):
            return
        time.sleep(AUTHORIZATION_POLL_INTERVAL)
    logging.info("Authentication process does not seem to be completed. Timing out")
    logging.info(TEST_CONNECTIVITY_FAILED)
    raise TimeoutError(
        "Authentication process does not seem to be completed. Timing out"
    )
