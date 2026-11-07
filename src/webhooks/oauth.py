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
import hmac

from soar_sdk.app import App
from soar_sdk.auth.client import AuthorizationRequiredError
from soar_sdk.webhooks.models import WebhookRequest, WebhookResponse

from ..auth import (
    authorization_handoff_is_active,
    get_authorization_code_flow,
    get_pending_delegated_scopes,
)
from ..consts import (
    ADMIN_CONSENT_COMPLETE_STATE_KEY,
    ADMIN_CONSENT_NONCE_STATE_KEY,
    ADMIN_CONSENT_STATE_KEY,
    AUTH_FLOW_MODE_ADMIN_CONSENT,
    AUTH_FLOW_MODE_DELEGATED,
    AUTH_FLOW_MODE_STATE_KEY,
    AUTHORIZATION_ERROR_STATE_KEY,
    AUTHORIZATION_URL_STATE_KEY,
    OAUTH_CALLBACK_ROUTE,
    OAUTH_START_ROUTE,
    REDIRECT_URI_STATE_KEY,
)


def _query_values(request: WebhookRequest) -> dict[str, str]:
    return {name: values[0] if values else "" for name, values in request.query.items()}


def _save_authorization_error(request: WebhookRequest, message: str) -> None:
    state = request.asset.auth_state.get_all()
    state[AUTHORIZATION_ERROR_STATE_KEY] = message
    request.asset.auth_state.put_all(state)


def oauth_start(request: WebhookRequest) -> WebhookResponse:
    if not authorization_handoff_is_active(
        request.asset.auth_state.get_all(force_reload=True)
    ):
        return WebhookResponse.text_response(
            "No active OAuth authorization request is pending.", status_code=400
        )
    authorization_url = request.asset.auth_state.get(AUTHORIZATION_URL_STATE_KEY)
    if not authorization_url:
        return WebhookResponse.text_response(
            "No OAuth authorization request is pending.", status_code=400
        )
    if (
        request.asset.auth_state.get(AUTH_FLOW_MODE_STATE_KEY)
        == AUTH_FLOW_MODE_DELEGATED
    ):
        try:
            get_pending_delegated_scopes(request.asset)
        except AuthorizationRequiredError as error:
            _save_authorization_error(request, str(error))
            return WebhookResponse.text_response(str(error), status_code=400)
    return WebhookResponse(
        status_code=302,
        headers=[("Location", authorization_url)],
        content="",
    )


def _handle_callback_error(
    request: WebhookRequest, query: dict[str, str]
) -> WebhookResponse | None:
    if error := query.get("error"):
        message = f"Error: {error}"
        if error_description := query.get("error_description"):
            message = f"{message} Details: {error_description}"
        _save_authorization_error(request, message)
        return WebhookResponse.text_response(
            f"Server returned {message}", status_code=400
        )
    return None


def oauth_callback(request: WebhookRequest) -> WebhookResponse:
    if not authorization_handoff_is_active(
        request.asset.auth_state.get_all(force_reload=True)
    ):
        return WebhookResponse.text_response(
            "ERROR: OAuth authorization request expired or is not pending.",
            status_code=400,
        )
    query = _query_values(request)
    flow_mode = request.asset.auth_state.get(AUTH_FLOW_MODE_STATE_KEY)
    if flow_mode == AUTH_FLOW_MODE_DELEGATED:
        return _handle_delegated_callback(request, query)
    if flow_mode == AUTH_FLOW_MODE_ADMIN_CONSENT:
        return _handle_admin_consent_callback(request, query)

    return WebhookResponse.text_response(
        "ERROR: No OAuth authorization request is pending.", status_code=400
    )


def _handle_delegated_callback(
    request: WebhookRequest, query: dict[str, str]
) -> WebhookResponse:
    redirect_uri = request.asset.auth_state.get(REDIRECT_URI_STATE_KEY)
    flow = get_authorization_code_flow(
        request.asset,
        str(request.asset_id),
        redirect_uri=redirect_uri,
    )
    session = flow.client.get_pending_session()
    callback_state = query.get("state", "")
    if (
        not session
        or not callback_state
        or not hmac.compare_digest(session.state, callback_state)
    ):
        message = "OAuth state mismatch."
        return WebhookResponse.text_response(message, status_code=400)

    if error_response := _handle_callback_error(request, query):
        return error_response

    try:
        get_pending_delegated_scopes(request.asset)
    except AuthorizationRequiredError as error:
        _save_authorization_error(request, str(error))
        return WebhookResponse.text_response(str(error), status_code=400)

    authorization_code = query.get("code")
    if not authorization_code:
        message = "OAuth response did not contain an authorization code."
        _save_authorization_error(request, message)
        return WebhookResponse.text_response(message, status_code=400)

    flow.set_authorization_code(authorization_code)
    return WebhookResponse.text_response(
        "Code received. Please close this window, the action will continue to get new token."
    )


def _handle_admin_consent_callback(
    request: WebhookRequest, query: dict[str, str]
) -> WebhookResponse:
    expected_state = request.asset.auth_state.get(ADMIN_CONSENT_NONCE_STATE_KEY, "")
    callback_state = query.get("state", "")
    if (
        not expected_state
        or request.asset.auth_state.get(ADMIN_CONSENT_COMPLETE_STATE_KEY, False)
        or not callback_state
        or not hmac.compare_digest(expected_state, callback_state)
    ):
        message = "OAuth state mismatch."
        return WebhookResponse.text_response(message, status_code=400)

    if error_response := _handle_callback_error(request, query):
        return error_response

    consent_granted = query.get("admin_consent") == "True"
    state = request.asset.auth_state.get_all()
    state[ADMIN_CONSENT_STATE_KEY] = consent_granted
    state[ADMIN_CONSENT_COMPLETE_STATE_KEY] = True
    request.asset.auth_state.put_all(state)

    if consent_granted:
        return WebhookResponse.text_response(
            "Admin Consent received. Please close this window."
        )
    return WebhookResponse.text_response(
        "Admin Consent declined. Please close this window and try again later.",
        status_code=400,
    )


def register_oauth_webhooks(app: App) -> App:
    app.webhook(OAUTH_START_ROUTE, allowed_methods=["GET"])(oauth_start)
    app.webhook(OAUTH_CALLBACK_ROUTE, allowed_methods=["GET"])(oauth_callback)
    return app
