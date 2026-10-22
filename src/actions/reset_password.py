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
import json
import shlex
from urllib.parse import quote, unquote

import httpx
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, ActionResult, OutputField
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..auth import get_graph_client


# Public diagnostic marker only. Never substitute this value into a request.
DIAGNOSTIC_PROBE_VALUE = "soar-diagnostic-probe"


class ResetPasswordParams(Params):
    user_id: str = Param(
        description="User ID to change password - can be user principal name or object ID",
        primary=True,
        cef_types=["user id"],
        column_name="User ID",
    )
    force_change: bool | None = Param(
        description="Force user to change password on next login", default=True
    )
    temp_password: str = Param(
        description="Temporary password for user", sensitive=True
    )


class ResetPasswordSummary(ActionOutput):
    status: str = OutputField(
        example_values=["Successfully reset password for user@test.com"]
    )
    diagnostics: str = OutputField(
        example_values=["Temporary reset diagnostics; no password values"]
    )


def _password_shape(password: str) -> str:
    """Describe parameter delivery without recording the password or a digest."""
    return (
        f"length={len(password)}, ascii={password.isascii()}, "
        f"ascii_letters={sum(character.isascii() and character.isalpha() for character in password)}, "
        f"digits={sum(character.isascii() and character.isdigit() for character in password)}, "
        f"non_ascii={sum(not character.isascii() for character in password)}"
    )


def _redacted_reset_curl(request: httpx.Request) -> str:
    """Represent the real reset request without credentials or password values."""
    profile = json.loads(request.content)["passwordProfile"]
    body = {
        "passwordProfile": {
            "forceChangePasswordNextSignIn": profile["forceChangePasswordNextSignIn"],
            "password": "<REDACTED>",
        }
    }
    # Deliberately omit Authorization, Cookie, and all other request headers.
    return shlex.join(
        [
            "curl",
            "--request",
            request.method,
            "--url",
            str(request.url),
            "--header",
            f"Content-Type: {request.headers['content-type']}",
            "--data-raw",
            json.dumps(body),
        ]
    )


def _quote_path_segment(value: str) -> str:
    raw_value = str(value)
    canonical_value = raw_value
    for _ in range(5):
        decoded_value = unquote(canonical_value)
        if decoded_value == canonical_value:
            break
        canonical_value = decoded_value
    if canonical_value in {".", ".."}:
        raise ValueError("Microsoft Graph path identifiers must not be dot segments")
    return quote(raw_value, safe="")


def _raise_for_graph_error(response: httpx.Response) -> None:
    if response.is_success:
        return
    try:
        payload = response.json()
    except ValueError:
        payload = {}
    error = payload.get("error") if isinstance(payload, dict) else None
    error = error if isinstance(error, dict) else {}
    details = [f"HTTP {response.status_code}"]
    if isinstance(code := error.get("code"), str):
        details.append(f"code {code}")
    inner_error = error.get("innerError")
    inner_error = inner_error if isinstance(inner_error, dict) else {}
    request_id = response.headers.get("request-id") or inner_error.get("request-id")
    if isinstance(request_id, str):
        details.append(f"request-id {request_id}")
    message = error.get("message")
    if not isinstance(message, str) or not message.strip():
        message = response.reason_phrase or "Microsoft returned no error message"
    raise RuntimeError(
        f"Microsoft Graph rejected password reset ({', '.join(details)}): {message}"
    )


def reset_password(
    params: ResetPasswordParams, soar: SOARClient, asset: Asset
) -> ActionOutput:
    safe_params = params.model_dump(exclude={"temp_password"})
    result = ActionResult(False, "Password reset has not completed", safe_params)
    diagnostic_log: list[str] = []
    summary_status = "Password reset has not completed"

    def redact(message: str) -> str:
        for secret in (params.temp_password, asset.client_secret):
            if secret:
                message = message.replace(secret, "[REDACTED]")
        return message[:2000]

    def record(message: str) -> None:
        diagnostic_log.append(redact(message))
        result.set_summary(
            ResetPasswordSummary(
                status=summary_status,
                diagnostics="\n".join(diagnostic_log),
            ).model_dump()
        )

    def record_request(request: httpx.Request) -> None:
        try:
            outgoing_password = json.loads(request.content)["passwordProfile"][
                "password"
            ]
            record(
                f"outgoing_password_matches_probe: {outgoing_password == DIAGNOSTIC_PROBE_VALUE}"
            )
            record(
                f"Outgoing curl (password and authentication redacted): {_redacted_reset_curl(request)}"
            )
        except (KeyError, TypeError, ValueError, RuntimeError) as diagnostic_error:
            record(f"Curl inspection unavailable: {type(diagnostic_error).__name__}")

    stage = "building request"
    try:
        record(
            f"handler_input_matches_probe: {params.temp_password == DIAGNOSTIC_PROBE_VALUE}"
        )
        record(f"Handler input: {_password_shape(params.temp_password)}")
        record(stage)
        endpoint = f"/users/{_quote_path_segment(params.user_id)}"
        body = {
            "passwordProfile": {
                "forceChangePasswordNextSignIn": params.force_change,
                "password": params.temp_password,
            }
        }
        stage = "acquiring authenticated Graph client"
        record(stage)
        with get_graph_client(asset, str(soar.get_asset_id())) as graph_client:
            graph_client.event_hooks["request"].append(record_request)
            stage = "sending Microsoft Graph request"
            record(stage)
            response = graph_client.patch(endpoint, json=body)
            record(
                f"Graph response: HTTP {response.status_code}; "
                f"request-id={response.headers.get('request-id', 'not provided')}"
            )
            # Inspect the real HTTPX request, not a reconstructed request body.
            try:
                sent_password = json.loads(response.request.content)["passwordProfile"][
                    "password"
                ]
                if isinstance(sent_password, str):
                    record(
                        f"Sent password matches handler input: {sent_password == params.temp_password}; "
                        f"{_password_shape(sent_password)}"
                    )
                else:
                    record(
                        f"Sent password has unexpected type: {type(sent_password).__name__}"
                    )
            except (KeyError, TypeError, ValueError, RuntimeError) as diagnostic_error:
                record(
                    f"Sent password inspection unavailable: {type(diagnostic_error).__name__}"
                )
            stage = "checking Microsoft Graph response"
            record(stage)
            _raise_for_graph_error(response)
        stage = "building action result"
        record(stage)
        status = f"Successfully reset password for {params.user_id}"
        summary_status = status
        result.set_status(True, f"Status: {status}")
        record("Password reset completed")
        return result
    except Exception as error:
        message = error.message if isinstance(error, ActionFailure) else str(error)
        message = message or "No error message was provided"
        summary_status = redact(
            f"Password reset failed while {stage} ({type(error).__name__}): {message}"
        )
        result.set_status(False, summary_status)
        record(summary_status)
        return result
