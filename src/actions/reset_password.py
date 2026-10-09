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
from soar_sdk.abstract import SOARClient
from urllib.parse import quote, unquote

import httpx
from soar_sdk.action_results import ActionOutput, ActionResult, OutputField
from soar_sdk.auth import OAuthClientError
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..auth import get_graph_client


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
        response.raise_for_status()
        return
    error = payload.get("error") if isinstance(payload, dict) else payload
    if isinstance(error, dict):
        error = error.get("message", error)
    raise RuntimeError(
        f"Error from server. Status Code: {response.status_code}. Data from server: \n{error}\n"
    )


def reset_password(
    params: ResetPasswordParams, soar: SOARClient, asset: Asset
) -> ActionOutput:
    try:
        endpoint = f"/users/{_quote_path_segment(params.user_id)}"
        body = {
            "passwordProfile": {
                "forceChangePasswordNextSignIn": params.force_change,
                "password": params.temp_password,
            }
        }
        with get_graph_client(asset, str(soar.get_asset_id())) as graph_client:
            response = graph_client.patch(endpoint, json=body)
            _raise_for_graph_error(response)
    except (httpx.HTTPError, OAuthClientError, RuntimeError, ValueError) as error:
        raise ActionFailure(str(error)) from error

    status = f"Successfully reset password for {params.user_id}"
    safe_params = params.model_dump(exclude={"temp_password"})
    result = ActionResult(True, f"Status: {status}", safe_params)
    result.set_summary(ResetPasswordSummary(status=status).model_dump())
    return result
