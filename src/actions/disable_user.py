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

import httpx
from soar_sdk.action_results import ActionOutput, ActionResult, OutputField
from soar_sdk.auth import OAuthClientError
from soar_sdk.params import Param, Params

from ..action_failure import failed_result
from ..asset import Asset
from ..graph_utils import quote_path_segment
from ..auth import get_graph_client


class DisableUserParams(Params):
    user_id: str = Param(
        description="User ID to disable - can be user principal name or object ID",
        primary=True,
        cef_types=["user id"],
        column_name="User ID",
    )


class DisableUserSummary(ActionOutput):
    status: str = OutputField(
        example_values=[
            "Successfully disabled user user@test.com and revoked sign-in sessions. Already-issued access tokens for non-CAE resources may remain valid until they expire."
        ]
    )


def _graph_error(response: httpx.Response) -> str | None:
    if response.is_success:
        return None
    try:
        payload = response.json()
    except ValueError:
        return f"HTTP {response.status_code}: {response.text}"
    error = payload.get("error") if isinstance(payload, dict) else payload
    if isinstance(error, dict):
        error = error.get("message", error)
    return f"Error from server. Status Code: {response.status_code}. Data from server: \n{error}\n"


def disable_user(
    params: DisableUserParams, soar: SOARClient, asset: Asset
) -> ActionOutput:
    try:
        encoded_user_id = quote_path_segment(params.user_id)
        with get_graph_client(asset, str(soar.get_asset_id())) as graph_client:
            response = graph_client.patch(
                f"/users/{encoded_user_id}", json={"accountEnabled": False}
            )
            if error := _graph_error(response):
                raise RuntimeError(error)

            try:
                response = graph_client.post(
                    f"/users/{encoded_user_id}/revokeSignInSessions"
                )
                if error := _graph_error(response):
                    raise RuntimeError(error)
            except (
                httpx.HTTPError,
                OAuthClientError,
                RuntimeError,
                ValueError,
            ) as error:
                detail = str(error).strip() or type(error).__name__
                return failed_result(
                    params,
                    f"User {params.user_id} was disabled, but session revocation "
                    f"could not be confirmed: {detail}",
                )
    except (httpx.HTTPError, OAuthClientError, RuntimeError, ValueError) as error:
        return failed_result(params, str(error) or type(error).__name__)

    status = (
        f"Successfully disabled user {params.user_id} and revoked sign-in sessions. "
        "Already-issued access tokens for non-CAE resources may remain valid until they expire."
    )
    result = ActionResult(True, f"Status: {status}", params.model_dump())
    result.set_summary(DisableUserSummary(status=status).model_dump())
    return result
