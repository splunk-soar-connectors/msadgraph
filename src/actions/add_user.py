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
from urllib.parse import quote, unquote

import httpx
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, ActionResult, OutputField
from soar_sdk.auth import OAuthClientError
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..auth import get_graph_client
from ..consts import MICROSOFT_GRAPH_BASE_URLS


class AddUserParams(Params):
    group_object_id: str = Param(
        description="Object ID of group",
        primary=True,
        cef_types=["group object id"],
        column_name="Group Object ID",
    )
    user_id: str = Param(
        description="User ID to add to group",
        primary=True,
        cef_types=["user id"],
        column_name="User ID",
    )


class AddUserSummary(ActionOutput):
    status: str = OutputField(
        example_values=["Successfully added user to group", "User already in group"]
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
    message = str(error).strip() if error is not None else ""
    return message or f"Microsoft Graph returned HTTP {response.status_code}"


def add_user(params: AddUserParams, soar: SOARClient, asset: Asset) -> ActionOutput:
    try:
        group_id = _quote_path_segment(params.group_object_id)
        user_id = _quote_path_segment(params.user_id)
        graph_base_url = MICROSOFT_GRAPH_BASE_URLS[asset.region or "Global"].rstrip("/")
        body = {"@odata.id": f"{graph_base_url}/directoryObjects/{user_id}"}
        with get_graph_client(asset, str(soar.get_asset_id())) as graph_client:
            response = graph_client.post(f"/groups/{group_id}/members/$ref", json=body)
        error = _graph_error(response)
    except (httpx.HTTPError, OAuthClientError, RuntimeError, ValueError) as error:
        raise ActionFailure(str(error)) from error

    if error is not None:
        status = (
            "User already in group"
            if (
                "references already exist for the following modified properties: 'members'."
                in error
            )
            else None
        )
        if status:
            result = ActionResult(False, error, params.model_dump())
            result.set_summary(AddUserSummary(status=status).model_dump())
            return result
        raise ActionFailure(error)

    status = "Successfully added user to group"
    result = ActionResult(True, f"Status: {status}", params.model_dump())
    result.set_summary(AddUserSummary(status=status).model_dump())
    return result
