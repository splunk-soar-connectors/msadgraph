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

import httpx
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, ActionResult, OutputField
from soar_sdk.auth import OAuthClientError
from soar_sdk.params import Param, Params

from ..action_failure import failed_result
from ..asset import Asset
from ..graph_response import get_graph_error
from ..graph_utils import quote_path_segment
from ..auth import get_graph_client


class RemoveUserParams(Params):
    group_object_id: str = Param(
        description="Object ID of group",
        primary=True,
        cef_types=["group object id"],
        column_name="Group Object ID",
    )
    user_id: str = Param(
        description="User ID to remove from group",
        primary=True,
        cef_types=["user id"],
        column_name="User ID",
    )


class RemoveUserSummary(ActionOutput):
    status: str = OutputField(
        example_values=["Successfully removed user from group", "User not in group"]
    )


def remove_user(
    params: RemoveUserParams, soar: SOARClient, asset: Asset
) -> ActionOutput:
    try:
        endpoint = (
            f"/groups/{quote_path_segment(params.group_object_id)}/members/"
            f"{quote_path_segment(params.user_id)}/$ref"
        )
        with get_graph_client(asset, str(soar.get_asset_id())) as graph_client:
            response = graph_client.delete(endpoint)
        error = get_graph_error(response)
    except (httpx.HTTPError, OAuthClientError, RuntimeError, ValueError) as error:
        return failed_result(params, str(error) or type(error).__name__)

    if error is not None:
        status = (
            "User not in group"
            if "does not exist or one of its queried" in error
            else None
        )
        if status:
            result = ActionResult(False, error, params.model_dump())
            result.set_summary(RemoveUserSummary(status=status).model_dump())
            return result
        return failed_result(params, error)

    status = "Successfully removed user from group"
    result = ActionResult(True, f"Status: {status}", params.model_dump())
    result.set_summary(RemoveUserSummary(status=status).model_dump())
    return result
