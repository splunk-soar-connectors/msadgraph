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
import contextlib
import json

import httpx
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, ActionResult, OutputField
from soar_sdk.auth import OAuthClientError
from soar_sdk.params import Param, Params

from ..action_failure import failed_result
from ..asset import Asset
from ..graph_response import raise_for_graph_error
from ..graph_utils import quote_path_segment
from ..auth import get_graph_client


class SetUserAttributeParams(Params):
    user_id: str = Param(
        description="User ID - can be user principal name or object ID",
        primary=True,
        cef_types=["user id"],
        column_name="User ID",
    )
    attribute: str = Param(description="Attribute to set", column_name="Attribute Name")
    attribute_value: str = Param(
        description="Value of attribute to set", column_name="Attribute Value"
    )


class SetUserAttributeSummary(ActionOutput):
    status: str = OutputField(example_values=["Successfully updated user attribute"])


def set_user_attribute(
    params: SetUserAttributeParams, soar: SOARClient, asset: Asset
) -> ActionOutput:
    attribute_value: object = params.attribute_value
    with contextlib.suppress(json.JSONDecodeError):
        attribute_value = json.loads(params.attribute_value)

    try:
        endpoint = f"/users/{quote_path_segment(params.user_id)}"
        with get_graph_client(asset, str(soar.get_asset_id())) as graph_client:
            response = graph_client.patch(
                endpoint, json={params.attribute: attribute_value}
            )
            raise_for_graph_error(response)
    except (httpx.HTTPError, OAuthClientError, RuntimeError, ValueError) as error:
        return failed_result(
            params, str(error) or type(error).__name__, exclude={"attribute_value"}
        )

    status = "Successfully updated user attribute"
    result = ActionResult(True, f"Status: {status}", params.model_dump())
    result.set_summary(SetUserAttributeSummary(status=status).model_dump())
    return result
