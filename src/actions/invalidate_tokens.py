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
from soar_sdk.action_results import ActionOutput, OutputField, PermissiveActionOutput
from soar_sdk.auth import OAuthClientError
from soar_sdk.params import Param, Params

from ..action_failure import failed_result
from ..asset import Asset
from ..graph_output import OdataOutput, normalize_odata
from ..graph_utils import quote_path_segment
from ..auth import get_graph_client
from ..graph_response import get_graph_response


class DisableTokensParams(Params):
    user_id: str = Param(
        description="User ID to disable tokens of - can be user principal name or object ID",
        primary=True,
        cef_types=["user id"],
        column_name="User ID",
    )


class DisableTokensOutput(PermissiveActionOutput):
    odata: OdataOutput | None = OutputField()
    odata_context: str = OutputField(
        alias="@odata.context",
        example_values=["https://graph.test.com/v1.0/$metadata#Edm.Boolean"],
    )
    value: bool = OutputField()


class DisableTokensSummary(ActionOutput):
    status: str = OutputField(example_values=["Successfully disabled tokens"])


def invalidate_tokens(
    params: DisableTokensParams, soar: SOARClient, asset: Asset
) -> DisableTokensOutput:
    endpoint = f"/users/{quote_path_segment(params.user_id)}/revokeSignInSessions"

    try:
        with get_graph_client(asset, str(soar.get_asset_id())) as graph_client:
            response = graph_client.post(endpoint)
            payload = get_graph_response(response, allow_empty=True)
    except (httpx.HTTPError, OAuthClientError, RuntimeError, ValueError) as error:
        return failed_result(params, str(error) or type(error).__name__)

    status = "Successfully disabled tokens"
    soar.set_summary(DisableTokensSummary(status=status))
    soar.set_message(f"Status: {status}")
    return DisableTokensOutput(**normalize_odata(payload))
