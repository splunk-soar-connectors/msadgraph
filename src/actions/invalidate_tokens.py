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
from soar_sdk.action_results import ActionOutput, OutputField, PermissiveActionOutput
from soar_sdk.auth import OAuthClientError
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..auth import get_graph_client
from ..graph_response import get_graph_response


class DisableTokensParams(Params):
    user_id: str = Param(
        description="User ID to disable tokens of - can be user principal name or object ID",
        primary=True,
        cef_types=["user id"],
        column_name="User ID",
    )


class OdataOutput(ActionOutput):
    metadata: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://graph.windows.net/1t309est-db6c-4tes-t1d2-12bf3456d78d/$metadata#Edm.Null"
        ],
    )
    null: bool = OutputField()


class DisableTokensOutput(PermissiveActionOutput):
    odata_context: str = OutputField(
        alias="@odata.context",
        example_values=["https://graph.test.com/v1.0/$metadata#Edm.Boolean"],
    )
    odata: OdataOutput = OutputField()
    value: bool = OutputField()


class DisableTokensSummary(ActionOutput):
    status: str = OutputField(example_values=["Successfully disabled tokens"])


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


def invalidate_tokens(
    params: DisableTokensParams, soar: SOARClient, asset: Asset
) -> DisableTokensOutput:
    endpoint = f"/users/{_quote_path_segment(params.user_id)}/revokeSignInSessions"

    try:
        with get_graph_client(asset, str(soar.get_asset_id())) as graph_client:
            response = graph_client.post(endpoint)
            payload = get_graph_response(response, allow_empty=True)
    except (httpx.HTTPError, OAuthClientError, RuntimeError, ValueError) as error:
        raise ActionFailure(str(error)) from error

    status = "Successfully disabled tokens"
    soar.set_summary(DisableTokensSummary(status=status))
    soar.set_message(f"Status: {status}")
    return DisableTokensOutput(**payload)
