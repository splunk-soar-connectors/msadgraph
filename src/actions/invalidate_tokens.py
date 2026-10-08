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
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.params import Param, Params

from ..asset import Asset


class DisableTokensParams(Params):
    user_id: str = Param(
        description="User ID to disable tokens of - can be user principal name or object ID",
        primary=True,
        cef_types=["user id"],
    )


class OdataOutput(ActionOutput):
    metadata: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://graph.windows.net/1t309est-db6c-4tes-t1d2-12bf3456d78d/$metadata#Edm.Null"
        ],
    )
    null: bool


class DisableTokensOutput(ActionOutput):
    odata: OdataOutput
    value: bool


def invalidate_tokens(
    params: DisableTokensParams, soar: SOARClient, asset: Asset
) -> DisableTokensOutput:
    raise NotImplementedError()
