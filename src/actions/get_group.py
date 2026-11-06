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


class GetGroupParams(Params):
    object_id: str = Param(
        description="Object ID of group", primary=True, cef_types=["group object id"]
    )
    select_string: str | None = Param(
        description="Select string to get additional group properties. Separate multiple values with commas"
    )
    expand_string: str | None = Param(
        description="Expand string to get a resource or collection referenced by a single relationship"
    )
    use_advanced_query: bool | None = Param(
        description="Use advanced query capabilities", default=False
    )


class GetGroupOutput(PermissiveActionOutput):
    odata: OdataOutput | None = OutputField()
    odata_type: str = OutputField(
        alias="@odata.type", example_values=["test.DirectoryServices.Group"]
    )
    odata_context: str = OutputField(alias="@odata.context")
    classification: str
    createdDateTime: str = OutputField(example_values=["2020-08-05T11:59:49Z"])
    deletedDateTime: str
    deletionTimestamp: str
    description: str = OutputField(
        example_values=["This is the office 365 group"], column_name="Description"
    )
    dirSyncEnabled: str
    displayName: str = OutputField(
        example_values=["o365group"], column_name="Display Name"
    )
    expirationDateTime: str
    id: str = OutputField(
        cef_types=["group object id"],
        example_values=["ddb876b3-603a-437b-9814-2d46a2219a1e"],
        column_name="Object ID",
    )
    isAssignableToRole: str
    lastDirSyncTime: str
    mail: str = OutputField(cef_types=["email"], example_values=["bc7f9cabe@test.com"])
    securityEnabled: bool = OutputField(column_name="Security Enabled")
    mailEnabled: bool = OutputField(column_name="Mail Enabled")
    mailNickname: str = OutputField(example_values=["bc7f9cabe"])
    membershipRule: str
    membershipRuleProcessingState: str
    objectType: str = OutputField(example_values=["Group"])
    onPremisesDomainName: str = OutputField(cef_types=["domain"])
    onPremisesLastSyncDateTime: str
    onPremisesNetBiosName: str
    onPremisesSamAccountName: str
    onPremisesSecurityIdentifier: str
    onPremisesSyncEnabled: str
    preferredDataLocation: str
    preferredLanguage: str
    proxyAddresses: list[str] = OutputField(example_values=["SMTP:bc7f9cabe@test.com"])
    renewedDateTime: str = OutputField(example_values=["2020-08-05T11:59:49Z"])
    securityIdentifier: str = OutputField(
        example_values=["S-1-12-1-909260723-1083662375-1952945031-2402852259"]
    )
    theme: str
    visibility: str


class GetGroupSummary(ActionOutput):
    status: str = OutputField(example_values=["Successfully retrieved group group-id"])


def get_group(params: GetGroupParams, soar: SOARClient, asset: Asset) -> GetGroupOutput:
    query: dict[str, str] = {}
    headers: dict[str, str] = {}
    if params.select_string:
        values = [
            value.strip() for value in params.select_string.split(",") if value.strip()
        ]
        if values:
            query["$select"] = ",".join(values)
    if params.expand_string:
        query["$expand"] = params.expand_string
    if params.use_advanced_query:
        headers["ConsistencyLevel"] = "eventual"
        query["$count"] = "true"
    try:
        endpoint = f"/groups/{quote_path_segment(params.object_id)}"
        with get_graph_client(asset, str(soar.get_asset_id())) as graph_client:
            payload = get_graph_response(
                graph_client.get(endpoint, headers=headers, params=query)
            )
    except (httpx.HTTPError, OAuthClientError, RuntimeError, ValueError) as error:
        return failed_result(params, str(error) or type(error).__name__)
    status = f"Successfully retrieved group {params.object_id}"
    soar.set_message(f"Status: {status}")
    soar.set_summary(GetGroupSummary(status=status))
    return GetGroupOutput(**normalize_odata(payload))
