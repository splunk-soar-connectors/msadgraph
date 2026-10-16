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
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField, PermissiveActionOutput
from soar_sdk.auth import OAuthClientError
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..auth import get_graph_client
from ..graph_response import get_graph_response


GRAPH_PAGE_SIZE = 999


class ListGroupsParams(Params):
    filter_string: str | None = Param(
        description="Filter string to apply to group listing"
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


class OdataOutput(ActionOutput):
    type: str = OutputField(example_values=["test.DirectoryServices.Group"])


class ListGroupsOutput(PermissiveActionOutput):
    classification: str
    createdDateTime: str = OutputField(example_values=["2021-03-25T18:40:53Z"])
    deletedDateTime: str
    deletionTimestamp: str
    displayName: str = OutputField(
        example_values=["Test-site"], column_name="Display Name"
    )
    description: str = OutputField(
        example_values=["This is for testing purpose"], column_name="Description"
    )
    dirSyncEnabled: str
    expirationDateTime: str
    id: str = OutputField(
        cef_types=["group object id"],
        example_values=["2a201c95-101b-42d9-a7af-9a2fdf8193f1"],
        column_name="Group Object ID",
    )
    isAssignableToRole: str
    lastDirSyncTime: str
    mail: str = OutputField(cef_types=["email"], example_values=["Test-site@test.com"])
    mailEnabled: bool
    mailNickname: str = OutputField(example_values=["Test-site"])
    membershipRule: str
    membershipRuleProcessingState: str
    objectType: str = OutputField(example_values=["Group"])
    odata: OdataOutput
    onPremisesDomainName: str = OutputField(cef_types=["domain"])
    onPremisesLastSyncDateTime: str
    onPremisesNetBiosName: str
    onPremisesSamAccountName: str
    onPremisesSecurityIdentifier: str
    onPremisesSyncEnabled: str
    preferredDataLocation: str
    preferredLanguage: str
    proxyAddresses: str = OutputField(example_values=["SMTP:test-h@test.com"])
    renewedDateTime: str = OutputField(example_values=["2021-03-25T18:40:53Z"])
    securityEnabled: bool
    securityIdentifier: str = OutputField(
        example_values=["S-1-12-1-294681889-1319597617-672379543-28952017"]
    )
    theme: str
    visibility: str = OutputField(example_values=["Private"])


class ListGroupsSummary(ActionOutput):
    num_groups: int = OutputField(example_values=[7])


def _normalize_odata(value: Any) -> Any:
    if isinstance(value, list):
        return [_normalize_odata(item) for item in value]
    if not isinstance(value, dict):
        return value
    normalized = {key: _normalize_odata(item) for key, item in value.items()}
    odata = {
        key.removeprefix("@odata."): _normalize_odata(item)
        for key, item in value.items()
        if key.startswith("@odata.")
    }
    if odata:
        normalized["odata"] = odata
    return normalized


def _get_groups(
    client: httpx.Client, *, headers: dict[str, str], params: dict[str, str]
) -> list[dict[str, Any]]:
    groups: list[dict[str, Any]] = []
    next_params: dict[str, str] | None = {**params, "$top": str(GRAPH_PAGE_SIZE)}
    while next_params is not None:
        payload = get_graph_response(
            client.get("/groups", headers=headers, params=next_params)
        )
        page = payload.get("value")
        if not isinstance(page, list) or not all(
            isinstance(item, dict) for item in page
        ):
            raise RuntimeError(
                "Microsoft Graph response did not contain a valid list value"
            )
        groups.extend(_normalize_odata(item) for item in page)
        next_link = payload.get("@odata.nextLink") or payload.get("odata.nextLink")
        if next_link is None:
            next_params = None
            continue
        if not isinstance(next_link, str):
            raise RuntimeError("Microsoft Graph returned an invalid next page URL")
        skip_tokens = parse_qs(urlparse(next_link).query).get("$skiptoken")
        if not skip_tokens:
            raise RuntimeError(
                "Microsoft Graph next page URL did not contain a skip token"
            )
        next_params = {
            **params,
            "$top": str(GRAPH_PAGE_SIZE),
            "$skiptoken": skip_tokens[0],
        }
    return groups


def list_groups(
    params: ListGroupsParams, soar: SOARClient, asset: Asset
) -> list[ListGroupsOutput]:
    query: dict[str, str] = {}
    headers: dict[str, str] = {}
    if params.filter_string:
        query["$filter"] = params.filter_string
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
        with get_graph_client(asset, str(soar.get_asset_id())) as graph_client:
            groups = _get_groups(graph_client, headers=headers, params=query)
    except (httpx.HTTPError, OAuthClientError, RuntimeError, ValueError) as error:
        raise ActionFailure(str(error)) from error
    soar.set_message(f"Num groups: {len(groups)}")
    soar.set_summary(ListGroupsSummary(num_groups=len(groups)))
    return [ListGroupsOutput(**group) for group in groups]
