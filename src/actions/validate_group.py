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


class ValidateGroupParams(Params):
    group_object_id: str = Param(
        description="Object ID of group",
        primary=True,
        cef_types=["group object id"],
        column_name="Group Object ID",
    )
    user_id: str = Param(
        description="User ID to validate",
        primary=True,
        cef_types=["user id"],
        column_name="User ID",
    )


class OdataOutput(ActionOutput):
    type: str = OutputField(example_values=["#test.graph.group"])


class ValueOutput(ActionOutput):
    odata_type: str = OutputField(alias="@odata.type")
    odata: OdataOutput
    classification: str
    createdDateTime: str = OutputField(example_values=["2022-02-25T12:05:22Z"])
    deletedDateTime: str
    description: str = OutputField(example_values=["Test group for MSGraph"])
    displayName: str = OutputField(example_values=["Test group for MSGraph"])
    expirationDateTime: str
    id: str = OutputField(
        cef_types=["user id"], example_values=["49233413-24c6-4516-a9e1-4d5f87fe34fd"]
    )
    isAssignableToRole: str
    mail: str = OutputField(example_values=["test@user.test.com"])
    mailEnabled: bool = OutputField(example_values=[True])
    mailNickname: str = OutputField(example_values=["TestgroupforMSGraph"])
    membershipRule: str
    membershipRuleProcessingState: str
    onPremisesDomainName: str
    onPremisesLastSyncDateTime: str
    onPremisesNetBiosName: str
    onPremisesSamAccountName: str
    onPremisesSecurityIdentifier: str
    onPremisesSyncEnabled: str
    preferredDataLocation: str
    preferredLanguage: str
    renewedDateTime: str = OutputField(example_values=["2022-02-25T12:05:22Z"])
    securityEnabled: bool = OutputField(example_values=[True])
    securityIdentifier: str = OutputField(
        example_values=["S-1-12-1-1227043859-1159079110-1598939561-4248108679"]
    )
    theme: str
    visibility: str = OutputField(example_values=["Private"])


class ValidateGroupOutput(PermissiveActionOutput):
    odata_context: str = OutputField(
        alias="@odata.context",
        example_values=["https://graph.test.com/v1.0/$metadata#directoryObjects"],
    )
    odata: OdataOutput
    user_in_group: bool
    value: list[ValueOutput]


class ValidateGroupSummary(ActionOutput):
    user_in_group: bool = OutputField(example_values=[True, False])
    message: str = OutputField(
        example_values=[
            "User is a member of the group",
            "User is not a member of the group",
        ]
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


def _escape_odata_string(value: str) -> str:
    return str(value).replace("'", "''")


def _normalize_odata(value: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(value)
    odata = {
        key.removeprefix("@odata."): item
        for key, item in value.items()
        if key.startswith("@odata.")
    }
    if odata:
        normalized["odata"] = odata
    return normalized


def validate_group(
    params: ValidateGroupParams, soar: SOARClient, asset: Asset
) -> ValidateGroupOutput:
    query = {"$filter": f"id eq '{_escape_odata_string(params.group_object_id)}'"}
    try:
        endpoint = f"/users/{_quote_path_segment(params.user_id)}/memberOf"
        with get_graph_client(asset, str(soar.get_asset_id())) as graph_client:
            payload = get_graph_response(graph_client.get(endpoint, params=query))
        values = payload.get("value", [])
        if not isinstance(values, list) or not all(
            isinstance(item, dict) for item in values
        ):
            raise RuntimeError(
                "Microsoft Graph response did not contain a valid list value"
            )
    except (httpx.HTTPError, OAuthClientError, RuntimeError, ValueError) as error:
        raise ActionFailure(str(error)) from error

    user_in_group = any(item.get("id") == params.group_object_id for item in values)
    summary_message = (
        "User is a member of the group"
        if user_in_group
        else "User is not a member of the group"
    )
    soar.set_message(f"User in group: {user_in_group}")
    soar.set_summary(
        ValidateGroupSummary(user_in_group=user_in_group, message=summary_message)
    )
    payload["user_in_group"] = user_in_group
    payload["value"] = [_normalize_odata(item) for item in values]
    return ValidateGroupOutput(**payload)
