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

import httpx
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField, PermissiveActionOutput
from soar_sdk.auth import OAuthClientError
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import Params

from ..asset import Asset
from ..auth import get_graph_client
from ..graph_response import get_graph_response


class OdataOutput(ActionOutput):
    type: str = OutputField(example_values=["test.DirectoryServices.DirectoryRole"])


class ListDirectoryRolesOutput(PermissiveActionOutput):
    deletedDateTime: str
    deletionTimestamp: str
    description: str = OutputField(
        example_values=[
            "Can read basic directory information. For granting access to applications, not intended for users."
        ]
    )
    displayName: str = OutputField(
        example_values=["Directory Readers"], column_name="Display Name"
    )
    id: str = OutputField(
        cef_types=["directory object id"],
        example_values=["02b238cb-0d15-454b-aae6-0e94993a3207"],
        column_name="Object ID",
    )
    isSystem: bool
    objectType: str = OutputField(example_values=["Role"])
    odata: OdataOutput
    roleTemplateId: str = OutputField(
        cef_types=["role template id"],
        example_values=["88d8e3e3-8f55-4a1e-953a-9b9898b8876b"],
    )


class ListDirectoryRolesSummary(ActionOutput):
    num_directory_roles: int = OutputField(example_values=[5])


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


def list_directory_roles(
    params: Params, soar: SOARClient, asset: Asset
) -> list[ListDirectoryRolesOutput]:
    try:
        with get_graph_client(asset, str(soar.get_asset_id())) as graph_client:
            payload = get_graph_response(graph_client.get("/directoryRoles"))
        roles = payload.get("value", [])
        if not isinstance(roles, list) or not all(
            isinstance(role, dict) for role in roles
        ):
            raise RuntimeError(
                "Microsoft Graph response did not contain a valid list value"
            )
    except (httpx.HTTPError, OAuthClientError, RuntimeError, ValueError) as error:
        raise ActionFailure(str(error)) from error
    soar.set_message(f"Num directory roles: {len(roles)}")
    soar.set_summary(ListDirectoryRolesSummary(num_directory_roles=len(roles)))
    return [ListDirectoryRolesOutput(**_normalize_odata(role)) for role in roles]
