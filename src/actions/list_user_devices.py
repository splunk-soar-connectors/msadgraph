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
from collections.abc import Iterator
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField, PermissiveActionOutput
from soar_sdk.auth import OAuthClientError
from soar_sdk.params import Param, Params

from ..action_failure import failed_result
from ..asset import Asset
from ..graph_utils import normalize_odata, quote_path_segment
from ..auth import get_graph_client
from ..graph_response import get_graph_response


GRAPH_PAGE_SIZE = 999


class ListUserDevicesParams(Params):
    user_id: str = Param(
        description="User ID - can be user principal name or object ID",
        primary=True,
        cef_types=["user id"],
    )
    select_string: str | None = Param(
        description="Select string to get additional user properties. Separate multiple values with commas"
    )


class OdataOutput(ActionOutput):
    type: str = OutputField(example_values=["#test.graph.device"])


class AlternativesecurityidsOutput(ActionOutput):
    identityProvider: str
    key: str = OutputField(
        example_values=[
            "WAA1ADAAOQA6ADwAUwBIAEEAMQAtAFQAUAAtAFAAVQBCAEsARQBZAD4AOQA5AEEARQAwADgAOABDAEUANAA1ADgAMABCADcAQgBGAEEARQA2ADEAQQBCADYANAA3ADYANgA5ADUAOAAzAEQANABFAEYARQA5ADYAOAAyAHkAcQBSAEIANwBrAGEAMQA4AEoATAByACsAegB4AE8AYwB6AE8AYgBNAFEANQBZAEgAbgB0AFQAdgBOAG0AbgA5AEQAZQA2AFgAVQBUAGgAcwBFAD0A"
        ]
    )
    type: float = OutputField(example_values=[2])


class ExtensionattributesOutput(ActionOutput):
    extensionAttribute1: str
    extensionAttribute10: str
    extensionAttribute11: str
    extensionAttribute12: str
    extensionAttribute13: str
    extensionAttribute14: str
    extensionAttribute15: str
    extensionAttribute2: str
    extensionAttribute3: str
    extensionAttribute4: str
    extensionAttribute5: str
    extensionAttribute6: str
    extensionAttribute7: str
    extensionAttribute8: str
    extensionAttribute9: str


class ListUserDevicesOutput(PermissiveActionOutput):
    odata: OdataOutput
    accountEnabled: bool
    alternativeSecurityIds: list[AlternativesecurityidsOutput]
    approximateLastSignInDateTime: str = OutputField(
        example_values=["2019-09-26T03:42:15Z"]
    )
    complianceExpirationDateTime: str
    createdDateTime: str = OutputField(example_values=["2019-09-26T03:42:15Z"])
    deletedDateTime: str
    deviceCategory: str
    deviceId: str = OutputField(column_name="Device ID")
    deviceMetadata: str
    deviceOwnership: str
    deviceVersion: float
    displayName: str = OutputField(column_name="Display Name")
    domainName: str
    enrollmentProfileName: str
    enrollmentType: str
    extensionAttributes: ExtensionattributesOutput
    externalSourceName: str
    id: str
    isCompliant: bool
    isManaged: bool
    isRooted: str
    managementType: str
    manufacturer: str
    mdmAppId: str
    model: str
    onPremisesLastSyncDateTime: str
    onPremisesSyncEnabled: bool
    operatingSystem: str = OutputField(example_values=["Windows"])
    operatingSystemVersion: str = OutputField(example_values=["10.0.18362.0"])
    profileType: str = OutputField(example_values=["RegisteredDevice"])
    registrationDateTime: str = OutputField(example_values=["2019-09-26T03:42:15Z"])
    sourceType: str
    trustType: str = OutputField(example_values=["Workplace"])


class ListUserDevicesSummary(ActionOutput):
    incomplete: bool = OutputField(example_values=[False, True])
    status: str = OutputField(
        example_values=["Successfully retrieved owned devices for user user@test.com"]
    )


def _get_devices(
    client: httpx.Client, endpoint: str, *, params: dict[str, str]
) -> Iterator[dict[str, Any]]:
    next_params: dict[str, str] | None = {**params, "$top": str(GRAPH_PAGE_SIZE)}
    while next_params is not None:
        payload = get_graph_response(client.get(endpoint, params=next_params))
        page = payload.get("value")
        if not isinstance(page, list) or not all(
            isinstance(item, dict) for item in page
        ):
            raise RuntimeError(
                "Microsoft Graph response did not contain a valid list value"
            )
        yield from (normalize_odata(item) for item in page)
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


def list_user_devices(
    params: ListUserDevicesParams, soar: SOARClient, asset: Asset
) -> list[ListUserDevicesOutput]:
    query: dict[str, str] = {}
    if params.select_string:
        values = [
            value.strip() for value in params.select_string.split(",") if value.strip()
        ]
        if values:
            query["$select"] = ",".join(values)
    devices: list[dict[str, Any]] = []
    try:
        endpoint = f"/users/{quote_path_segment(params.user_id)}/ownedDevices"
        with get_graph_client(asset, str(soar.get_asset_id())) as graph_client:
            devices.extend(_get_devices(graph_client, endpoint, params=query))
    except (httpx.HTTPError, OAuthClientError, RuntimeError, ValueError) as error:
        return failed_result(
            params,
            f"Results incomplete; retrieved {len(devices)} records. {str(error) or type(error).__name__}",
            data=devices,
            summary=ListUserDevicesSummary(
                status="Results incomplete", incomplete=True
            ),
        )
    status = f"Successfully retrieved owned devices for user {params.user_id}"
    soar.set_message(f"Status: {status}")
    soar.set_summary(ListUserDevicesSummary(status=status, incomplete=False))
    return [ListUserDevicesOutput(**device) for device in devices]
