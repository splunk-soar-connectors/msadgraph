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
from urllib.parse import parse_qs, quote, unquote, urlparse

import httpx
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField, PermissiveActionOutput
from soar_sdk.auth import OAuthClientError
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..auth import get_graph_client


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
    status: str = OutputField(
        example_values=["Successfully retrieved owned devices for user user@test.com"]
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


def _get_graph_response(response: httpx.Response) -> dict[str, Any]:
    try:
        payload = response.json()
    except ValueError as error:
        if response.is_success:
            raise RuntimeError(
                "Unable to parse JSON response from Microsoft Graph"
            ) from error
        response.raise_for_status()
        raise
    if not response.is_success:
        graph_error = payload.get("error") if isinstance(payload, dict) else payload
        if isinstance(graph_error, dict):
            graph_error = graph_error.get("message", graph_error)
        raise RuntimeError(
            f"Error from server. Status Code: {response.status_code}. Data from server: \n{graph_error}\n"
        )
    if not isinstance(payload, dict):
        raise RuntimeError("Microsoft Graph returned a non-object JSON response")
    return payload


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


def _get_devices(
    client: httpx.Client, endpoint: str, *, params: dict[str, str]
) -> list[dict[str, Any]]:
    devices: list[dict[str, Any]] = []
    next_params: dict[str, str] | None = {**params, "$top": str(GRAPH_PAGE_SIZE)}
    while next_params is not None:
        payload = _get_graph_response(client.get(endpoint, params=next_params))
        page = payload.get("value")
        if not isinstance(page, list) or not all(
            isinstance(item, dict) for item in page
        ):
            raise RuntimeError(
                "Microsoft Graph response did not contain a valid list value"
            )
        devices.extend(_normalize_odata(item) for item in page)
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
    return devices


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
    try:
        endpoint = f"/users/{_quote_path_segment(params.user_id)}/ownedDevices"
        with get_graph_client(asset, str(soar.get_asset_id())) as graph_client:
            devices = _get_devices(graph_client, endpoint, params=query)
    except (httpx.HTTPError, OAuthClientError, RuntimeError, ValueError) as error:
        raise ActionFailure(str(error)) from error
    status = f"Successfully retrieved owned devices for user {params.user_id}"
    soar.set_message(f"Status: {status}")
    soar.set_summary(ListUserDevicesSummary(status=status))
    return [ListUserDevicesOutput(**device) for device in devices]
