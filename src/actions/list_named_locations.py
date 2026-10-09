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


GRAPH_PAGE_SIZE = 999


class ListNamedLocationsParams(Params):
    location_type: str | None = Param(
        description="Type of named locations to return",
        default="all",
        value_list=["all", "ip", "country"],
        column_name="Location Type",
    )
    filter: str | None = Param(
        description="Optional OData filter, for example contains(displayName,'Blocked')",
        column_name="Filter",
    )
    select: str | None = Param(
        description="Optional select string to get specific properties. Separate multiple values with commas",
        column_name="Select",
    )


class OdataOutput(ActionOutput):
    type: str = OutputField(
        example_values=[
            "#microsoft.graph.iPv6CidrRange",
            "#microsoft.graph.iPv4CidrRange",
        ]
    )


class IprangesOutput(ActionOutput):
    odata_type: str = OutputField(alias="@odata.type")
    odata: OdataOutput
    cidrAddress: str = OutputField(
        cef_types=["ip", "cidr"], example_values=["127.0.0.1/32", "2001:8000::/20"]
    )


class ListNamedLocationsOutput(PermissiveActionOutput):
    odata_type: str = OutputField(alias="@odata.type", column_name="Type")
    odata: OdataOutput
    id: str = OutputField(
        cef_types=["directory object id"],
        example_values=["0c0c6d27-93e7-4fd7-88a4-952c6d61a697"],
        column_name="Object ID",
    )
    displayName: str = OutputField(
        example_values=["Named locations to be blocked"], column_name="Display Name"
    )
    createdDateTime: str = OutputField(
        cef_types=["datetime"],
        example_values=["2021-03-23T04:59:25.8014022Z"],
        column_name="Created",
    )
    modifiedDateTime: str = OutputField(
        cef_types=["datetime"],
        example_values=["2021-03-23T08:05:02.1027085Z"],
        column_name="Modified",
    )
    isTrusted: bool = OutputField(column_name="Trusted")
    ipRanges: list[IprangesOutput]
    countriesAndRegions: list[str] = OutputField(example_values=["US", "CA"])
    countryLookupMethod: str = OutputField(
        example_values=["clientIpAddress", "authenticatorAppGps"]
    )
    includeUnknownCountriesAndRegions: bool


class ListNamedLocationsSummary(ActionOutput):
    num_named_locations: int = OutputField(example_values=[3])


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


def _get_named_locations(
    client: httpx.Client, *, headers: dict[str, str], params: dict[str, str]
) -> list[dict[str, Any]]:
    endpoint = "/identity/conditionalAccess/namedLocations"
    locations: list[dict[str, Any]] = []
    next_params: dict[str, str] | None = {**params, "$top": str(GRAPH_PAGE_SIZE)}
    while next_params is not None:
        payload = _get_graph_response(
            client.get(endpoint, headers=headers, params=next_params)
        )
        page = payload.get("value")
        if not isinstance(page, list) or not all(
            isinstance(item, dict) for item in page
        ):
            raise RuntimeError(
                "Microsoft Graph response did not contain a valid list value"
            )
        locations.extend(_normalize_odata(item) for item in page)
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
    return locations


def list_named_locations(
    params: ListNamedLocationsParams, soar: SOARClient, asset: Asset
) -> list[ListNamedLocationsOutput]:
    query: dict[str, str] = {"$count": "true"}
    headers = {"ConsistencyLevel": "eventual"}
    type_filter = None
    if params.location_type == "ip":
        type_filter = "isof('microsoft.graph.ipNamedLocation')"
    elif params.location_type == "country":
        type_filter = "isof('microsoft.graph.countryNamedLocation')"
    filter_string = params.filter.strip() if params.filter else ""
    if filter_string and type_filter:
        query["$filter"] = f"{type_filter} and ({filter_string})"
    elif filter_string:
        query["$filter"] = filter_string
    elif type_filter:
        query["$filter"] = type_filter
    if params.select:
        values = [value.strip() for value in params.select.split(",") if value.strip()]
        if values:
            query["$select"] = ",".join(values)
    try:
        with get_graph_client(asset, str(soar.get_asset_id())) as graph_client:
            locations = _get_named_locations(
                graph_client, headers=headers, params=query
            )
    except (httpx.HTTPError, OAuthClientError, RuntimeError, ValueError) as error:
        raise ActionFailure(str(error)) from error
    soar.set_message("Successfully listed named locations")
    soar.set_summary(ListNamedLocationsSummary(num_named_locations=len(locations)))
    return [ListNamedLocationsOutput(**location) for location in locations]
