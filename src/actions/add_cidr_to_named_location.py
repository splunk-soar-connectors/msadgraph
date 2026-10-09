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
from ipaddress import ip_network
from typing import Any
from urllib.parse import quote, unquote

import httpx
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, ActionResult, OutputField
from soar_sdk.auth import OAuthClientError
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..auth import get_graph_client


class AddCidrToNamedLocationParams(Params):
    cidr_range: str = Param(
        description="IPv4 or IPv6 CIDR range, for example 1.1.1.0/24 or 2001:db8::/32",
        primary=True,
        cef_types=["ip", "cidr"],
        column_name="CIDR Range",
    )
    location_id: str = Param(
        description="Object ID of the IP-based named location",
        primary=True,
        cef_types=["directory object id"],
        column_name="Location ID",
    )


class AddCidrToNamedLocationSummary(ActionOutput):
    status: str = OutputField(
        example_values=["Successfully added 1.1.1.0/24", "CIDR already present"]
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
    if not response.content and response.is_success:
        return {}
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


def add_cidr_to_named_location(
    params: AddCidrToNamedLocationParams, soar: SOARClient, asset: Asset
) -> ActionOutput:
    try:
        network = ip_network(params.cidr_range, strict=False)
    except ValueError as error:
        raise ActionFailure(f"Invalid CIDR range: {error}") from error
    normalized_cidr = str(network)
    cidr_type = (
        "#microsoft.graph.iPv4CidrRange"
        if network.version == 4
        else "#microsoft.graph.iPv6CidrRange"
    )
    try:
        endpoint = (
            "/identity/conditionalAccess/namedLocations/"
            f"{_quote_path_segment(params.location_id)}"
        )
        with get_graph_client(asset, str(soar.get_asset_id())) as graph_client:
            location = _get_graph_response(graph_client.get(endpoint))
            if location.get("@odata.type") != "#microsoft.graph.ipNamedLocation":
                raise RuntimeError(
                    f"Named location {params.location_id} is not an IP-based named location"
                )
            ranges = location.get("ipRanges", [])
            if not isinstance(ranges, list) or not all(
                isinstance(item, dict) for item in ranges
            ):
                raise RuntimeError(
                    "Microsoft Graph returned invalid named-location IP ranges"
                )
            if any(item.get("cidrAddress") == normalized_cidr for item in ranges):
                status = "CIDR already present"
                result = ActionResult(
                    True, "CIDR already present in named location", params.model_dump()
                )
                result.set_summary(
                    AddCidrToNamedLocationSummary(status=status).model_dump()
                )
                return result
            updated_ranges = [
                *ranges,
                {"@odata.type": cidr_type, "cidrAddress": normalized_cidr},
            ]
            _get_graph_response(
                graph_client.patch(
                    endpoint,
                    json={
                        "@odata.type": "#microsoft.graph.ipNamedLocation",
                        "ipRanges": updated_ranges,
                    },
                )
            )
    except (httpx.HTTPError, OAuthClientError, RuntimeError, ValueError) as error:
        raise ActionFailure(str(error)) from error
    status = f"Successfully added {normalized_cidr}"
    result = ActionResult(True, status, params.model_dump())
    result.set_summary(AddCidrToNamedLocationSummary(status=status).model_dump())
    return result
