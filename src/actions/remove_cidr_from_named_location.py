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
from urllib.parse import quote, unquote

import httpx
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, ActionResult, OutputField
from soar_sdk.auth import OAuthClientError
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..auth import get_graph_client
from ..graph_response import get_graph_response


class RemoveCidrFromNamedLocationParams(Params):
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


class RemoveCidrFromNamedLocationSummary(ActionOutput):
    status: str = OutputField(
        example_values=["Successfully removed 1.1.1.0/24", "CIDR not present"]
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


def remove_cidr_from_named_location(
    params: RemoveCidrFromNamedLocationParams, soar: SOARClient, asset: Asset
) -> ActionOutput:
    try:
        normalized_cidr = str(ip_network(params.cidr_range, strict=False))
    except ValueError as error:
        raise ActionFailure(f"Invalid CIDR range: {error}") from error
    try:
        endpoint = (
            "/identity/conditionalAccess/namedLocations/"
            f"{_quote_path_segment(params.location_id)}"
        )
        with get_graph_client(asset, str(soar.get_asset_id())) as graph_client:
            location = get_graph_response(graph_client.get(endpoint), allow_empty=True)
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
            updated_ranges = [
                item for item in ranges if item.get("cidrAddress") != normalized_cidr
            ]
            if len(updated_ranges) == len(ranges):
                status = "CIDR not present"
                result = ActionResult(
                    True, "CIDR not present in named location", params.model_dump()
                )
                result.set_summary(
                    RemoveCidrFromNamedLocationSummary(status=status).model_dump()
                )
                return result
            get_graph_response(
                graph_client.patch(
                    endpoint,
                    json={
                        "@odata.type": "#microsoft.graph.ipNamedLocation",
                        "ipRanges": updated_ranges,
                    },
                ),
                allow_empty=True,
            )
    except (httpx.HTTPError, OAuthClientError, RuntimeError, ValueError) as error:
        raise ActionFailure(str(error)) from error
    status = f"Successfully removed {normalized_cidr}"
    result = ActionResult(True, status, params.model_dump())
    result.set_summary(RemoveCidrFromNamedLocationSummary(status=status).model_dump())
    return result
