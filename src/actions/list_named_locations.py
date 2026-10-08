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


class ListNamedLocationsParams(Params):
    location_type: str | None = Param(
        description="Type of named locations to return",
        default="all",
        value_list=["all", "ip", "country"],
    )
    filter: str | None = Param(
        description="Optional OData filter, for example contains(displayName,'Blocked')"
    )
    select: str | None = Param(
        description="Optional select string to get specific properties. Separate multiple values with commas"
    )


class OdataOutput(ActionOutput):
    type: str = OutputField(
        example_values=[
            "#microsoft.graph.iPv6CidrRange",
            "#microsoft.graph.iPv4CidrRange",
        ]
    )


class IprangesOutput(ActionOutput):
    odata: OdataOutput
    cidrAddress: str = OutputField(
        cef_types=["ip", "cidr"], example_values=["127.0.0.1/32", "2001:8000::/20"]
    )


class ListNamedLocationsOutput(ActionOutput):
    odata: OdataOutput
    id: str = OutputField(
        cef_types=["directory object id"],
        example_values=["0c0c6d27-93e7-4fd7-88a4-952c6d61a697"],
    )
    displayName: str = OutputField(example_values=["Named locations to be blocked"])
    createdDateTime: str = OutputField(
        cef_types=["datetime"], example_values=["2021-03-23T04:59:25.8014022Z"]
    )
    modifiedDateTime: str = OutputField(
        cef_types=["datetime"], example_values=["2021-03-23T08:05:02.1027085Z"]
    )
    isTrusted: bool
    ipRanges: list[IprangesOutput]
    countriesAndRegions: list[str] = OutputField(example_values=["US", "CA"])
    countryLookupMethod: str = OutputField(
        example_values=["clientIpAddress", "authenticatorAppGps"]
    )
    includeUnknownCountriesAndRegions: bool


def list_named_locations(
    params: ListNamedLocationsParams, soar: SOARClient, asset: Asset
) -> ListNamedLocationsOutput:
    raise NotImplementedError()
