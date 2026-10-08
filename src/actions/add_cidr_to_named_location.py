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
from soar_sdk.action_results import ActionOutput
from soar_sdk.params import Param, Params

from ..asset import Asset


class AddCidrToNamedLocationParams(Params):
    cidr_range: str = Param(
        description="IPv4 or IPv6 CIDR range, for example 1.1.1.0/24 or 2001:db8::/32",
        primary=True,
        cef_types=["ip", "cidr"],
    )
    location_id: str = Param(
        description="Object ID of the IP-based named location",
        primary=True,
        cef_types=["directory object id"],
    )


def add_cidr_to_named_location(
    params: AddCidrToNamedLocationParams, soar: SOARClient, asset: Asset
) -> ActionOutput:
    raise NotImplementedError()
