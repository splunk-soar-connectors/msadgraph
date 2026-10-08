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


class GetGroupParams(Params):
    object_id: str = Param(
        description="Object ID of group", primary=True, cef_types=["group object id"]
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
    metadata: str = OutputField(
        example_values=[
            "https://graph.windows.net/1t309est-db6c-4tes-t1d2-12bf3456d78d/$metadata#directoryObjects/@Element"
        ]
    )
    type: str = OutputField(example_values=["test.DirectoryServices.Group"])


class GetGroupOutput(ActionOutput):
    odata: OdataOutput
    classification: str
    createdDateTime: str = OutputField(example_values=["2020-08-05T11:59:49Z"])
    deletedDateTime: str
    deletionTimestamp: str
    description: str = OutputField(example_values=["This is the office 365 group"])
    dirSyncEnabled: str
    displayName: str = OutputField(example_values=["o365group"])
    expirationDateTime: str
    id: str = OutputField(
        cef_types=["group object id"],
        example_values=["ddb876b3-603a-437b-9814-2d46a2219a1e"],
    )
    isAssignableToRole: str
    lastDirSyncTime: str
    mail: str = OutputField(cef_types=["email"], example_values=["bc7f9cabe@test.com"])
    mailEnabled: bool
    mailNickname: str = OutputField(example_values=["bc7f9cabe"])
    membershipRule: str
    membershipRuleProcessingState: str
    objectType: str = OutputField(example_values=["Group"])
    onPremisesDomainName: str = OutputField(cef_types=["domain"])
    onPremisesLastSyncDateTime: str
    onPremisesNetBiosName: str
    onPremisesSamAccountName: str
    onPremisesSecurityIdentifier: str
    onPremisesSyncEnabled: str
    preferredDataLocation: str
    preferredLanguage: str
    proxyAddresses: str = OutputField(example_values=["SMTP:bc7f9cabe@test.com"])
    renewedDateTime: str = OutputField(example_values=["2020-08-05T11:59:49Z"])
    securityEnabled: bool
    securityIdentifier: str = OutputField(
        example_values=["S-1-12-1-909260723-1083662375-1952945031-2402852259"]
    )
    theme: str
    visibility: str


def get_group(params: GetGroupParams, soar: SOARClient, asset: Asset) -> GetGroupOutput:
    raise NotImplementedError()
