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


class ListGroupsParams(Params):
    filter_string: str | None = Param(
        description="Filter string to apply to group listing"
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
    type: str = OutputField(example_values=["test.DirectoryServices.Group"])


class ListGroupsOutput(ActionOutput):
    classification: str
    createdDateTime: str = OutputField(example_values=["2021-03-25T18:40:53Z"])
    deletedDateTime: str
    deletionTimestamp: str
    description: str = OutputField(example_values=["This is for testing purpose"])
    dirSyncEnabled: str
    displayName: str = OutputField(example_values=["Test-site"])
    expirationDateTime: str
    id: str = OutputField(
        cef_types=["group object id"],
        example_values=["2a201c95-101b-42d9-a7af-9a2fdf8193f1"],
    )
    isAssignableToRole: str
    lastDirSyncTime: str
    mail: str = OutputField(cef_types=["email"], example_values=["Test-site@test.com"])
    mailEnabled: bool
    mailNickname: str = OutputField(example_values=["Test-site"])
    membershipRule: str
    membershipRuleProcessingState: str
    objectType: str = OutputField(example_values=["Group"])
    odata: OdataOutput
    onPremisesDomainName: str = OutputField(cef_types=["domain"])
    onPremisesLastSyncDateTime: str
    onPremisesNetBiosName: str
    onPremisesSamAccountName: str
    onPremisesSecurityIdentifier: str
    onPremisesSyncEnabled: str
    preferredDataLocation: str
    preferredLanguage: str
    proxyAddresses: str = OutputField(example_values=["SMTP:test-h@test.com"])
    renewedDateTime: str = OutputField(example_values=["2021-03-25T18:40:53Z"])
    securityEnabled: bool
    securityIdentifier: str = OutputField(
        example_values=["S-1-12-1-294681889-1319597617-672379543-28952017"]
    )
    theme: str
    visibility: str = OutputField(example_values=["Private"])


def list_groups(
    params: ListGroupsParams, soar: SOARClient, asset: Asset
) -> ListGroupsOutput:
    raise NotImplementedError()
