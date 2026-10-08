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


class ValidateGroupParams(Params):
    group_object_id: str = Param(
        description="Object ID of group", primary=True, cef_types=["group object id"]
    )
    user_id: str = Param(
        description="User ID to validate", primary=True, cef_types=["user id"]
    )


class OdataOutput(ActionOutput):
    type: str = OutputField(example_values=["#test.graph.group"])


class ValueOutput(ActionOutput):
    odata: OdataOutput
    classification: str
    createdDateTime: str = OutputField(example_values=["2022-02-25T12:05:22Z"])
    deletedDateTime: str
    description: str = OutputField(example_values=["Test group for MSGraph"])
    displayName: str = OutputField(example_values=["Test group for MSGraph"])
    expirationDateTime: str
    id: str = OutputField(
        cef_types=["user id"], example_values=["49233413-24c6-4516-a9e1-4d5f87fe34fd"]
    )
    isAssignableToRole: str
    mail: str = OutputField(example_values=["test@user.test.com"])
    mailEnabled: bool = OutputField(example_values=[True])
    mailNickname: str = OutputField(example_values=["TestgroupforMSGraph"])
    membershipRule: str
    membershipRuleProcessingState: str
    onPremisesDomainName: str
    onPremisesLastSyncDateTime: str
    onPremisesNetBiosName: str
    onPremisesSamAccountName: str
    onPremisesSecurityIdentifier: str
    onPremisesSyncEnabled: str
    preferredDataLocation: str
    preferredLanguage: str
    renewedDateTime: str = OutputField(example_values=["2022-02-25T12:05:22Z"])
    securityEnabled: bool = OutputField(example_values=[True])
    securityIdentifier: str = OutputField(
        example_values=["S-1-12-1-1227043859-1159079110-1598939561-4248108679"]
    )
    theme: str
    visibility: str = OutputField(example_values=["Private"])


class ValidateGroupOutput(ActionOutput):
    odata: OdataOutput
    user_in_group: str
    value: list[ValueOutput]


def validate_group(
    params: ValidateGroupParams, soar: SOARClient, asset: Asset
) -> ValidateGroupOutput:
    raise NotImplementedError()
