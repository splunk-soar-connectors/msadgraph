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


class ListGroupMembersParams(Params):
    group_object_id: str = Param(
        description="Object ID of group", primary=True, cef_types=["group object id"]
    )
    select_string: str | None = Param(
        description="Select string to get additional properties. Separate multiple values with commas"
    )
    expand_string: str | None = Param(
        description="Expand string to get a resource or collection referenced by a single relationship"
    )
    use_advanced_query: bool | None = Param(
        description="Use advanced query capabilities", default=False
    )


class OdataOutput(ActionOutput):
    type: str = OutputField(example_values=["#test.graph.user"])


class AssignedlicensesOutput(ActionOutput):
    skuId: str = OutputField(example_values=["189a915c-fe4f-4ffa-bde4-85b9628d07a0"])


class AssignedplansOutput(ActionOutput):
    assignedDateTime: str = OutputField(example_values=["2022-11-03T15:12:28Z"])
    capabilityStatus: str = OutputField(example_values=["Deleted"])
    service: str = OutputField(example_values=["AADPremiumService"])
    servicePlanId: str = OutputField(
        example_values=["eec0eb4f-6444-4f95-aba0-50c24d67f998"]
    )


class IdentitiesOutput(ActionOutput):
    issuer: str = OutputField(example_values=["test.com"])
    issuerAssignedId: str = OutputField(example_values=["test@user.test.com"])
    signInType: str = OutputField(example_values=["userPrincipalName"])


class OnpremisesextensionattributesOutput(ActionOutput):
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


class ProvisionedplansOutput(ActionOutput):
    capabilityStatus: str = OutputField(example_values=["Enabled"])
    provisioningStatus: str = OutputField(example_values=["Success"])
    service: str = OutputField(example_values=["testCommunicationsOnline"])


class ListGroupMembersOutput(ActionOutput):
    odata: OdataOutput
    accountEnabled: bool = OutputField(example_values=[True])
    ageGroup: str
    assignedLicenses: list[AssignedlicensesOutput]
    assignedPlans: list[AssignedplansOutput]
    city: str = OutputField(example_values=["Palo Alto"])
    companyName: str
    consentProvidedForMinor: str
    country: str = OutputField(example_values=["US"])
    createdDateTime: str = OutputField(example_values=["2016-06-09T18:33:27Z"])
    creationType: str
    deletedDateTime: str
    department: str
    displayName: str = OutputField(example_values=["Firstname Lastname"])
    employeeHireDate: str
    employeeId: str
    employeeOrgData: str
    employeeType: str
    externalUserState: str
    externalUserStateChangeDateTime: str
    faxNumber: str
    givenName: str
    id: str = OutputField(
        cef_types=["user id"], example_values=["17be76d0-35ed-4881-ab62-d2eb73c2ebe3"]
    )
    identities: list[IdentitiesOutput]
    isResourceAccount: str
    jobTitle: str
    legalAgeGroupClassification: str
    mail: str
    mailNickname: str = OutputField(example_values=["User"])
    mobilePhone: str
    officeLocation: str
    onPremisesDistinguishedName: str
    onPremisesDomainName: str
    onPremisesExtensionAttributes: OnpremisesextensionattributesOutput
    onPremisesImmutableId: str
    onPremisesLastSyncDateTime: str
    onPremisesSamAccountName: str
    onPremisesSecurityIdentifier: str
    onPremisesSyncEnabled: str
    onPremisesUserPrincipalName: str
    passwordPolicies: str
    passwordProfile: str
    postalCode: str = OutputField(example_values=["94303"])
    preferredDataLocation: str
    preferredLanguage: str
    provisionedPlans: list[ProvisionedplansOutput]
    refreshTokensValidFromDateTime: str = OutputField(
        example_values=["2022-08-08T13:00:58Z"]
    )
    showInAddressList: str
    signInSessionsValidFromDateTime: str = OutputField(
        example_values=["2022-08-08T13:00:58Z"]
    )
    state: str = OutputField(example_values=["CA"])
    streetAddress: str = OutputField(example_values=["2479 E. Bayshore Rd."])
    surname: str
    usageLocation: str = OutputField(example_values=["US"])
    userPrincipalName: str = OutputField(example_values=["ews_retest@test.com"])
    userType: str = OutputField(example_values=["Member"])


def list_group_members(
    params: ListGroupMembersParams, soar: SOARClient, asset: Asset
) -> ListGroupMembersOutput:
    raise NotImplementedError()
