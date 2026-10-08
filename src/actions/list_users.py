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


class ListUsersParams(Params):
    filter_string: str | None = Param(
        description="Filter string to apply to user listing"
    )
    select_string: str | None = Param(
        description="Select string to get additional user properties. Separate multiple values with commas"
    )
    expand_string: str | None = Param(
        description="Expand string to get a resource or collection referenced by a single relationship"
    )
    use_advanced_query: bool | None = Param(
        description="Use advanced query capabilities", default=False
    )


class AssignedlicensesOutput(ActionOutput):
    skuId: str = OutputField(example_values=["189a915c-fe4f-4ffa-bde4-85b9628d07a0"])


class AssignedplansOutput(ActionOutput):
    assignedTimestamp: str = OutputField(example_values=["2017-08-29T02:31:40Z"])
    capabilityStatus: str = OutputField(example_values=["Enabled"])
    service: str = OutputField(example_values=["OfficeForms"])
    servicePlanId: str = OutputField(
        example_values=["e212cbc7-0961-4c40-9825-01117710dcb1"]
    )


class OdataOutput(ActionOutput):
    type: str = OutputField(example_values=["test.DirectoryServices.User"])


class PasswordprofileOutput(ActionOutput):
    enforceChangePasswordPolicy: bool
    forceChangePasswordNextLogin: bool
    password: str


class ProvisionedplansOutput(ActionOutput):
    capabilityStatus: str = OutputField(example_values=["Enabled"])
    provisioningStatus: str = OutputField(example_values=["Success"])
    service: str = OutputField(example_values=["exchange"])


class Thumbnailphoto_OdataOutput(ActionOutput):
    mediaEditLink: str = OutputField(
        example_values=[
            "directoryObjects/6132ca31-7a09-434f-a269-abe836d0c01e/test.DirectoryServices.User/thumbnailPhoto"
        ]
    )


class ListUsersOutput(ActionOutput):
    accountEnabled: bool
    ageGroup: str
    assignedLicenses: list[AssignedlicensesOutput]
    assignedPlans: list[AssignedplansOutput]
    city: str = OutputField(example_values=["Palo Alto"])
    companyName: str
    consentProvidedForMinor: str
    country: str = OutputField(example_values=["US"])
    createdDateTime: str = OutputField(example_values=["2019-05-21T22:27:20Z"])
    creationType: str
    deletionTimestamp: str
    department: str = OutputField(example_values=["Sales"])
    dirSyncEnabled: str
    displayName: str = OutputField(example_values=["User"])
    employeeId: str
    facsimileTelephoneNumber: str
    givenName: str = OutputField(example_values=["testuser"])
    id: str = OutputField(
        cef_types=["user id"], example_values=["e4c722ac-3b83-478d-8f52-c388885dc30f"]
    )
    immutableId: str
    isCompromised: str
    jobTitle: str = OutputField(example_values=["Sales Manager"])
    lastDirSyncTime: str
    legalAgeGroupClassification: str
    mail: str = OutputField(cef_types=["email"], example_values=["user@test.com"])
    mailNickname: str = OutputField(example_values=["testmail"])
    mobile: str = OutputField(example_values=["+1 5556378688"])
    mobilePhone: str
    objectType: str = OutputField(example_values=["User"])
    odata: OdataOutput
    officeLocation: str
    onPremisesDistinguishedName: str
    onPremisesSecurityIdentifier: str
    otherMails: str = OutputField(
        cef_types=["email"], example_values=["user.test@outlook.com"]
    )
    passwordPolicies: str = OutputField(example_values=["None"])
    passwordProfile: PasswordprofileOutput
    physicalDeliveryOfficeName: str
    postalCode: str = OutputField(example_values=["94303"])
    preferredLanguage: str = OutputField(example_values=["en-US"])
    provisionedPlans: list[ProvisionedplansOutput]
    proxyAddresses: str = OutputField(example_values=["SMTP:user1@test.com"])
    refreshTokensValidFromDateTime: str = OutputField(
        example_values=["2017-09-27T22:54:59Z"]
    )
    showInAddressList: str
    sipProxyAddress: str = OutputField(
        cef_types=["email"], example_values=["user@test.com"]
    )
    state: str = OutputField(example_values=["CA"])
    streetAddress: str = OutputField(example_values=["2479 E. Bayshore Rd."])
    surname: str = OutputField(example_values=["Test_surname"])
    telephoneNumber: str
    thumbnailPhoto_odata: Thumbnailphoto_OdataOutput
    usageLocation: str = OutputField(example_values=["US"])
    userPrincipalName: str = OutputField(
        cef_types=["user id"], example_values=["user@test.com"]
    )
    userState: str
    userStateChangedOn: str
    userType: str = OutputField(example_values=["Member"])


def list_users(
    params: ListUsersParams, soar: SOARClient, asset: Asset
) -> ListUsersOutput:
    raise NotImplementedError()
