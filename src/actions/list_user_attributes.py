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


class ListUserAttributesParams(Params):
    user_id: str | None = Param(
        description="User ID - can be user principal name or object ID",
        primary=True,
        cef_types=["user id"],
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


class OdataOutput(ActionOutput):
    metadata: str = OutputField(
        example_values=[
            "https://graph.windows.net/1t309est-db6c-4tes-t1d2-12bf3456d78d/$metadata#directoryObjects/@Element"
        ]
    )
    type: str = OutputField(example_values=["test.DirectoryServices.User"])


class AssignedlicensesOutput(ActionOutput):
    skuId: str = OutputField(example_values=["f30db892-07e9-47e9-837c-80727f46fd3d"])


class AssignedplansOutput(ActionOutput):
    assignedTimestamp: str = OutputField(example_values=["2019-04-26T07:21:18Z"])
    capabilityStatus: str = OutputField(example_values=["Enabled"])
    service: str = OutputField(example_values=["exchange"])
    servicePlanId: str = OutputField(
        example_values=["33c4f319-9bdd-48d6-9c4d-410b750a4a5a"]
    )


class IdentitiesOutput(ActionOutput):
    issuer: str = OutputField(example_values=["test.com"])
    issuerAssignedId: str = OutputField(example_values=["test2@user.test.com"])
    signInType: str = OutputField(example_values=["userPrincipalName"])


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
            "directoryObjects/59f12345-1998-4932-a8ac-468e59374edc/test.DirectoryServices.User/thumbnailPhoto"
        ]
    )


class ListUserAttributesOutput(ActionOutput):
    odata: OdataOutput
    accountEnabled: bool
    ageGroup: str
    assignedLicenses: list[AssignedlicensesOutput]
    assignedPlans: list[AssignedplansOutput]
    city: str
    companyName: str
    consentProvidedForMinor: str
    country: str
    createdDateTime: str = OutputField(example_values=["2019-05-02T20:27:59Z"])
    creationType: str
    deletionTimestamp: str
    department: str = OutputField(example_values=["Sales"])
    dirSyncEnabled: str
    displayName: str = OutputField(example_values=["Test User"])
    employeeId: str
    facsimileTelephoneNumber: str
    givenName: str
    id: str = OutputField(
        cef_types=["user id"], example_values=["7d55d7e6-cf5a-4dd2-a176-57a3c33b7fa9"]
    )
    identities: list[IdentitiesOutput]
    immutableId: str
    isCompromised: str
    jobTitle: str
    lastDirSyncTime: str
    legalAgeGroupClassification: str
    mail: str = OutputField(cef_types=["email"])
    mailNickname: str = OutputField(example_values=["test"])
    mobile: str
    mobilePhone: str
    objectId: str = OutputField(example_values=["59f51194-1998-4932-a8ac-468e59374edc"])
    objectType: str = OutputField(example_values=["User"])
    officeLocation: str
    onPremisesDistinguishedName: str
    onPremisesSecurityIdentifier: str
    otherMails: str = OutputField(cef_types=["email"], example_values=["user@test.com"])
    passwordPolicies: str
    passwordProfile: PasswordprofileOutput
    physicalDeliveryOfficeName: str
    postalCode: str
    preferredLanguage: str
    provisionedPlans: list[ProvisionedplansOutput]
    proxyAddresses: str = OutputField(
        example_values=["SMTP:test_shared_mailbox@test.com"]
    )
    refreshTokensValidFromDateTime: str = OutputField(
        example_values=["2019-05-16T19:54:18Z"]
    )
    showInAddressList: str
    sipProxyAddress: str = OutputField(cef_types=["email"])
    state: str
    streetAddress: str
    surname: str
    telephoneNumber: str
    thumbnailPhoto_odata: Thumbnailphoto_OdataOutput
    usageLocation: str = OutputField(example_values=["US"])
    userPrincipalName: str = OutputField(
        cef_types=["user id"], example_values=["user@test.com"]
    )
    userState: str
    userStateChangedOn: str
    userType: str = OutputField(example_values=["Member"])


def list_user_attributes(
    params: ListUserAttributesParams, soar: SOARClient, asset: Asset
) -> ListUserAttributesOutput:
    raise NotImplementedError()
