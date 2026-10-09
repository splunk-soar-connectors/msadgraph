from typing import Union
from collections.abc import Iterator
from zoneinfo import ZoneInfo
from soar_sdk.abstract import SOARClient
from soar_sdk.app import App
from soar_sdk.params import Param, Params, OnPollParams, OnESPollParams
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.asset import BaseAsset, AssetField
from soar_sdk.logging import getLogger
from soar_sdk.models.container import Container
from soar_sdk.models.artifact import Artifact
from soar_sdk.models.finding import Finding
from soar_sdk.models.attachment_input import AttachmentInput

logger = getLogger()


class Asset(BaseAsset):
    tenant_id: str = AssetField(description="Tenant (Tenant ID or Tenant Name)")
    client_id: str = AssetField(description="Application ID")
    client_secret: str = AssetField(description="Client Secret")
    region: str | None = AssetField(
        description="Microsoft AD Region",
        default="Global",
        value_list=[
            "Global",
            "US Gov L4",
            "US Gov L5 (DOD)",
            "Germany",
            "China (21Vianet)",
        ],
    )
    admin_access_required: bool | None = AssetField(
        description="Admin Access Required", default=False
    )
    admin_access_granted: bool | None = AssetField(
        description="Admin Consent Already Provided", default=False
    )


app = App(
    name="msadgraph",
    app_type="identity management",
    logo="logo_msadgraph.svg",
    logo_dark="logo_msadgraph_dark.svg",
    product_vendor="Microsoft",
    product_name="MS Graph for Active Directory",
    publisher="Splunk",
    appid="f2a239df-acb2-47d6-861c-726a435cfe76",
    fips_compliant=True,
    encrypt_cache_state=True,
    encrypt_ingest_state=True,
    asset_cls=Asset,
)


@app.test_connectivity()
def test_connectivity(soar: SOARClient, asset: Asset) -> None:
    raise NotImplementedError()


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


@app.action(
    description="Get a list of users",
    action_type="investigate",
    verbose="For more information on using the filter_string, select_string and expand_string parameters, refer to https://docs.microsoft.com/en-us/graph/query-parameters. By default, only a limited set of properties are returned, to return an alternative property set use $select query parameter.",
)
def list_users(
    params: ListUsersParams, soar: SOARClient, asset: Asset
) -> ListUsersOutput:
    raise NotImplementedError()


class ResetPasswordParams(Params):
    user_id: str = Param(
        description="User ID to change password - can be user principal name or object ID",
        primary=True,
        cef_types=["user id"],
    )
    force_change: bool | None = Param(
        description="Force user to change password on next login", default=True
    )
    temp_password: str = Param(description="Temporary password for user")


@app.action(
    description="Reset or set a user's password in a Microsoft AD environment",
    action_type="contain",
    read_only=False,
    verbose="Password reset updates the user's passwordProfile property. The required temp_password input parameter is not included in action output. This property cannot be used for federated users; manage those passwords through the federation provider. For more information, refer to https://learn.microsoft.com/en-us/graph/api/user-update?view=graph-rest-1.0#request-body.",
)
def reset_password(
    params: ResetPasswordParams, soar: SOARClient, asset: Asset
) -> ActionOutput:
    raise NotImplementedError()


class DisableTokensParams(Params):
    user_id: str = Param(
        description="User ID to disable tokens of - can be user principal name or object ID",
        primary=True,
        cef_types=["user id"],
    )


class OdataOutput(ActionOutput):
    metadata: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://graph.windows.net/1t309est-db6c-4tes-t1d2-12bf3456d78d/$metadata#Edm.Null"
        ],
    )
    null: bool


class DisableTokensOutput(ActionOutput):
    odata: OdataOutput
    value: bool


@app.action(
    description="Invalidate all active refresh tokens for a user in a Microsoft AD environment",
    action_type="contain",
    read_only=False,
)
def invalidate_tokens(
    params: DisableTokensParams, soar: SOARClient, asset: Asset
) -> DisableTokensOutput:
    raise NotImplementedError()


class EnableUserParams(Params):
    user_id: str = Param(
        description="User ID to enable - can be user principal name or object ID",
        primary=True,
        cef_types=["user id"],
    )


@app.action(description="Enable a user", action_type="generic", read_only=False)
def enable_user(
    params: EnableUserParams, soar: SOARClient, asset: Asset
) -> ActionOutput:
    raise NotImplementedError()


class DisableUserParams(Params):
    user_id: str = Param(
        description="User ID to disable - can be user principal name or object ID",
        primary=True,
        cef_types=["user id"],
    )


@app.action(
    description="Disable a user and revoke sign-in sessions. Already-issued access tokens for non-CAE resources may remain valid until they expire",
    action_type="generic",
    read_only=False,
)
def disable_user(
    params: DisableUserParams, soar: SOARClient, asset: Asset
) -> ActionOutput:
    raise NotImplementedError()


class ListUserDevicesParams(Params):
    user_id: str = Param(
        description="User ID - can be user principal name or object ID",
        primary=True,
        cef_types=["user id"],
    )
    select_string: str | None = Param(
        description="Select string to get additional user properties. Separate multiple values with commas"
    )


class OdataOutput(ActionOutput):
    type: str = OutputField(example_values=["#test.graph.device"])


class AlternativesecurityidsOutput(ActionOutput):
    identityProvider: str
    key: str = OutputField(
        example_values=[
            "WAA1ADAAOQA6ADwAUwBIAEEAMQAtAFQAUAAtAFAAVQBCAEsARQBZAD4AOQA5AEEARQAwADgAOABDAEUANAA1ADgAMABCADcAQgBGAEEARQA2ADEAQQBCADYANAA3ADYANgA5ADUAOAAzAEQANABFAEYARQA5ADYAOAAyAHkAcQBSAEIANwBrAGEAMQA4AEoATAByACsAegB4AE8AYwB6AE8AYgBNAFEANQBZAEgAbgB0AFQAdgBOAG0AbgA5AEQAZQA2AFgAVQBUAGgAcwBFAD0A"
        ]
    )
    type: float = OutputField(example_values=[2])


class ExtensionattributesOutput(ActionOutput):
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


class ListUserDevicesOutput(ActionOutput):
    odata: OdataOutput
    accountEnabled: bool
    alternativeSecurityIds: list[AlternativesecurityidsOutput]
    approximateLastSignInDateTime: str = OutputField(
        example_values=["2019-09-26T03:42:15Z"]
    )
    complianceExpirationDateTime: str
    createdDateTime: str = OutputField(example_values=["2019-09-26T03:42:15Z"])
    deletedDateTime: str
    deviceCategory: str
    deviceId: str
    deviceMetadata: str
    deviceOwnership: str
    deviceVersion: float
    displayName: str
    domainName: str
    enrollmentProfileName: str
    enrollmentType: str
    extensionAttributes: ExtensionattributesOutput
    externalSourceName: str
    id: str
    isCompliant: bool
    isManaged: bool
    isRooted: str
    managementType: str
    manufacturer: str
    mdmAppId: str
    model: str
    onPremisesLastSyncDateTime: str
    onPremisesSyncEnabled: bool
    operatingSystem: str = OutputField(example_values=["Windows"])
    operatingSystemVersion: str = OutputField(example_values=["10.0.18362.0"])
    profileType: str = OutputField(example_values=["RegisteredDevice"])
    registrationDateTime: str = OutputField(example_values=["2019-09-26T03:42:15Z"])
    sourceType: str
    trustType: str = OutputField(example_values=["Workplace"])


@app.action(
    description="List devices for a specified user",
    action_type="investigate",
    verbose="By default, only a limited set of properties are returned, to return an alternative property set use $select query parameter. For more information on using the select_string parameter, refer to <a href='https://docs.microsoft.com/en-us/graph/query-parameters#select-parameter' target='_blank'>this</a> documentation.",
)
def list_user_devices(
    params: ListUserDevicesParams, soar: SOARClient, asset: Asset
) -> ListUserDevicesOutput:
    raise NotImplementedError()


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


@app.action(
    description="List attributes for all or a specified user",
    action_type="investigate",
    verbose="By default, only a limited set of properties are returned, to return an alternative property set use $select query parameter. For more information on using the select_string and expand_string parameters, refer to https://docs.microsoft.com/en-us/graph/query-parameters.",
)
def list_user_attributes(
    params: ListUserAttributesParams, soar: SOARClient, asset: Asset
) -> ListUserAttributesOutput:
    raise NotImplementedError()


class SetUserAttributeParams(Params):
    user_id: str = Param(
        description="User ID - can be user principal name or object ID",
        primary=True,
        cef_types=["user id"],
    )
    attribute: str = Param(description="Attribute to set")
    attribute_value: str = Param(description="Value of attribute to set")


class OdataOutput(ActionOutput):
    type: str = OutputField(example_values=["test.DirectoryServices.Group"])


class SetUserAttributeOutput(ActionOutput):
    classification: str
    createdDateTime: str = OutputField(example_values=["2021-03-25T18:40:53Z"])
    deletedDateTime: str
    deletionTimestamp: str
    description: str = OutputField(example_values=["This is for testing purpose"])
    dirSyncEnabled: str
    displayName: str = OutputField(example_values=["Test-site"])
    expirationDateTime: str
    id: str = OutputField(
        cef_types=["user id"], example_values=["2a201c95-101b-42d9-a7af-9a2fdf8193f1"]
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


@app.action(
    description="Set an attribute for a user", action_type="generic", read_only=False
)
def set_user_attribute(
    params: SetUserAttributeParams, soar: SOARClient, asset: Asset
) -> SetUserAttributeOutput:
    raise NotImplementedError()


class RemoveUserParams(Params):
    group_object_id: str = Param(
        description="Object ID of group", primary=True, cef_types=["group object id"]
    )
    user_id: str = Param(
        description="User ID to remove from group", primary=True, cef_types=["user id"]
    )


@app.action(
    description="Remove a user from a specified group",
    action_type="generic",
    read_only=False,
)
def remove_user(
    params: RemoveUserParams, soar: SOARClient, asset: Asset
) -> ActionOutput:
    raise NotImplementedError()


class AddUserParams(Params):
    group_object_id: str = Param(
        description="Object ID of group", primary=True, cef_types=["group object id"]
    )
    user_id: str = Param(
        description="User ID to add to group", primary=True, cef_types=["user id"]
    )


@app.action(
    description="Add a user to a specified group",
    action_type="generic",
    read_only=False,
)
def add_user(params: AddUserParams, soar: SOARClient, asset: Asset) -> ActionOutput:
    raise NotImplementedError()


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


@app.action(
    description="List groups in the organization",
    action_type="investigate",
    verbose="By default, only a limited set of properties are returned, to return an alternative property set use $select query parameter. For more information on using the select_string and expand_string parameters, refer to https://docs.microsoft.com/en-us/graph/query-parameters.",
)
def list_groups(
    params: ListGroupsParams, soar: SOARClient, asset: Asset
) -> ListGroupsOutput:
    raise NotImplementedError()


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


@app.action(
    description="Get information about a group",
    action_type="investigate",
    verbose="By default, only a limited set of properties are returned, to return an alternative property set use $select query parameter. For more information on using the select_string and expand_string parameters, refer to https://docs.microsoft.com/en-us/graph/query-parameters.",
)
def get_group(params: GetGroupParams, soar: SOARClient, asset: Asset) -> GetGroupOutput:
    raise NotImplementedError()


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


@app.action(
    description="List the members in a group",
    action_type="investigate",
    verbose="By default, only a limited set of properties are returned, to return an alternative property set use $select query parameter. For more information on using the select_string and expand_string parameters, refer to https://docs.microsoft.com/en-us/graph/query-parameters.",
)
def list_group_members(
    params: ListGroupMembersParams, soar: SOARClient, asset: Asset
) -> ListGroupMembersOutput:
    raise NotImplementedError()


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


@app.action(
    description="Returns true if a user is in a group; otherwise, false",
    action_type="investigate",
)
def validate_group(
    params: ValidateGroupParams, soar: SOARClient, asset: Asset
) -> ValidateGroupOutput:
    raise NotImplementedError()


class OdataOutput(ActionOutput):
    type: str = OutputField(example_values=["test.DirectoryServices.DirectoryRole"])


class ListDirectoryRolesOutput(ActionOutput):
    deletedDateTime: str
    deletionTimestamp: str
    description: str = OutputField(
        example_values=[
            "Can read basic directory information. For granting access to applications, not intended for users."
        ]
    )
    displayName: str = OutputField(example_values=["Directory Readers"])
    id: str = OutputField(
        cef_types=["directory object id"],
        example_values=["02b238cb-0d15-454b-aae6-0e94993a3207"],
    )
    isSystem: bool
    objectType: str = OutputField(example_values=["Role"])
    odata: OdataOutput
    roleTemplateId: str = OutputField(
        cef_types=["role template id"],
        example_values=["88d8e3e3-8f55-4a1e-953a-9b9898b8876b"],
    )


@app.action(
    description="List the directory roles that are activated in the tenant",
    action_type="investigate",
    verbose="<p>Pagination is not implemented for this action as this endpoint does not support pagination. Here is the <b><a href='https://docs.microsoft.com/en-us/graph/paging' target='_blank'>Documentation</a></b> for the same.</p>",
)
def list_directory_roles(
    params: Params, soar: SOARClient, asset: Asset
) -> ListDirectoryRolesOutput:
    raise NotImplementedError()


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


@app.action(
    description="List named locations in Entra Conditional Access",
    action_type="investigate",
    verbose="For more information on using the filter and select parameters, refer to https://learn.microsoft.com/en-us/graph/filter-query-parameter and https://learn.microsoft.com/en-us/graph/query-parameters#select-parameter.",
)
def list_named_locations(
    params: ListNamedLocationsParams, soar: SOARClient, asset: Asset
) -> ListNamedLocationsOutput:
    raise NotImplementedError()


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


@app.action(
    description="Add a CIDR range to an IP-based named location in Entra Conditional Access",
    action_type="contain",
    read_only=False,
)
def add_cidr_to_named_location(
    params: AddCidrToNamedLocationParams, soar: SOARClient, asset: Asset
) -> ActionOutput:
    raise NotImplementedError()


class RemoveCidrFromNamedLocationParams(Params):
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


@app.action(
    description="Remove a CIDR range from an IP-based named location in Entra Conditional Access",
    action_type="correct",
    read_only=False,
)
def remove_cidr_from_named_location(
    params: RemoveCidrFromNamedLocationParams, soar: SOARClient, asset: Asset
) -> ActionOutput:
    raise NotImplementedError()


@app.action(description="Generate a token", action_type="generic", read_only=False)
def generate_token(params: Params, soar: SOARClient, asset: Asset) -> ActionOutput:
    raise NotImplementedError()


if __name__ == "__main__":
    app.cli()
