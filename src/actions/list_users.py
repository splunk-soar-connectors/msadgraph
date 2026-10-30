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
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField, PermissiveActionOutput
from soar_sdk.auth import OAuthClientError
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..auth import get_graph_client
from ..graph_response import get_graph_response


GRAPH_PAGE_SIZE = 999


def _normalize_odata(value: Any) -> Any:
    if isinstance(value, list):
        return [_normalize_odata(item) for item in value]
    if not isinstance(value, dict):
        return value
    normalized = {key: _normalize_odata(item) for key, item in value.items()}
    odata = {
        key.removeprefix("@odata."): _normalize_odata(item)
        for key, item in value.items()
        if key.startswith("@odata.")
    }
    if odata:
        normalized["odata"] = odata
    return normalized


class _GraphAPIError(RuntimeError):
    """An error response or invalid payload returned by Microsoft Graph."""


def _get_users(
    client: httpx.Client,
    *,
    headers: dict[str, str],
    params: dict[str, str],
) -> list[dict[str, Any]]:
    users: list[dict[str, Any]] = []
    next_params: dict[str, str] | None = dict(params)

    while next_params is not None:
        response = client.get("/users", headers=headers, params=next_params)
        payload = get_graph_response(response)
        page = payload.get("value")
        if not isinstance(page, list):
            raise _GraphAPIError(
                "Microsoft Graph response did not contain a list value"
            )
        if not all(isinstance(user, dict) for user in page):
            raise _GraphAPIError("Microsoft Graph returned an invalid user")
        users.extend(_normalize_odata(user) for user in page)

        raw_next_url = payload.get("@odata.nextLink") or payload.get("odata.nextLink")
        if raw_next_url is None:
            next_params = None
            continue
        if not isinstance(raw_next_url, str):
            raise _GraphAPIError("Microsoft Graph returned an invalid next page URL")
        skip_tokens = parse_qs(urlparse(raw_next_url).query).get("$skiptoken")
        if not skip_tokens:
            raise _GraphAPIError(
                "Microsoft Graph next page URL did not contain a skip token"
            )
        next_params = {**params, "$skiptoken": skip_tokens[0]}

    return users


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
    forceChangePasswordNextSignIn: bool
    forceChangePasswordNextSignInWithMfa: bool
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


class ListUsersOutput(PermissiveActionOutput):
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
    displayName: str = OutputField(example_values=["User"], column_name="Display Name")
    employeeId: str
    facsimileTelephoneNumber: str
    givenName: str = OutputField(example_values=["testuser"])
    id: str = OutputField(
        cef_types=["user id"],
        example_values=["e4c722ac-3b83-478d-8f52-c388885dc30f"],
        column_name="Object ID",
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
    otherMails: list[str] = OutputField(
        cef_types=["email"], example_values=["user.test@outlook.com"]
    )
    passwordPolicies: str = OutputField(example_values=["None"])
    passwordProfile: PasswordprofileOutput
    physicalDeliveryOfficeName: str
    postalCode: str = OutputField(example_values=["94303"])
    preferredLanguage: str = OutputField(example_values=["en-US"])
    provisionedPlans: list[ProvisionedplansOutput]
    proxyAddresses: list[str] = OutputField(example_values=["SMTP:user1@test.com"])
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
    thumbnailPhoto_odata: Thumbnailphoto_OdataOutput = OutputField(
        alias="thumbnailPhoto@odata"
    )
    usageLocation: str = OutputField(example_values=["US"])
    userPrincipalName: str = OutputField(
        cef_types=["user id"],
        example_values=["user@test.com"],
        column_name="User Principal Name",
    )
    userState: str
    userStateChangedOn: str
    userType: str = OutputField(example_values=["Member"])


class ListUsersSummary(ActionOutput):
    num_users: int = OutputField(example_values=[8])
    result_found: bool | None = OutputField(example_values=[True, False])
    total_results: int | None = OutputField(example_values=[7])


def list_users(
    params: ListUsersParams, soar: SOARClient, asset: Asset
) -> list[ListUsersOutput]:
    query: dict[str, str] = {"$top": str(GRAPH_PAGE_SIZE)}
    headers: dict[str, str] = {}

    if params.filter_string:
        query["$filter"] = params.filter_string
    if params.select_string:
        selected_fields = [
            value.strip() for value in params.select_string.split(",") if value.strip()
        ]
        if selected_fields:
            query["$select"] = ",".join(selected_fields)
    if params.expand_string:
        query["$expand"] = params.expand_string
    if params.use_advanced_query:
        headers["ConsistencyLevel"] = "eventual"
        query["$count"] = "true"

    try:
        with get_graph_client(asset, str(soar.get_asset_id())) as graph_client:
            users = _get_users(
                graph_client,
                headers=headers,
                params=query,
            )
    except (httpx.HTTPError, OAuthClientError, RuntimeError, ValueError) as error:
        raise ActionFailure(str(error)) from error

    soar.set_message(f"Num users: {len(users)}")
    soar.set_summary(ListUsersSummary(num_users=len(users)))
    return [ListUsersOutput(**user) for user in users]
