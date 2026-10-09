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
from urllib.parse import parse_qs, quote, unquote, urlparse

import httpx
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField, PermissiveActionOutput
from soar_sdk.auth import OAuthClientError
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..auth import get_graph_client


GRAPH_PAGE_SIZE = 999


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


class ListUserAttributesOutput(PermissiveActionOutput):
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


class ListUserAttributesSummary(ActionOutput):
    status: str = OutputField(
        example_values=[
            "Successfully retrieved attributes for user user@test.com",
            "Successfully retrieved user attributes",
        ]
    )


def _quote_path_segment(value: str) -> str:
    raw_value = str(value)
    canonical_value = raw_value
    for _ in range(5):
        decoded_value = unquote(canonical_value)
        if decoded_value == canonical_value:
            break
        canonical_value = decoded_value
    if canonical_value in {".", ".."}:
        raise ValueError("Microsoft Graph path identifiers must not be dot segments")
    return quote(raw_value, safe="")


def _get_graph_response(response: httpx.Response) -> dict[str, Any]:
    try:
        payload = response.json()
    except ValueError as error:
        if response.is_success:
            raise RuntimeError(
                "Unable to parse JSON response from Microsoft Graph"
            ) from error
        response.raise_for_status()
        raise
    if not response.is_success:
        graph_error = payload.get("error") if isinstance(payload, dict) else payload
        if isinstance(graph_error, dict):
            graph_error = graph_error.get("message", graph_error)
        raise RuntimeError(
            f"Error from server. Status Code: {response.status_code}. Data from server: \n{graph_error}\n"
        )
    if not isinstance(payload, dict):
        raise RuntimeError("Microsoft Graph returned a non-object JSON response")
    return payload


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


def _get_attributes(
    client: httpx.Client,
    endpoint: str,
    *,
    headers: dict[str, str],
    params: dict[str, str],
) -> list[dict[str, Any]]:
    attributes: list[dict[str, Any]] = []
    next_params: dict[str, str] | None = {**params, "$top": str(GRAPH_PAGE_SIZE)}
    while next_params is not None:
        payload = _get_graph_response(
            client.get(endpoint, headers=headers, params=next_params)
        )
        if "value" not in payload:
            attributes.append(_normalize_odata(payload))
            break
        page = payload.get("value")
        if not isinstance(page, list) or not all(
            isinstance(item, dict) for item in page
        ):
            raise RuntimeError(
                "Microsoft Graph response did not contain a valid list value"
            )
        attributes.extend(_normalize_odata(item) for item in page)
        next_link = payload.get("@odata.nextLink") or payload.get("odata.nextLink")
        if next_link is None:
            next_params = None
            continue
        if not isinstance(next_link, str):
            raise RuntimeError("Microsoft Graph returned an invalid next page URL")
        skip_tokens = parse_qs(urlparse(next_link).query).get("$skiptoken")
        if not skip_tokens:
            raise RuntimeError(
                "Microsoft Graph next page URL did not contain a skip token"
            )
        next_params = {
            **params,
            "$top": str(GRAPH_PAGE_SIZE),
            "$skiptoken": skip_tokens[0],
        }
    return attributes


def list_user_attributes(
    params: ListUserAttributesParams, soar: SOARClient, asset: Asset
) -> list[ListUserAttributesOutput]:
    query: dict[str, str] = {}
    headers: dict[str, str] = {}
    if params.select_string:
        values = [
            value.strip() for value in params.select_string.split(",") if value.strip()
        ]
        if values:
            query["$select"] = ",".join(values)
    if params.expand_string:
        query["$expand"] = params.expand_string
    if params.use_advanced_query:
        headers["ConsistencyLevel"] = "eventual"
        query["$count"] = "true"
    try:
        endpoint = (
            f"/users/{_quote_path_segment(params.user_id)}"
            if params.user_id
            else "/users"
        )
        with get_graph_client(asset, str(soar.get_asset_id())) as graph_client:
            attributes = _get_attributes(
                graph_client, endpoint, headers=headers, params=query
            )
    except (httpx.HTTPError, OAuthClientError, RuntimeError, ValueError) as error:
        raise ActionFailure(str(error)) from error
    status = (
        f"Successfully retrieved attributes for user {params.user_id}"
        if params.user_id
        else "Successfully retrieved user attributes"
    )
    soar.set_message(f"Status: {status}")
    soar.set_summary(ListUserAttributesSummary(status=status))
    return [ListUserAttributesOutput(**item) for item in attributes]
