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


class ListGroupMembersOutput(PermissiveActionOutput):
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
    displayName: str = OutputField(
        example_values=["Firstname Lastname"], column_name="Display Name"
    )
    employeeHireDate: str
    employeeId: str
    employeeOrgData: str
    employeeType: str
    externalUserState: str
    externalUserStateChangeDateTime: str
    faxNumber: str
    givenName: str
    id: str = OutputField(
        cef_types=["user id"],
        example_values=["17be76d0-35ed-4881-ab62-d2eb73c2ebe3"],
        column_name="User Object ID",
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
    userPrincipalName: str = OutputField(
        cef_types=["user id"],
        example_values=["ews_retest@test.com"],
        column_name="User Principal Name",
    )
    userType: str = OutputField(example_values=["Member"])


class ListGroupMembersSummary(ActionOutput):
    num_users: int = OutputField(example_values=[8])


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


def _get_members(
    client: httpx.Client,
    endpoint: str,
    *,
    headers: dict[str, str],
    params: dict[str, str],
) -> list[dict[str, Any]]:
    members: list[dict[str, Any]] = []
    next_params: dict[str, str] | None = {**params, "$top": str(GRAPH_PAGE_SIZE)}
    while next_params is not None:
        payload = _get_graph_response(
            client.get(endpoint, headers=headers, params=next_params)
        )
        page = payload.get("value")
        if not isinstance(page, list) or not all(
            isinstance(item, dict) for item in page
        ):
            raise RuntimeError(
                "Microsoft Graph response did not contain a valid list value"
            )
        members.extend(_normalize_odata(item) for item in page)
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
    return members


def list_group_members(
    params: ListGroupMembersParams, soar: SOARClient, asset: Asset
) -> list[ListGroupMembersOutput]:
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
        endpoint = f"/groups/{_quote_path_segment(params.group_object_id)}/members"
        with get_graph_client(asset, str(soar.get_asset_id())) as graph_client:
            members = _get_members(
                graph_client, endpoint, headers=headers, params=query
            )
    except (httpx.HTTPError, OAuthClientError, RuntimeError, ValueError) as error:
        raise ActionFailure(str(error)) from error
    soar.set_message(f"Num users: {len(members)}")
    soar.set_summary(ListGroupMembersSummary(num_users=len(members)))
    return [ListGroupMembersOutput(**member) for member in members]
