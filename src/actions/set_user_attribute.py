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
import contextlib
import json
from urllib.parse import quote, unquote

import httpx
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, ActionResult, OutputField
from soar_sdk.auth import OAuthClientError
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..auth import get_graph_client


class SetUserAttributeParams(Params):
    user_id: str = Param(
        description="User ID - can be user principal name or object ID",
        primary=True,
        cef_types=["user id"],
        column_name="User ID",
    )
    attribute: str = Param(description="Attribute to set", column_name="Attribute Name")
    attribute_value: str = Param(
        description="Value of attribute to set", column_name="Attribute Value"
    )


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


class SetUserAttributeSummary(ActionOutput):
    status: str = OutputField(example_values=["Successfully updated user attribute"])


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


def _raise_for_graph_error(response: httpx.Response) -> None:
    if response.is_success:
        return
    try:
        payload = response.json()
    except ValueError:
        response.raise_for_status()
        return
    error = payload.get("error") if isinstance(payload, dict) else payload
    if isinstance(error, dict):
        error = error.get("message", error)
    raise RuntimeError(
        f"Error from server. Status Code: {response.status_code}. Data from server: \n{error}\n"
    )


def set_user_attribute(
    params: SetUserAttributeParams, soar: SOARClient, asset: Asset
) -> ActionOutput:
    attribute_value: object = params.attribute_value
    with contextlib.suppress(json.JSONDecodeError):
        attribute_value = json.loads(params.attribute_value)

    try:
        endpoint = f"/users/{_quote_path_segment(params.user_id)}"
        with get_graph_client(asset, str(soar.get_asset_id())) as graph_client:
            response = graph_client.patch(
                endpoint, json={params.attribute: attribute_value}
            )
            _raise_for_graph_error(response)
    except (httpx.HTTPError, OAuthClientError, RuntimeError, ValueError) as error:
        raise ActionFailure(str(error)) from error

    status = "Successfully updated user attribute"
    result = ActionResult(True, f"Status: {status}", params.model_dump())
    result.set_summary(SetUserAttributeSummary(status=status).model_dump())
    return result
