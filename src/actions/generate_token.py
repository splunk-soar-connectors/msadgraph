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
from soar_sdk.action_results import ActionOutput, ActionResult
from soar_sdk.auth import OAuthClientError
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import Params

from ..asset import Asset
from ..auth import (
    get_authorization_code_flow,
    get_client_credentials_flow,
    get_delegated_redirect_uri,
)


def generate_token(params: Params, soar: SOARClient, asset: Asset) -> ActionOutput:
    try:
        if asset.admin_access_required:
            get_client_credentials_flow(asset).authenticate()
        else:
            redirect_uri = get_delegated_redirect_uri(asset, str(soar.get_asset_id()))
            get_authorization_code_flow(
                asset,
                str(soar.get_asset_id()),
                redirect_uri=redirect_uri,
            ).get_token()
    except (OAuthClientError, RuntimeError, ValueError) as error:
        raise ActionFailure(str(error)) from error

    return ActionResult(True, "Token generated", params.model_dump())
