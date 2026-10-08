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
from soar_sdk.params import Params

from ..asset import Asset


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


def list_directory_roles(
    params: Params, soar: SOARClient, asset: Asset
) -> ListDirectoryRolesOutput:
    raise NotImplementedError()
