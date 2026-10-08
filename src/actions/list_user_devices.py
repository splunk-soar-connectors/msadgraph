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


def list_user_devices(
    params: ListUserDevicesParams, soar: SOARClient, asset: Asset
) -> ListUserDevicesOutput:
    raise NotImplementedError()
