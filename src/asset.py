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
from soar_sdk.asset import AssetField, BaseAsset


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
