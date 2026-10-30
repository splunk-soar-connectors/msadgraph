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
import os
import sys
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))


class RedactedAssetConfig(dict[str, str]):
    """Keep live credentials out of pytest configuration representations."""

    def __repr__(self) -> str:
        return f"{type(self).__name__}(<redacted>)"


@pytest.fixture(scope="session")
def live_asset_config() -> RedactedAssetConfig:
    """Provide client credentials to opt-in live tests, skipping if unavailable.

    Export MSGRAPH_TENANT_ID, MSGRAPH_CLIENT_ID and MSGRAPH_CLIENT_SECRET
    before running live tests. Existing offline tests do not use this fixture.
    """
    config = RedactedAssetConfig()
    missing: list[str] = []
    for name in ("tenant_id", "client_id", "client_secret"):
        env_name = f"MSGRAPH_{name.upper()}"
        value = os.environ.get(env_name)
        if value:
            config[name] = value
        else:
            missing.append(env_name)

    if missing:
        pytest.skip(
            "Missing required live test environment variables: " + ", ".join(missing)
        )

    return config
