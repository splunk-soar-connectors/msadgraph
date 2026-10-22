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
import json

import pytest
from soar_sdk.app import App
from soar_sdk.input_spec import InputSpecification

from src.app import app


@pytest.mark.parametrize("enabled", [True, False, None])
def test_sdk_handle_input_model_preserves_encryption_flag(enabled: bool | None) -> None:
    # Use the actual model resolved by SDK App.handle, not a substitute handler.
    model = App.handle.__globals__["InputSpecification"]
    assert app is not None
    assert model is InputSpecification
    raw = {
        "identifier": "reset_password",
        "asset_id": "1",
        "config": {
            "app_version": "2.0.0",
            "directory": "/tmp/sdk-input-diagnostic",
            "main_module": "app.py",
        },
    }
    if enabled is not None:
        raw["enable_action_parameter_encryption"] = enabled

    forwarded = json.loads(model.model_validate(raw).model_dump_json())

    assert forwarded["enable_action_parameter_encryption"] is (enabled is True)
