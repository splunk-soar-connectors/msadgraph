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
from src.app import app, create_msadgraph_app
from src.asset import Asset


EXPECTED_ACTIONS = (
    "test_connectivity",
    "list_users",
    "reset_password",
    "invalidate_tokens",
    "enable_user",
    "disable_user",
    "list_user_devices",
    "list_user_attributes",
    "set_user_attribute",
    "remove_user",
    "add_user",
    "list_groups",
    "get_group",
    "list_group_members",
    "validate_group",
    "list_directory_roles",
    "list_named_locations",
    "add_cidr_to_named_location",
    "remove_cidr_from_named_location",
    "generate_token",
)


def test_exported_app_uses_typed_asset_and_registers_all_actions() -> None:
    assert app.asset_cls is Asset
    assert tuple(app.get_actions()) == EXPECTED_ACTIONS


def test_app_factory_builds_an_independent_application() -> None:
    created_app = create_msadgraph_app()

    assert created_app is not app
    assert created_app.asset_cls is Asset
    assert tuple(created_app.get_actions()) == EXPECTED_ACTIONS
