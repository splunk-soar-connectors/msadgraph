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
from src.actions.validate_group import ValidateGroupOutput, ValidateGroupSummary
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
    "make_request",
)

EXPECTED_TABLE_COLUMNS = {
    "list_users": ("Display Name", "Object ID", "User Principal Name"),
    "list_user_devices": ("Device ID", "Display Name"),
    "list_user_attributes": (
        "Display Name",
        "User Object ID",
        "User Principal Name",
    ),
    "list_groups": ("Display Name", "Description", "Group Object ID"),
    "get_group": (
        "Description",
        "Display Name",
        "Object ID",
        "Security Enabled",
        "Mail Enabled",
    ),
    "list_group_members": (
        "Display Name",
        "User Object ID",
        "User Principal Name",
    ),
}


def test_exported_app_uses_typed_asset_and_registers_all_actions() -> None:
    assert app.asset_cls is Asset
    assert tuple(app.get_actions()) == EXPECTED_ACTIONS


def test_app_factory_builds_an_independent_application() -> None:
    created_app = create_msadgraph_app()

    assert created_app is not app
    assert created_app.asset_cls is Asset
    assert tuple(created_app.get_actions()) == EXPECTED_ACTIONS


def test_migrated_custom_views_use_sdk_tables() -> None:
    for action_name, expected_columns in EXPECTED_TABLE_COLUMNS.items():
        action = app.actions_manager.get_action(action_name)
        columns = tuple(
            field["column_name"]
            for field in action.meta.output._to_json_schema()
            if "column_name" in field
        )

        assert action.meta.render_as == "table"
        assert columns == expected_columns


def test_legacy_platform_and_read_only_contract() -> None:
    assert app.app_meta_info["min_phantom_version"] == "8.6.0"
    read_only_actions = {
        "list_users",
        "list_user_devices",
        "list_user_attributes",
        "list_groups",
        "get_group",
        "list_group_members",
        "validate_group",
        "list_directory_roles",
        "list_named_locations",
    }
    for action_name in EXPECTED_ACTIONS:
        if action_name != "test_connectivity":
            action = app.actions_manager.get_action(action_name)
            assert action.meta.read_only == (action_name in read_only_actions)


def test_user_attributes_advertises_legacy_photo_datapath() -> None:
    action = app.actions_manager.get_action("list_user_attributes")
    datapaths = {field["data_path"] for field in action.meta.output._to_json_schema()}
    assert "action_result.data.*.thumbnailPhoto@odata.mediaEditLink" in datapaths
    assert not any("thumbnailPhoto_odata" in path for path in datapaths)


def test_group_membership_preserves_boolean_contract() -> None:
    assert ValidateGroupOutput.model_fields["user_in_group"].annotation is bool
    assert ValidateGroupSummary.model_fields["user_in_group"].annotation is bool
    for membership in (True, False):
        summary = ValidateGroupSummary(user_in_group=membership, message="")
        assert summary.model_dump()["user_in_group"] is membership

    action = app.actions_manager.get_action("validate_group")
    fields = {
        field["data_path"]: field for field in action.meta.output._to_json_schema()
    }
    assert fields["action_result.data.*.user_in_group"]["data_type"] == "boolean"
