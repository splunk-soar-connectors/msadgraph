# Copyright (c) 2026 Splunk Inc.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
"""Check SDK serialization and published datapaths without substituting Graph calls."""

from copy import deepcopy

import pytest

from src.app import create_msadgraph_app
from src.actions.list_named_locations import IprangesOutput
from src.graph_output import normalize_odata


ANNOTATED_ACTIONS = (
    "get_group",
    "invalidate_tokens",
    "list_directory_roles",
    "list_group_members",
    "list_groups",
    "list_named_locations",
    "list_user_attributes",
    "list_user_devices",
    "list_users",
    "validate_group",
)


@pytest.mark.parametrize("action_name", ANNOTATED_ACTIONS)
@pytest.mark.parametrize("existing_odata", [None, "existing-value", {"custom": True}])
def test_registered_outputs_preserve_fields_and_add_nested_aliases(
    action_name, existing_odata
):
    action = create_msadgraph_app().actions_manager.get_action(action_name)
    payload = {
        "@odata.type": "#microsoft.graph.directoryObject",
        "@odata.context": "public-context",
        "@odata.nextLink": "public-next-link",
        "odata": existing_odata,
        "unknown": {
            "nested": [{"@odata.type": "public-nested-type", "enabled": False}]
        },
    }
    original = deepcopy(payload)

    result = action.meta.output(**normalize_odata(payload)).model_dump(by_alias=True)

    assert result["@odata.type"] == original["@odata.type"]
    assert result["@odata.context"] == original["@odata.context"]
    assert result["@odata.nextLink"] == original["@odata.nextLink"]
    if isinstance(existing_odata, dict):
        assert result["odata"] == {
            "type": original["@odata.type"],
            "context": "public-context",
            "nextLink": "public-next-link",
            "custom": True,
        }
    else:
        assert result["odata"] == existing_odata
    assert result["unknown"]["nested"] == [
        {
            "@odata.type": "public-nested-type",
            "enabled": False,
            "odata": {"type": "public-nested-type"},
        }
    ]
    assert payload == original


@pytest.mark.parametrize("action_name", ANNOTATED_ACTIONS)
def test_registered_outputs_add_aliases_at_each_response_level(action_name):
    action = create_msadgraph_app().actions_manager.get_action(action_name)
    payload = {
        "@odata.type": "public-type",
        "value": [{"@odata.type": "public-nested-type"}],
    }

    result = action.meta.output(**normalize_odata(payload)).model_dump(by_alias=True)
    assert result["odata"]["type"] == "public-type"
    assert result["value"][0] == {
        "@odata.type": "public-nested-type",
        "odata": {"type": "public-nested-type"},
    }
    assert "odata" not in payload


@pytest.mark.parametrize("action_name", ANNOTATED_ACTIONS)
def test_annotation_datapaths_include_nested_and_original_keys(action_name):
    action = create_msadgraph_app().actions_manager.get_action(action_name)
    datapaths = {field["data_path"] for field in action.meta.output._to_json_schema()}
    annotation = (
        "@odata.context" if action_name == "invalidate_tokens" else "@odata.type"
    )

    assert f"action_result.data.*.{annotation}" in datapaths
    assert (
        f"action_result.data.*.odata.{annotation.removeprefix('@odata.')}" in datapaths
    )


def test_nested_ip_range_alias_serializes_with_original_graph_key():
    payload = {
        "@odata.type": "#microsoft.graph.iPv4CidrRange",
        "cidrAddress": "192.0.2.0/24",
    }

    result = IprangesOutput(**normalize_odata(payload)).model_dump(
        by_alias=True, exclude_none=True
    )
    assert result["@odata.type"] == payload["@odata.type"]
    assert result["odata"]["type"] == payload["@odata.type"]
    assert result["cidrAddress"] == payload["cidrAddress"]


@pytest.mark.parametrize("action_name", ANNOTATED_ACTIONS)
def test_unannotated_outputs_do_not_gain_odata_fields(action_name):
    payload = {"id": "public-id", "unknown": [None, False, 0, ""]}
    action = create_msadgraph_app().actions_manager.get_action(action_name)
    assert (
        action.meta.output(**normalize_odata(payload)).model_dump(by_alias=True)
        == payload
    )


def test_existing_nested_aliases_win_collisions_without_mutating_input():
    payload = {
        "@odata.type": "graph-type",
        "@odata.context": "graph-context",
        "odata": {"type": "existing-type", "custom": {"enabled": False}},
    }
    original = deepcopy(payload)
    result = normalize_odata(payload)
    assert result == {
        "@odata.type": "graph-type",
        "@odata.context": "graph-context",
        "odata": {
            "type": "existing-type",
            "context": "graph-context",
            "custom": {"enabled": False},
        },
    }
    assert normalize_odata(result) == result
    assert payload == original


def test_named_location_type_column_uses_extractable_nested_datapath():
    action = create_msadgraph_app().actions_manager.get_action("list_named_locations")
    columns = list(action.meta.output._to_json_schema())
    type_columns = [field for field in columns if field.get("column_name") == "Type"]
    assert [field["data_path"] for field in type_columns] == [
        "action_result.data.*.odata.type"
    ]
    assert any(
        field["data_path"] == "action_result.data.*.ipRanges.*.odata.type"
        for field in columns
    )
