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
def test_registered_outputs_preserve_annotations_and_unknown_fields(
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

    result = action.meta.output(**payload).model_dump(by_alias=True)

    assert result == original
    assert payload == original


@pytest.mark.parametrize("action_name", ANNOTATED_ACTIONS)
def test_registered_outputs_do_not_add_nested_odata_objects(action_name):
    action = create_msadgraph_app().actions_manager.get_action(action_name)
    payload = {
        "@odata.type": "public-type",
        "value": [{"@odata.type": "public-nested-type"}],
    }

    assert action.meta.output(**payload).model_dump(by_alias=True) == payload


@pytest.mark.parametrize("action_name", ANNOTATED_ACTIONS)
def test_annotation_datapaths_use_graph_keys(action_name):
    action = create_msadgraph_app().actions_manager.get_action(action_name)
    datapaths = {field["data_path"] for field in action.meta.output._to_json_schema()}
    annotation = (
        "@odata.context" if action_name == "invalidate_tokens" else "@odata.type"
    )

    assert f"action_result.data.*.{annotation}" in datapaths
    assert not any(".odata." in path for path in datapaths)


def test_nested_ip_range_alias_serializes_with_original_graph_key():
    payload = {
        "@odata.type": "#microsoft.graph.iPv4CidrRange",
        "cidrAddress": "192.0.2.0/24",
    }

    assert IprangesOutput(**payload).model_dump(by_alias=True) == payload
