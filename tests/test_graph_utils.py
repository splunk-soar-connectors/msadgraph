# Copyright (c) 2026 Splunk Inc.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
from copy import deepcopy

import pytest

from src.actions.list_directory_roles import ListDirectoryRolesOutput
from src.actions.list_users import ListUsersOutput
from src.graph_utils import normalize_odata, normalize_odata_object, quote_path_segment


@pytest.mark.parametrize(
    "identifier,encoded",
    [
        ("user@example.com", "user%40example.com"),
        ("a/b?#%", "a%2Fb%3F%23%25"),
        ("a%2Fb", "a%252Fb"),
        ("display name", "display%20name"),
    ],
)
def test_identifier_is_one_encoded_path_segment(identifier, encoded):
    assert quote_path_segment(identifier) == encoded


@pytest.mark.parametrize("identifier", [".", "..", "%2e", "%2E%2e", "%252e%252e"])
def test_encoded_dot_segments_are_rejected(identifier):
    with pytest.raises(ValueError, match="must not be dot segments"):
        quote_path_segment(identifier)


def test_recursive_annotations_preserve_original_fields_and_nested_values():
    value = {
        "@odata.type": "#microsoft.graph.user",
        "members": [{"@odata.type": "#microsoft.graph.group", "enabled": False}],
        "empty": None,
    }
    original = deepcopy(value)
    normalized = normalize_odata(value)
    assert normalized["@odata.type"] == value["@odata.type"]
    assert normalized["odata"] == {"type": "#microsoft.graph.user"}
    assert normalized["members"][0]["odata"] == {"type": "#microsoft.graph.group"}
    assert normalized["members"][0]["enabled"] is False
    assert normalized["empty"] is None
    assert value == original


def test_object_normalization_retains_existing_top_level_only_behavior():
    value = {
        "@odata.type": "#microsoft.graph.group",
        "nested": {"@odata.type": "#microsoft.graph.user"},
    }
    original = deepcopy(value)
    normalized = normalize_odata_object(value)
    assert normalized["odata"] == {"type": "#microsoft.graph.group"}
    assert normalized["nested"] == value["nested"]
    assert "odata" not in normalized["nested"]
    assert value == original


@pytest.mark.parametrize(
    "normalizer,output_cls",
    [
        (normalize_odata, ListUsersOutput),
        (normalize_odata_object, ListDirectoryRolesOutput),
    ],
)
def test_odata_aliases_preserve_existing_fields_through_output_serialization(
    normalizer, output_cls
):
    value = {
        "@odata.type": "#microsoft.graph.user",
        "@odata.context": "public-context",
        "odata": {"type": "existing-type", "custom": {"enabled": False}},
        "unknown": {"nested": True},
    }
    original = deepcopy(value)

    result = output_cls(**normalizer(value)).model_dump(by_alias=True)

    assert result == {
        **original,
        "odata": {"context": "public-context", **original["odata"]},
    }
    assert value == original


@pytest.mark.parametrize("normalizer", [normalize_odata, normalize_odata_object])
@pytest.mark.parametrize("existing", [None, "existing-value", []])
def test_odata_aliases_do_not_replace_an_existing_non_object(normalizer, existing):
    value = {"@odata.type": "#microsoft.graph.user", "odata": existing}
    original = deepcopy(value)

    assert normalizer(value) == original
    assert value == original


def test_recursive_annotations_preserve_nested_odata_fields():
    value = {
        "members": [
            {
                "@odata.type": "#microsoft.graph.group",
                "odata": {"custom": "existing-value"},
            }
        ]
    }
    original = deepcopy(value)

    result = normalize_odata(value)

    assert result["members"][0] == {
        **original["members"][0],
        "odata": {"type": "#microsoft.graph.group", "custom": "existing-value"},
    }
    assert value == original
