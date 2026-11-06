# Copyright (c) 2026 Splunk Inc.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
"""Exercise actual SDK result adaptation and connector input rejection.

No Graph/OAuth responses are substituted. These checks do not establish later
page failure behavior against Microsoft or installed platform behavior.
"""

import json

import pytest
from soar_sdk.app import App

from src.action_failure import failed_result
from src.actions.list_users import ListUsersParams, ListUsersSummary
from src.app import create_msadgraph_app
from src.asset import Asset


PUBLIC_MARKER = "public-test-marker"


@pytest.mark.parametrize(
    "action_name,inputs,expected",
    [
        ("enable_user", {"user_id": ".."}, {"user_id": ".."}),
        ("disable_user", {"user_id": ".."}, {"user_id": ".."}),
        (
            "reset_password",
            {
                "user_id": "..",
                "temp_password": PUBLIC_MARKER,
                "force_change": False,
            },
            {"user_id": "..", "force_change": False},
        ),
        (
            "set_user_attribute",
            {
                "user_id": "..",
                "attribute": "passwordProfile",
                "attribute_value": PUBLIC_MARKER,
            },
            {"user_id": "..", "attribute": "passwordProfile"},
        ),
        (
            "make_request",
            {
                "http_method": "TRACE",
                "endpoint": f"/v1.0/users?secret={PUBLIC_MARKER}",
                "headers": json.dumps({"X-Secret": PUBLIC_MARKER}),
                "body": PUBLIC_MARKER,
                "query_parameters": f"secret={PUBLIC_MARKER}",
            },
            {"http_method": "TRACE", "verify_ssl": True, "timeout": None},
        ),
    ],
)
def test_registered_action_retains_safe_inputs_on_local_rejection(
    action_name, inputs, expected
):
    app = create_msadgraph_app()
    action = app.actions_manager.get_action(action_name)
    asset = Asset(tenant_id="unused", client_id="unused", client_secret="unused")

    status = action(action.params_class(**inputs), asset=asset)

    assert status is False
    [result] = app.actions_manager.get_results()
    assert result.get_status() is False
    assert result.get_param() == expected
    assert result.get_message()
    assert PUBLIC_MARKER not in repr(result.get_param())


@pytest.mark.parametrize("record_count", [0, 2])
def test_sdk_adapter_keeps_failed_result_data_summary_and_parameters(record_count):
    app = create_msadgraph_app()
    params = ListUsersParams(filter_string="accountEnabled eq true")
    records = [{"id": str(index)} for index in range(record_count)]
    result = failed_result(
        params,
        "Results incomplete",
        data=records,
        summary=ListUsersSummary(num_users=record_count, incomplete=True),
    )

    assert App._adapt_action_result(result, app.actions_manager, params) is False
    [stored] = app.actions_manager.get_results()
    assert stored.get_data() == records
    assert stored.get_param() == params.model_dump()
    assert stored.get_summary()["num_users"] == record_count
    assert stored.get_summary()["incomplete"] is True


@pytest.mark.parametrize(
    "action_name",
    [
        "list_users",
        "list_groups",
        "list_group_members",
        "list_user_attributes",
        "list_user_devices",
        "list_named_locations",
    ],
)
def test_paginated_actions_publish_completeness_summary(action_name):
    action = create_msadgraph_app().actions_manager.get_action(action_name)
    fields = {field["data_path"]: field for field in action.meta.model_dump()["output"]}
    assert fields["action_result.summary.incomplete"]["data_type"] == "boolean"
