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
from soar_sdk.app import App

from .add_cidr_to_named_location import (
    AddCidrToNamedLocationSummary,
    add_cidr_to_named_location,
)
from .add_user import AddUserSummary, add_user
from .disable_user import DisableUserSummary, disable_user
from .enable_user import EnableUserSummary, enable_user
from .generate_token import generate_token
from .get_group import GetGroupSummary, get_group
from .invalidate_tokens import DisableTokensSummary, invalidate_tokens
from .list_directory_roles import ListDirectoryRolesSummary, list_directory_roles
from .list_group_members import ListGroupMembersSummary, list_group_members
from .list_groups import ListGroupsSummary, list_groups
from .list_named_locations import ListNamedLocationsSummary, list_named_locations
from .list_user_attributes import ListUserAttributesSummary, list_user_attributes
from .list_user_devices import ListUserDevicesSummary, list_user_devices
from .list_users import ListUsersSummary, list_users
from .make_request import make_request
from .remove_cidr_from_named_location import (
    RemoveCidrFromNamedLocationSummary,
    remove_cidr_from_named_location,
)
from .remove_user import RemoveUserSummary, remove_user
from .reset_password import ResetPasswordSummary, reset_password
from .set_user_attribute import SetUserAttributeSummary, set_user_attribute
from .validate_group import ValidateGroupSummary, validate_group


def register_actions(app: App) -> App:
    app.register_action(
        action=list_users,
        description="Get a list of users",
        action_type="investigate",
        read_only=True,
        render_as="table",
        summary_type=ListUsersSummary,
        verbose="For more information on using the filter_string, select_string and expand_string parameters, refer to https://docs.microsoft.com/en-us/graph/query-parameters. By default, only a limited set of properties are returned, to return an alternative property set use $select query parameter.",
    )
    app.register_action(
        action=reset_password,
        description="Reset or set a user's password in a Microsoft AD environment",
        action_type="contain",
        read_only=False,
        render_as="table",
        summary_type=ResetPasswordSummary,
        verbose="Password reset updates the user's passwordProfile property. The required temp_password input parameter is not included in action output. This property cannot be used for federated users; manage those passwords through the federation provider. For more information, refer to https://learn.microsoft.com/en-us/graph/api/user-update?view=graph-rest-1.0#request-body.",
    )
    app.register_action(
        action=invalidate_tokens,
        name="disable tokens",
        description="Invalidate all active refresh tokens for a user in a Microsoft AD environment",
        action_type="contain",
        read_only=False,
        render_as="table",
        summary_type=DisableTokensSummary,
    )
    app.register_action(
        action=enable_user,
        description="Enable a user",
        action_type="generic",
        read_only=False,
        render_as="table",
        summary_type=EnableUserSummary,
    )
    app.register_action(
        action=disable_user,
        description="Disable a user and revoke sign-in sessions. Already-issued access tokens for non-CAE resources may remain valid until they expire",
        action_type="generic",
        read_only=False,
        render_as="table",
        summary_type=DisableUserSummary,
    )
    app.register_action(
        action=list_user_devices,
        description="List devices for a specified user",
        action_type="investigate",
        read_only=True,
        render_as="table",
        summary_type=ListUserDevicesSummary,
        verbose="By default, only a limited set of properties are returned, to return an alternative property set use $select query parameter. For more information on using the select_string parameter, refer to <a href='https://docs.microsoft.com/en-us/graph/query-parameters#select-parameter' target='_blank'>this</a> documentation.",
    )
    app.register_action(
        action=list_user_attributes,
        description="List attributes for all or a specified user",
        action_type="investigate",
        read_only=True,
        render_as="table",
        summary_type=ListUserAttributesSummary,
        verbose="By default, only a limited set of properties are returned, to return an alternative property set use $select query parameter. For more information on using the select_string and expand_string parameters, refer to https://docs.microsoft.com/en-us/graph/query-parameters.",
    )
    app.register_action(
        action=set_user_attribute,
        description="Set an attribute for a user",
        action_type="generic",
        read_only=False,
        render_as="table",
        summary_type=SetUserAttributeSummary,
    )
    app.register_action(
        action=remove_user,
        description="Remove a user from a specified group",
        action_type="generic",
        read_only=False,
        render_as="table",
        summary_type=RemoveUserSummary,
    )
    app.register_action(
        action=add_user,
        description="Add a user to a specified group",
        action_type="generic",
        read_only=False,
        render_as="table",
        summary_type=AddUserSummary,
    )
    app.register_action(
        action=list_groups,
        description="List groups in the organization",
        action_type="investigate",
        read_only=True,
        render_as="table",
        summary_type=ListGroupsSummary,
        verbose="By default, only a limited set of properties are returned, to return an alternative property set use $select query parameter. For more information on using the select_string and expand_string parameters, refer to https://docs.microsoft.com/en-us/graph/query-parameters.",
    )
    app.register_action(
        action=get_group,
        description="Get information about a group",
        action_type="investigate",
        read_only=True,
        render_as="table",
        summary_type=GetGroupSummary,
        verbose="By default, only a limited set of properties are returned, to return an alternative property set use $select query parameter. For more information on using the select_string and expand_string parameters, refer to https://docs.microsoft.com/en-us/graph/query-parameters.",
    )
    app.register_action(
        action=list_group_members,
        description="List the members in a group",
        action_type="investigate",
        read_only=True,
        render_as="table",
        summary_type=ListGroupMembersSummary,
        verbose="By default, only a limited set of properties are returned, to return an alternative property set use $select query parameter. For more information on using the select_string and expand_string parameters, refer to https://docs.microsoft.com/en-us/graph/query-parameters.",
    )
    app.register_action(
        action=validate_group,
        description="Returns true if a user is in a group; otherwise, false",
        action_type="investigate",
        read_only=True,
        render_as="table",
        summary_type=ValidateGroupSummary,
    )
    app.register_action(
        action=list_directory_roles,
        description="List the directory roles that are activated in the tenant",
        action_type="investigate",
        read_only=True,
        render_as="table",
        summary_type=ListDirectoryRolesSummary,
        verbose="<p>Pagination is not implemented for this action as this endpoint does not support pagination. Here is the <b><a href='https://docs.microsoft.com/en-us/graph/paging' target='_blank'>Documentation</a></b> for the same.</p>",
    )
    app.register_action(
        action=list_named_locations,
        description="List named locations in Entra Conditional Access",
        action_type="investigate",
        read_only=True,
        render_as="table",
        summary_type=ListNamedLocationsSummary,
        verbose="For more information on using the filter and select parameters, refer to https://learn.microsoft.com/en-us/graph/filter-query-parameter and https://learn.microsoft.com/en-us/graph/query-parameters#select-parameter.",
    )
    app.register_action(
        action=add_cidr_to_named_location,
        description="Add a CIDR range to an IP-based named location in Entra Conditional Access",
        action_type="contain",
        read_only=False,
        render_as="table",
        summary_type=AddCidrToNamedLocationSummary,
    )
    app.register_action(
        action=remove_cidr_from_named_location,
        description="Remove a CIDR range from an IP-based named location in Entra Conditional Access",
        action_type="correct",
        read_only=False,
        render_as="table",
        summary_type=RemoveCidrFromNamedLocationSummary,
    )
    app.register_action(
        action=generate_token,
        description="Generate a token",
        action_type="generic",
        read_only=False,
        render_as="table",
    )
    app.make_request()(make_request)
    return app
