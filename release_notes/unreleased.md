**Unreleased**

* Expire pending OAuth handoffs and reject callbacks after connectivity timeout.
* Force a delegated token refresh when the generate token action is explicitly requested.
* Treat a successful legacy authorization-code exchange as token generation, even when no refresh token is returned; existing delegated sessions still require explicit refresh.
* Correct collection and password-profile output metadata and advertise Python 3.13 only. See the setup manual's corrected output datapaths and playbook migration table for array element selections, renamed properties and fields without a direct replacement.
* Restore SDK setup guidance, publication files and historical release notes.

* Add the SDK-native make request action for versioned Microsoft Graph requests using the asset's authentication and cloud, with raw HTTP status/body outputs.

* Preserve the legacy Microsoft Graph application identity during SDK conversion.
* Port Microsoft Graph actions to SDK authentication. Intentional output, validation and summary-metadata changes are described in the setup manual's SDK action behavior changes section.
* Expose the disable tokens Graph response in action data while retaining request error handling and its status summary. Playbooks must not require empty action data as a success condition.
* Fail invalid list response shapes or nonempty pagination continuations without a usable skip token instead of silently treating earlier pages as a complete result.
* Omit the synthetic Empty response record for pages beginning with an empty object; count returned objects. Normal empty collections still return no records and zero counts.
* Treat whitespace/comma-only select_string values as unspecified for list users, list groups, get group, list group members, list user attributes and list user devices.
* Preserve populated list summary keys and document removal of the legacy advertised-but-unpopulated get group display_name and list group members num_members summary fields, with replacement datapaths.
* Replace legacy custom result views with SDK-native tables while retaining complete action data.
* Validate OAuth callback state before recording errors, preserve boolean group-membership results, recover rejected application tokens once, and restore the publication workflow.
