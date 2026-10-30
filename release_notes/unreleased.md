**Unreleased**

* Allow asset-specific delegated OAuth scopes while preserving blank-field defaults and application authentication. Explicitly scoped connectivity validates authentication without requiring user-list access; scope changes require reauthorization, with guidance preserved in make request failures.

* Expire pending OAuth handoffs and reject callbacks after connectivity timeout.
* Force a delegated token refresh when the generate token action is explicitly requested.
* Correct collection and password-profile output metadata and advertise Python 3.13 only.
* Restore SDK setup guidance, publication files and historical release notes.

* Add the SDK-native make request action for versioned Microsoft Graph requests using the asset's authentication and cloud, with raw HTTP status/body outputs.

* Preserve the legacy Microsoft Graph application identity during SDK conversion.
* Implement Microsoft Graph actions using SDK authentication while preserving legacy action contracts.
* Replace legacy custom result views with SDK-native tables while retaining complete action data.
* Validate OAuth callback state before recording errors, preserve boolean group-membership results, recover rejected application tokens once, and restore the publication workflow.
