**Unreleased**

* Encode caller-supplied Microsoft Graph path identifiers.
* Escape dynamic JavaScript values in action widgets.
* Bind OAuth callbacks to their initiating authorization flow.
* Escape validate group filters and report the actual membership result.
* Exclude OAuth token responses from diagnostic debug data.
* Remove temporary passwords from persisted action parameters.
* Revoke active sessions when disabling a user.
* Reject exact and nested-encoded dot segments in Microsoft Graph path identifiers.
* Disclose the residual lifetime of non-CAE access tokens after disabling a user.
* Require the pending-flow nonce before redirecting a browser into an OAuth flow.
* Keep temporary OAuth handshake files in the platform application-state directory and remove timed-out state.
