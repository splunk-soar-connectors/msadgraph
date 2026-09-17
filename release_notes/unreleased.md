**Unreleased**

* Store temporary OAuth callback handoff data through the connector state API and remove it after completion or timeout.
* Breaking (`reset password`): `temp_password` remains a required `password` input PARAMETER, but it is no longer copied into `ActionResult` or declared in the action OUTPUT. This changes only the output contract; callers must continue supplying the password because the app does not generate one.
