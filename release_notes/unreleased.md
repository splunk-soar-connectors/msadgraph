**Unreleased**

* Store temporary OAuth callback handoff data through the connector state API and remove it after completion or timeout.
* Breaking (`reset password`): `temp_password` remains a required password input parameter, but the password is no longer returned as `action_result.parameter.temp_password`. The action stores the secret in the executing container's Vault, and its OUTPUT returns only the Vault reference `temp_password_vault_id` through `action_result.data.*.temp_password_vault_id` and `action_result.summary.temp_password_vault_id`.
