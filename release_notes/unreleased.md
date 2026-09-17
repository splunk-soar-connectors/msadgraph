**Unreleased**

* Store temporary OAuth callback handoff data through the connector state API and remove it after completion or timeout.
* Breaking: Store reset-password temporary passwords in Vault and return a Vault ID instead of returning the password in action parameters.
