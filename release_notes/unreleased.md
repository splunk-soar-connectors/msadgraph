**Unreleased**

* Migrate the connector to the Splunk SOAR SDK. Requires Python 3.13.
* Add **make request** for authenticated Microsoft Graph API calls.
* Replace custom result views with tables.
* Preserve Graph's original `@odata.*` fields. Correct output datapaths, data types, list counts and summaries. **Disable tokens** now returns the Graph response. See the app documentation for playbook upgrade guidance.
* Keep earlier records when a later page fails. Include non-sensitive parameters in handled failure results.
* Reject expired OAuth callbacks and refresh delegated tokens when **generate token** is run.
* Preserve cached tokens until actual expiry and retain usable legacy sessions with unknown expiry during upgrade.
