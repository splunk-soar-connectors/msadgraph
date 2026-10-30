## Setup

This SDK-based connector supports delegated authorization-code authentication
and application authentication using client credentials. It requires a SOAR
installation with Python 3.13. Existing custom views are replaced by SDK tables.

### Register the Microsoft Entra application

1. Open **App registrations** in the Microsoft Entra admin center and register
   an application for your tenant.
1. Record the **Application (client) ID** and **Directory (tenant) ID**.
1. Under **Certificates & secrets**, create a client secret. Copy its **Value**,
   not its secret ID, into a secure store; manage expiration according to your
   organization's policy.
1. Under **API permissions**, add Microsoft Graph permissions for the chosen
   authentication mode and grant administrator consent where required. Delegated
   and application permissions are distinct; granting one does not grant the other.

See Microsoft's [delegated authorization guide](https://learn.microsoft.com/en-us/graph/auth-v2-user)
and [application authorization guide](https://learn.microsoft.com/en-us/graph/auth-v2-service).

### Configure the SOAR asset

Save the asset before configuring its callback. Use these configuration fields:

| Field | Value |
| --- | --- |
| **Tenant (Tenant ID or Tenant Name)** | Directory tenant ID or tenant name. |
| **Application ID** | Application client ID. |
| **Client Secret** | Client secret value. |
| **Microsoft AD Region** | Cloud containing the application and users; defaults to Global. |
| **Admin Access Required** | Leave unchecked for delegated authentication; check for application authentication. |
| **Admin Consent Already Provided** | For application authentication, check only after an administrator has granted the required application permissions. It does not grant consent itself. |

SOAR must reach the selected cloud's Microsoft identity and Graph endpoints over
HTTPS. National-cloud applications and permissions must belong to that cloud.
The Germany option is retained for legacy compatibility with a retired service;
its presence is not a claim of current service availability.

### Delegated authentication

Delegated actions run with both the application's granted permissions and the
signed-in user's privileges. The connector requests this fixed scope set:

```text
offline_access Group.ReadWrite.All User.Read.All User.ReadWrite.All
Directory.ReadWrite.All Directory.AccessAsUser.All User.ManageIdentities.All
GroupMember.ReadWrite.All RoleManagement.ReadWrite.Directory Policy.Read.All
Policy.ReadWrite.ConditionalAccess
```

These are the connector's requested scopes, not a least-privilege recommendation
for every individual action. Review them with your tenant administrator before
granting consent. The `offline_access` scope enables refresh-token use.

1. Leave **Admin Access Required** unchecked and save the asset.
1. Enable the asset's incoming webhooks and allow callbacks without SOAR
   authentication. Microsoft cannot supply a SOAR session cookie. The connector
   checks the pending OAuth state before accepting a callback.
1. Start **TEST CONNECTIVITY**. Its log displays **Using OAuth URL:** followed by
   the callback URL. Register that exact URL as a **Web** redirect URI under the
   Entra application's **Authentication** settings. If necessary, let this first
   attempt time out, then restart it after saving the redirect URI.
1. Open the separate authorization/start link displayed by the test in a browser
   that can reach both Microsoft sign-in and the SOAR webhook service. Sign in
   with the intended account and complete the consent prompt.
1. Return to SOAR and wait for **Test Connectivity Passed**. The connector verifies
   the token by querying users; the consent page alone does not prove connectivity.

The SDK callback has the form below. The app directory, asset ID and port must
come from the actual test log; do not copy the placeholders:

```text
https://<soar-host>:<webhook-port>/webhook/<app-directory>/<asset-id>/oauth_callback
```

SDK 7.0.3 uses the SOAR system base URL and the platform-configured webhook port
(default 3500). Ensure the browser can reach that endpoint with a trusted TLS
certificate. Register `oauth_callback`, not the `oauth_start` link and not the
legacy `/rest/handler/.../result` URL. Do not append `/result` to a displayed URL.
Changing the host, webhook port or asset requires checking the redirect registration.

### Application authentication (client credentials)

Application actions use the app's identity, not a signed-in user's delegated
token. Configure Microsoft Graph **Application permissions**, grant administrator
consent, then check both **Admin Access Required** and **Admin Consent Already
Provided**. **TEST CONNECTIVITY** obtains an app token and queries users without
interactive sign-in. This pre-consented path does not need an OAuth callback.

Alternatively, leave **Admin Consent Already Provided** unchecked to request
administrator consent through **TEST CONNECTIVITY**. That initial consent flow
does require the reachable webhook, exact Web redirect URI and browser steps
described above. After successful consent, check **Admin Consent Already
Provided** and save the asset for subsequent non-interactive connectivity tests.
Changing application permissions requires fresh administrator consent.

### Permissions and privileged actions

Grant only permissions needed for your operations. **TEST CONNECTIVITY** lists
users, so the configured identity must be allowed to read users. Additional
actions can require directory, group, session-revocation or Conditional Access
permissions, and Microsoft Entra roles in addition to Graph permissions.
The generic **make request** action does not bypass these requirements.

Use Microsoft's current [Graph permissions reference](https://learn.microsoft.com/en-us/graph/permissions-reference)
and each API's permission table rather than assigning a blanket administrator role.
An access token or successful connectivity test does not authorize every action.

### Password resets

**reset password** updates the user's `passwordProfile`. The least-privileged
Graph permission for that property is `User-PasswordProfile.ReadWrite.All`.
Microsoft also imposes role requirements: delegated resets of non-administrators
require an appropriate administrator such as User Administrator; resetting
administrators requires higher privileges. App-only resets also require a
supported Entra role for the application. Consult the current
[Update user requirements](https://learn.microsoft.com/en-us/graph/api/user-update?view=graph-rest-1.0#request-body)
for the target user's role and tenant.

Microsoft enforces the effective password policy. This connector does not invent
additional complexity rules, and it excludes the temporary password from its
returned action parameters. Password-profile updates cannot be used for federated
users; manage those passwords through the federation provider. Use an approved
test account when validating resets and set **force_change** as appropriate.

### Troubleshooting and upgrades

- A redirect mismatch means the Entra **Web** redirect URI must match the callback
  logged by the current asset, including scheme, host, port and path.
- A connectivity timeout can indicate an unreachable webhook, disabled incoming
  webhooks, an additional SOAR authentication requirement, or incomplete Microsoft
  sign-in. Check those prerequisites before changing credentials or permissions.
  Pending authorization links expire with the connectivity attempt; start a new
  **TEST CONNECTIVITY** attempt instead of completing an expired link.
- Delegated **generate token** explicitly refreshes an existing session. When a
  usable legacy authorization code is migrated, its successful token exchange
  completes the action without requiring a second refresh. That new token can be
  used even if the exchange did not issue a refresh token; later regeneration
  requires **TEST CONNECTIVITY** if no refresh token is available.
- A Graph authorization error requires checking permission type, consent, the
  selected cloud, the target object and applicable Entra roles. Re-run connectivity
  after replacing an expired client secret.
- Legacy delegated sessions are migrated when usable state is available. If
  migration cannot recover the session, run **TEST CONNECTIVITY** to authorize the
  asset again. Do not manually edit token state or weaken state-file permissions.
- SDK tables may present results differently from legacy templates. Four legacy
  reciprocal undo metadata links are omitted; the corresponding inverse actions
  remain available. Review playbooks that depend on those UI conveniences.

Keep client secrets, access tokens, authorization codes and passwords out of
support reports. Share action IDs and sanitized Microsoft error details instead.

### Corrected output datapaths and playbook migration

The SDK corrects collection and password-profile metadata from the legacy app.
These corrections affect the fields offered by the playbook editor. They do not
convert Graph arrays into strings or rename properties in Microsoft's response.
Review saved datapath selections and custom code before upgrading; existing
playbooks are not rewritten automatically.

In this table, `P` means the full prefix `action_result.data.*.`. Append the
listed suffix to that prefix when reviewing a datapath.

| Actions | Legacy suffix/type | SDK suffix/type | Playbook change |
| --- | --- | --- | --- |
| **list users**, **list user attributes** | `otherMails` / string | `otherMails.*` / string elements | Select the array elements; handle zero, one or multiple email values. |
| **list users**, **list user attributes**, **list groups**, **get group** | `proxyAddresses` / string | `proxyAddresses.*` / string elements | Select the array elements and review formatting, comparisons and iteration. |
| **list users**, **list user attributes** | `passwordProfile` / string | Object container with nested datapaths | Select the required property rather than treating the whole profile as a scalar string. |
| **list users**, **list user attributes** | `passwordProfile.forceChangePasswordNextLogin` / boolean | `passwordProfile.forceChangePasswordNextSignIn` / boolean | Replace the obsolete property selection with the current Graph property. |
| **list users**, **list user attributes** | `passwordProfile.enforceChangePasswordPolicy` / boolean | No direct replacement | Review the playbook's intended policy check. Do not automatically map this to a different password-profile flag. |
| **list users**, **list user attributes** | Not previously advertised | `passwordProfile.forceChangePasswordNextSignInWithMfa` / boolean | This is an additional selectable property, not a replacement for `enforceChangePasswordPolicy`. |

For example, the full email element datapath is
`action_result.data.*.otherMails.*`, replacing the legacy advertised
`action_result.data.*.otherMails`. The full corrected sign-in flag is
`action_result.data.*.passwordProfile.forceChangePasswordNextSignIn`.
`action_result.data.*.passwordProfile.password` is unchanged in metadata; a
published datapath does not guarantee that Graph returns the property for a
particular request. Preserve missing-value handling and validate affected
playbook conditions with the output of an authorized read action.

### SDK action behavior changes

The SDK port includes the following output and validation changes. Review
playbook conditions that depend on empty action data, unusual responses,
summary selections or message text when upgrading from the legacy app.

#### Token-revocation response data

**disable tokens** (action identifier `invalidate_tokens`) now returns Graph's
JSON response in action data, including `action_result.data.*.value` when Graph
supplies that property. The legacy handler discarded the response body and
returned no action data. This is an enhancement to the available output, not a
change to the existing HTTP/API error handling or `action_result.summary.status`.

For example, a Graph response of `{"value": true}` is now available as an
action-data record. A successful response without a body remains accepted and
does not guarantee that `value` is present. Use the action status for request
success or failure, and inspect `value` when the playbook needs that returned
property. Update conditions that previously treated empty action data as a
requirement for success; absence or presence of a data record alone is not a
success test.

#### List requests, pagination and counts

These changes apply to **list users**, **list groups**, **list group members**,
**list user devices**, **list user attributes** and **list named locations**:

- Pagination still uses the continuation's `$skiptoken`. A nonempty continuation
  that has an invalid type or lacks a usable skip token fails the action. The
  legacy helper could stop pagination and return success with earlier pages
  when it could not extract that token. Do not treat that former partial-success
  behavior as proof that all records were retrieved.
- Collection responses must contain a `value` array of objects. Invalid
  collection shapes fail rather than being returned as an apparent result.
  **list user attributes** also accepts an unwrapped object response, including
  the single-user response.
- A normal `{"value": []}` response returns no records. Count summaries, where
  provided, are zero, as in the legacy app.
- The SDK does not add the legacy synthetic `"Empty response"` record when a
  page begins with an empty object. For `{"value": [{}]}`, the empty object
  remains one returned record. Counts use returned objects, without an extra
  sentinel. In particular, **list group members** reports `num_users=1` for
  this case; the legacy handler counted both the object and the sentinel.

For **list users**, **list groups**, **get group**, **list group members**,
**list user attributes** and **list user devices**, a `select_string` containing
only whitespace and commas is treated as unspecified. The legacy handlers
could send `$select=""`; the SDK omits `$select` after discarding empty field
names. Nonempty selections still trim whitespace and discard empty names.
**list named locations** already omitted empty selections in the legacy app.

#### Summary fields and messages

The following populated legacy summary datapaths remain the fields to use:

| Actions | Summary datapath |
| --- | --- |
| **list users**, **list group members** | `action_result.summary.num_users` |
| **list groups** | `action_result.summary.num_groups` |
| **list named locations** | `action_result.summary.num_named_locations` |
| **get group**, **list user attributes**, **list user devices**, **disable tokens** | `action_result.summary.status` |

The old manifest advertised `action_result.summary.display_name` for **get
group** and `action_result.summary.num_members` for **list group members**,
but those legacy handlers did not populate these fields. They are no longer
advertised by the SDK action schemas. For the group name, select
`action_result.data.*.displayName`; for the member count, select
`action_result.summary.num_users`.

**list users** still advertises the optional `result_found` and `total_results`
summary fields, but its handler populates `num_users`, as the legacy handler
did. Do not assume the optional fields are present.

The SDK supplies explicit human-readable messages such as `Num users: N` and
`Num groups: N`. Use the summary datapaths for numeric comparisons rather than
parsing message text. Review conditions that match exact legacy messages.
