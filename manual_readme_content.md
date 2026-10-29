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
| **Delegated OAuth scopes (space-separated; blank uses existing defaults)** | Optional delegated permission list. Replaces the default list; ignored for application authentication. |
| **Microsoft AD Region** | Cloud containing the application and users; defaults to Global. |
| **Admin Access Required** | Leave unchecked for delegated authentication; check for application authentication. |
| **Admin Consent Already Provided** | For application authentication, check only after an administrator has granted the required application permissions. It does not grant consent itself. |

SOAR must reach the selected cloud's Microsoft identity and Graph endpoints over
HTTPS. National-cloud applications and permissions must belong to that cloud.
The Germany option is retained for legacy compatibility with a retired service;
its presence is not a claim of current service availability.

### Delegated authentication

Delegated actions run with both the application's granted permissions and the
signed-in user's privileges. Leave **Delegated OAuth scopes** blank to retain
the existing scope request and preserve authorized sessions after upgrade:

```text
offline_access Group.ReadWrite.All User.Read.All User.ReadWrite.All
Directory.ReadWrite.All Directory.AccessAsUser.All User.ManageIdentities.All
GroupMember.ReadWrite.All RoleManagement.ReadWrite.Directory Policy.Read.All
Policy.ReadWrite.ConditionalAccess
```

These are the connector's requested scopes, not a least-privilege recommendation
for every individual action. Review them with your tenant administrator before
granting consent. The `offline_access` scope enables refresh-token use.

To request a smaller permission set, enter space-separated scopes in
**Delegated OAuth scopes**, for example `offline_access User.Read.All` for user
reads or `offline_access Policy.Read.All` for named-location reads. Only the
configured scopes are requested; the connector does not append its defaults or
automatically add permissions after an action fails. Include `offline_access`
if the asset needs refresh tokens; it is not added automatically. Without it,
reauthorization may be necessary after the access token expires.

After changing the effective scope set, save the asset and run **TEST
CONNECTIVITY** to authorize it again. An existing session with a different scope
configuration is not reused. Reordering scopes or changing whitespace does not
change the effective set. Existing assets with this field blank do not require
reauthorization solely because of this upgrade. Configuring scopes does not
revoke previously granted consent in Entra; manage consent separately there.
Do not change scope configuration during a pending login: restart connectivity
instead. A start link or callback with changed scopes is rejected.

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
1. Return to SOAR and wait for **Test Connectivity Passed**. With default scopes,
   the connector queries users. With explicit scopes, it completes the token
   exchange without requiring unrelated user-list permissions. This verifies
   authentication with the identity service, not Graph access or authorization
   for every action; run the intended read action to verify that access.

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
users for default delegated configuration and application authentication, so
those paths require user-read access. Explicit delegated scopes do not require
that connectivity query. Additional
actions can require directory, group, session-revocation or Conditional Access
permissions, and Microsoft Entra roles in addition to Graph permissions.
The generic **make request** action does not bypass these requirements.

Use Microsoft's current [Graph permissions reference](https://learn.microsoft.com/en-us/graph/permissions-reference)
and each API's permission table rather than assigning a blanket administrator role.
An access token or successful connectivity test does not authorize every action.

### Delegated permissions by action

The table maps connector operations to Microsoft Graph delegated permissions
for work or school accounts. It is not a runtime permission allowlist. Choose
permissions for the actual properties, target users and group types you use;
the linked Microsoft API documentation lists alternatives and special cases.
Reading additional properties or expanded relationships can require additional
permissions. Consent and the signed-in user's Entra privileges still apply.

| Action | Delegated permissions and conditions |
| --- | --- |
| **list users** | `User.ReadBasic.All` for basic profiles; `User.Read.All` for broader user properties. See [List users](https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0). |
| **list user attributes** | `User.Read` for the signed-in user's own profile; `User.ReadBasic.All` for other users' basic profiles or `User.Read.All` for broader reads. Without a user ID it lists users. Property-specific permissions may be needed. See [Get user](https://learn.microsoft.com/en-us/graph/api/user-get?view=graph-rest-1.0). |
| **list user devices** | `User.Read` for the signed-in user's owned devices; `User.Read.All` for other users. Device properties may be limited without permission to read those objects. See [List ownedDevices](https://learn.microsoft.com/en-us/graph/api/user-list-owneddevices?view=graph-rest-1.0). |
| **list groups**, **get group** | `GroupMember.Read.All` for basic group properties; `Group.Read.All` for broader reads. See [List groups](https://learn.microsoft.com/en-us/graph/api/group-list?view=graph-rest-1.0) and [Get group](https://learn.microsoft.com/en-us/graph/api/group-get?view=graph-rest-1.0). |
| **list group members** | `GroupMember.Read.All` for membership; add permissions for member properties as needed. Hidden membership requires `Member.Read.Hidden` and an appropriate role. See [List members](https://learn.microsoft.com/en-us/graph/api/group-list-members?view=graph-rest-1.0). |
| **validate group** | Queries the user's direct memberships: `User.Read` for the signed-in user, `User.Read.All` for another user. See [List memberOf](https://learn.microsoft.com/en-us/graph/api/user-list-memberof?view=graph-rest-1.0). |
| **add user**, **remove user** | `GroupMember.ReadWrite.All` for user membership changes, plus a supported role or group ownership. Role-assignable groups additionally require `RoleManagement.ReadWrite.Directory` and a supported role such as Privileged Role Administrator. See [Add members](https://learn.microsoft.com/en-us/graph/api/group-post-members?view=graph-rest-1.0) and [Remove member](https://learn.microsoft.com/en-us/graph/api/group-delete-members?view=graph-rest-1.0). These actions change membership, not user existence. |
| **enable user** | `User.EnableDisableAccount.All` and `User.Read.All`; the signed-in user needs a role permitted to manage the target. See [Update user](https://learn.microsoft.com/en-us/graph/api/user-update?view=graph-rest-1.0). |
| **disable user** | Permissions for **enable user**, plus `User.RevokeSessions.All`: this action disables the account and then revokes sessions. A failure in session revocation can occur after the account was disabled. |
| **invalidate tokens** | `User.RevokeSessions.All`; target-user privilege restrictions still apply. See [revokeSignInSessions](https://learn.microsoft.com/en-us/graph/api/user-revokesigninsessions?view=graph-rest-1.0). |
| **reset password** | `User-PasswordProfile.ReadWrite.All`, plus a supported administrator role for the target user; see **Password resets** below. |
| **set user attribute** | Depends on the property. `User.ReadWrite.All` is a general update permission, but properties can require specific permissions, such as `User.ManageIdentities.All` for identities or `User-PasswordProfile.ReadWrite.All` for passwordProfile. Use the property-specific requirements in [Update user](https://learn.microsoft.com/en-us/graph/api/user-update?view=graph-rest-1.0), including applicable roles. |
| **list directory roles** | `RoleManagement.Read.Directory` and a supported signed-in user role. See [List directoryRoles](https://learn.microsoft.com/en-us/graph/api/directoryrole-list?view=graph-rest-1.0). |
| **list named locations** | `Policy.Read.All` and a supported role such as Security Reader. See [List namedLocations](https://learn.microsoft.com/en-us/graph/api/conditionalaccessroot-list-namedlocations?view=graph-rest-1.0). |
| **add cidr to named location**, **remove cidr from named location** | `Policy.Read.All` and `Policy.ReadWrite.ConditionalAccess`, with Security Administrator or Conditional Access Administrator. Both actions read and update an existing location. See [Update ipNamedLocation](https://learn.microsoft.com/en-us/graph/api/ipnamedlocation-update?view=graph-rest-1.0). |
| **generate token** | No additional Graph permission; uses the stored refresh token. Request `offline_access` during delegated authorization to obtain refresh tokens. |
| **make request** | Depends on the requested endpoint, HTTP method and properties. It uses the asset's existing permissions, not an expanded set. HTTP errors, including Graph permission errors, are returned in `status_code` and `response_body` under the generic action's existing contract. |
| **test connectivity** | Explicit delegated scopes: no user-list permission required. Default delegated scopes: user-list check. It does not test permissions for every action. |

Specific actions report Microsoft's permission errors without requesting broader
access. A `403` can also indicate a missing role or tenant restriction, not just
a missing scope. Do not grant unrelated permissions as an automatic remedy.

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
- Delegated **generate token** explicitly refreshes the stored token. If no refresh
  token is available, run **TEST CONNECTIVITY** to authorize the asset again.
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
