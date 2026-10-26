# MS Graph for Active Directory

Publisher: Splunk <br>
Connector Version: 2.0.0 <br>
Product Vendor: Microsoft <br>
Product Name: MS Graph for Active Directory <br>
Minimum Product Version: 8.6.0

Connects to Microsoft Active Directory using MS Graph REST API services to support various generic and investigative actions

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

### Configuration variables

This table lists the configuration variables required to operate MS Graph for Active Directory. These variables are specified when configuring a MS Graph for Active Directory asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**tenant_id** | required | string | Tenant (Tenant ID or Tenant Name) |
**client_id** | required | string | Application ID |
**client_secret** | required | password | Client Secret |
**region** | optional | string | Microsoft AD Region |
**admin_access_required** | optional | boolean | Admin Access Required |
**admin_access_granted** | optional | boolean | Admin Consent Already Provided |

### Supported Actions

[test connectivity](#action-test-connectivity) - test connectivity <br>
[list users](#action-list-users) - Get a list of users <br>
[reset password](#action-reset-password) - Reset or set a user's password in a Microsoft AD environment <br>
[disable tokens](#action-disable-tokens) - Invalidate all active refresh tokens for a user in a Microsoft AD environment <br>
[enable user](#action-enable-user) - Enable a user <br>
[disable user](#action-disable-user) - Disable a user and revoke sign-in sessions. Already-issued access tokens for non-CAE resources may remain valid until they expire <br>
[list user devices](#action-list-user-devices) - List devices for a specified user <br>
[list user attributes](#action-list-user-attributes) - List attributes for all or a specified user <br>
[set user attribute](#action-set-user-attribute) - Set an attribute for a user <br>
[remove user](#action-remove-user) - Remove a user from a specified group <br>
[add user](#action-add-user) - Add a user to a specified group <br>
[list groups](#action-list-groups) - List groups in the organization <br>
[get group](#action-get-group) - Get information about a group <br>
[list group members](#action-list-group-members) - List the members in a group <br>
[validate group](#action-validate-group) - Returns true if a user is in a group; otherwise, false <br>
[list directory roles](#action-list-directory-roles) - List the directory roles that are activated in the tenant <br>
[list named locations](#action-list-named-locations) - List named locations in Entra Conditional Access <br>
[add cidr to named location](#action-add-cidr-to-named-location) - Add a CIDR range to an IP-based named location in Entra Conditional Access <br>
[remove cidr from named location](#action-remove-cidr-from-named-location) - Remove a CIDR range from an IP-based named location in Entra Conditional Access <br>
[generate token](#action-generate-token) - Generate a token <br>
[make request](#action-make-request) - Call Microsoft Graph with the asset's authentication; return its HTTP status and raw body.

Uses the asset's configured Microsoft cloud. Supply an explicit /v1.0/ or
/beta/ path. Redirects are not followed. HTTP errors are returned as data;
invalid inputs, authentication and transport failures fail the action.
One response is returned; pagination is not followed automatically.

## action: 'test connectivity'

test connectivity

Type: **test** <br>
Read only: **True**

Basic test for app.

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list users'

Get a list of users

Type: **investigate** <br>
Read only: **True**

For more information on using the filter_string, select_string and expand_string parameters, refer to https://docs.microsoft.com/en-us/graph/query-parameters. By default, only a limited set of properties are returned, to return an alternative property set use $select query parameter.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**filter_string** | optional | Filter string to apply to user listing | string | |
**select_string** | optional | Select string to get additional user properties. Separate multiple values with commas | string | |
**expand_string** | optional | Expand string to get a resource or collection referenced by a single relationship | string | |
**use_advanced_query** | optional | Use advanced query capabilities | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.filter_string | string | | |
action_result.parameter.select_string | string | | |
action_result.parameter.expand_string | string | | |
action_result.parameter.use_advanced_query | boolean | | |
action_result.data.\*.accountEnabled | boolean | | True False |
action_result.data.\*.ageGroup | string | | |
action_result.data.\*.assignedLicenses.\*.skuId | string | | 189a915c-fe4f-4ffa-bde4-85b9628d07a0 |
action_result.data.\*.assignedPlans.\*.assignedTimestamp | string | | 2017-08-29T02:31:40Z |
action_result.data.\*.assignedPlans.\*.capabilityStatus | string | | Enabled |
action_result.data.\*.assignedPlans.\*.service | string | | OfficeForms |
action_result.data.\*.assignedPlans.\*.servicePlanId | string | | e212cbc7-0961-4c40-9825-01117710dcb1 |
action_result.data.\*.city | string | | Palo Alto |
action_result.data.\*.companyName | string | | |
action_result.data.\*.consentProvidedForMinor | string | | |
action_result.data.\*.country | string | | US |
action_result.data.\*.createdDateTime | string | | 2019-05-21T22:27:20Z |
action_result.data.\*.creationType | string | | |
action_result.data.\*.deletionTimestamp | string | | |
action_result.data.\*.department | string | | Sales |
action_result.data.\*.dirSyncEnabled | string | | |
action_result.data.\*.displayName | string | | User |
action_result.data.\*.employeeId | string | | |
action_result.data.\*.facsimileTelephoneNumber | string | | |
action_result.data.\*.givenName | string | | testuser |
action_result.data.\*.id | string | `user id` | e4c722ac-3b83-478d-8f52-c388885dc30f |
action_result.data.\*.immutableId | string | | |
action_result.data.\*.isCompromised | string | | |
action_result.data.\*.jobTitle | string | | Sales Manager |
action_result.data.\*.lastDirSyncTime | string | | |
action_result.data.\*.legalAgeGroupClassification | string | | |
action_result.data.\*.mail | string | `email` | user@test.com |
action_result.data.\*.mailNickname | string | | testmail |
action_result.data.\*.mobile | string | | +1 5556378688 |
action_result.data.\*.mobilePhone | string | | |
action_result.data.\*.objectType | string | | User |
action_result.data.\*.odata.type | string | | test.DirectoryServices.User |
action_result.data.\*.officeLocation | string | | |
action_result.data.\*.onPremisesDistinguishedName | string | | |
action_result.data.\*.onPremisesSecurityIdentifier | string | | |
action_result.data.\*.otherMails | string | `email` | user.test@outlook.com |
action_result.data.\*.passwordPolicies | string | | None |
action_result.data.\*.passwordProfile | string | | |
action_result.data.\*.passwordProfile.enforceChangePasswordPolicy | boolean | | True False |
action_result.data.\*.passwordProfile.forceChangePasswordNextLogin | boolean | | True False |
action_result.data.\*.passwordProfile.password | string | | |
action_result.data.\*.physicalDeliveryOfficeName | string | | |
action_result.data.\*.postalCode | string | | 94303 |
action_result.data.\*.preferredLanguage | string | | en-US |
action_result.data.\*.provisionedPlans.\*.capabilityStatus | string | | Enabled |
action_result.data.\*.provisionedPlans.\*.provisioningStatus | string | | Success |
action_result.data.\*.provisionedPlans.\*.service | string | | exchange |
action_result.data.\*.proxyAddresses | string | | SMTP:user1@test.com |
action_result.data.\*.refreshTokensValidFromDateTime | string | | 2017-09-27T22:54:59Z |
action_result.data.\*.showInAddressList | string | | |
action_result.data.\*.sipProxyAddress | string | `email` | user@test.com |
action_result.data.\*.state | string | | CA |
action_result.data.\*.streetAddress | string | | 2479 E. Bayshore Rd. |
action_result.data.\*.surname | string | | Test_surname |
action_result.data.\*.telephoneNumber | string | | |
action_result.data.\*.thumbnailPhoto@odata.mediaEditLink | string | | directoryObjects/6132ca31-7a09-434f-a269-abe836d0c01e/test.DirectoryServices.User/thumbnailPhoto |
action_result.data.\*.usageLocation | string | | US |
action_result.data.\*.userPrincipalName | string | `user id` | user@test.com |
action_result.data.\*.userState | string | | |
action_result.data.\*.userStateChangedOn | string | | |
action_result.data.\*.userType | string | | Member |
action_result.summary.num_users | numeric | | 8 |
action_result.summary.result_found | boolean | | True False |
action_result.summary.total_results | numeric | | 7 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'reset password'

Reset or set a user's password in a Microsoft AD environment

Type: **contain** <br>
Read only: **False**

Password reset updates the user's passwordProfile property. The required temp_password input parameter is not included in action output. This property cannot be used for federated users; manage those passwords through the federation provider. For more information, refer to https://learn.microsoft.com/en-us/graph/api/user-update?view=graph-rest-1.0#request-body.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user_id** | required | User ID to change password - can be user principal name or object ID | string | `user id` |
**force_change** | optional | Force user to change password on next login | boolean | |
**temp_password** | required | Temporary password for user | password | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.user_id | string | `user id` | |
action_result.parameter.force_change | boolean | | |
action_result.parameter.temp_password | string | | |
action_result.summary.status | string | | Successfully reset password for user@test.com |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'disable tokens'

Invalidate all active refresh tokens for a user in a Microsoft AD environment

Type: **contain** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user_id** | required | User ID to disable tokens of - can be user principal name or object ID | string | `user id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.user_id | string | `user id` | |
action_result.data.\*.@odata.context | string | | https://graph.test.com/v1.0/$metadata#Edm.Boolean |
action_result.data.\*.odata.metadata | string | `url` | https://graph.windows.net/1t309est-db6c-4tes-t1d2-12bf3456d78d/$metadata#Edm.Null |
action_result.data.\*.odata.null | boolean | | True False |
action_result.data.\*.value | boolean | | True False |
action_result.summary.status | string | | Successfully disabled tokens |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'enable user'

Enable a user

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user_id** | required | User ID to enable - can be user principal name or object ID | string | `user id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.user_id | string | `user id` | |
action_result.summary.status | string | | Successfully enabled user user@test.com |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'disable user'

Disable a user and revoke sign-in sessions. Already-issued access tokens for non-CAE resources may remain valid until they expire

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user_id** | required | User ID to disable - can be user principal name or object ID | string | `user id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.user_id | string | `user id` | |
action_result.summary.status | string | | Successfully disabled user user@test.com and revoked sign-in sessions. Already-issued access tokens for non-CAE resources may remain valid until they expire. |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list user devices'

List devices for a specified user

Type: **investigate** <br>
Read only: **True**

By default, only a limited set of properties are returned, to return an alternative property set use $select query parameter. For more information on using the select_string parameter, refer to <a href='https://docs.microsoft.com/en-us/graph/query-parameters#select-parameter' target='_blank'>this</a> documentation.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user_id** | required | User ID - can be user principal name or object ID | string | `user id` |
**select_string** | optional | Select string to get additional user properties. Separate multiple values with commas | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.user_id | string | `user id` | |
action_result.parameter.select_string | string | | |
action_result.data.\*.odata.type | string | | #test.graph.device |
action_result.data.\*.accountEnabled | boolean | | True False |
action_result.data.\*.alternativeSecurityIds.\*.identityProvider | string | | |
action_result.data.\*.alternativeSecurityIds.\*.key | string | | WAA1ADAAOQA6ADwAUwBIAEEAMQAtAFQAUAAtAFAAVQBCAEsARQBZAD4AOQA5AEEARQAwADgAOABDAEUANAA1ADgAMABCADcAQgBGAEEARQA2ADEAQQBCADYANAA3ADYANgA5ADUAOAAzAEQANABFAEYARQA5ADYAOAAyAHkAcQBSAEIANwBrAGEAMQA4AEoATAByACsAegB4AE8AYwB6AE8AYgBNAFEANQBZAEgAbgB0AFQAdgBOAG0AbgA5AEQAZQA2AFgAVQBUAGgAcwBFAD0A |
action_result.data.\*.alternativeSecurityIds.\*.type | numeric | | 2 |
action_result.data.\*.approximateLastSignInDateTime | string | | 2019-09-26T03:42:15Z |
action_result.data.\*.complianceExpirationDateTime | string | | |
action_result.data.\*.createdDateTime | string | | 2019-09-26T03:42:15Z |
action_result.data.\*.deletedDateTime | string | | |
action_result.data.\*.deviceCategory | string | | |
action_result.data.\*.deviceId | string | | |
action_result.data.\*.deviceMetadata | string | | |
action_result.data.\*.deviceOwnership | string | | |
action_result.data.\*.deviceVersion | numeric | | |
action_result.data.\*.displayName | string | | |
action_result.data.\*.domainName | string | | |
action_result.data.\*.enrollmentProfileName | string | | |
action_result.data.\*.enrollmentType | string | | |
action_result.data.\*.extensionAttributes.extensionAttribute1 | string | | |
action_result.data.\*.extensionAttributes.extensionAttribute10 | string | | |
action_result.data.\*.extensionAttributes.extensionAttribute11 | string | | |
action_result.data.\*.extensionAttributes.extensionAttribute12 | string | | |
action_result.data.\*.extensionAttributes.extensionAttribute13 | string | | |
action_result.data.\*.extensionAttributes.extensionAttribute14 | string | | |
action_result.data.\*.extensionAttributes.extensionAttribute15 | string | | |
action_result.data.\*.extensionAttributes.extensionAttribute2 | string | | |
action_result.data.\*.extensionAttributes.extensionAttribute3 | string | | |
action_result.data.\*.extensionAttributes.extensionAttribute4 | string | | |
action_result.data.\*.extensionAttributes.extensionAttribute5 | string | | |
action_result.data.\*.extensionAttributes.extensionAttribute6 | string | | |
action_result.data.\*.extensionAttributes.extensionAttribute7 | string | | |
action_result.data.\*.extensionAttributes.extensionAttribute8 | string | | |
action_result.data.\*.extensionAttributes.extensionAttribute9 | string | | |
action_result.data.\*.externalSourceName | string | | |
action_result.data.\*.id | string | | |
action_result.data.\*.isCompliant | boolean | | True False |
action_result.data.\*.isManaged | boolean | | True False |
action_result.data.\*.isRooted | string | | |
action_result.data.\*.managementType | string | | |
action_result.data.\*.manufacturer | string | | |
action_result.data.\*.mdmAppId | string | | |
action_result.data.\*.model | string | | |
action_result.data.\*.onPremisesLastSyncDateTime | string | | |
action_result.data.\*.onPremisesSyncEnabled | boolean | | True False |
action_result.data.\*.operatingSystem | string | | Windows |
action_result.data.\*.operatingSystemVersion | string | | 10.0.18362.0 |
action_result.data.\*.profileType | string | | RegisteredDevice |
action_result.data.\*.registrationDateTime | string | | 2019-09-26T03:42:15Z |
action_result.data.\*.sourceType | string | | |
action_result.data.\*.trustType | string | | Workplace |
action_result.summary.status | string | | Successfully retrieved owned devices for user user@test.com |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list user attributes'

List attributes for all or a specified user

Type: **investigate** <br>
Read only: **True**

By default, only a limited set of properties are returned, to return an alternative property set use $select query parameter. For more information on using the select_string and expand_string parameters, refer to https://docs.microsoft.com/en-us/graph/query-parameters.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user_id** | optional | User ID - can be user principal name or object ID | string | `user id` |
**select_string** | optional | Select string to get additional user properties. Separate multiple values with commas | string | |
**expand_string** | optional | Expand string to get a resource or collection referenced by a single relationship | string | |
**use_advanced_query** | optional | Use advanced query capabilities | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.user_id | string | `user id` | |
action_result.parameter.select_string | string | | |
action_result.parameter.expand_string | string | | |
action_result.parameter.use_advanced_query | boolean | | |
action_result.data.\*.odata.metadata | string | | https://graph.windows.net/1t309est-db6c-4tes-t1d2-12bf3456d78d/$metadata#directoryObjects/@Element |
action_result.data.\*.odata.type | string | | test.DirectoryServices.User |
action_result.data.\*.accountEnabled | boolean | | True False |
action_result.data.\*.ageGroup | string | | |
action_result.data.\*.assignedLicenses.\*.skuId | string | | f30db892-07e9-47e9-837c-80727f46fd3d |
action_result.data.\*.assignedPlans.\*.assignedTimestamp | string | | 2019-04-26T07:21:18Z |
action_result.data.\*.assignedPlans.\*.capabilityStatus | string | | Enabled |
action_result.data.\*.assignedPlans.\*.service | string | | exchange |
action_result.data.\*.assignedPlans.\*.servicePlanId | string | | 33c4f319-9bdd-48d6-9c4d-410b750a4a5a |
action_result.data.\*.city | string | | |
action_result.data.\*.companyName | string | | |
action_result.data.\*.consentProvidedForMinor | string | | |
action_result.data.\*.country | string | | |
action_result.data.\*.createdDateTime | string | | 2019-05-02T20:27:59Z |
action_result.data.\*.creationType | string | | |
action_result.data.\*.deletionTimestamp | string | | |
action_result.data.\*.department | string | | Sales |
action_result.data.\*.dirSyncEnabled | string | | |
action_result.data.\*.displayName | string | | Test User |
action_result.data.\*.employeeId | string | | |
action_result.data.\*.facsimileTelephoneNumber | string | | |
action_result.data.\*.givenName | string | | |
action_result.data.\*.id | string | `user id` | 7d55d7e6-cf5a-4dd2-a176-57a3c33b7fa9 |
action_result.data.\*.identities.\*.issuer | string | | test.com |
action_result.data.\*.identities.\*.issuerAssignedId | string | | test2@user.test.com |
action_result.data.\*.identities.\*.signInType | string | | userPrincipalName |
action_result.data.\*.immutableId | string | | |
action_result.data.\*.isCompromised | string | | |
action_result.data.\*.jobTitle | string | | |
action_result.data.\*.lastDirSyncTime | string | | |
action_result.data.\*.legalAgeGroupClassification | string | | |
action_result.data.\*.mail | string | `email` | |
action_result.data.\*.mailNickname | string | | test |
action_result.data.\*.mobile | string | | |
action_result.data.\*.mobilePhone | string | | |
action_result.data.\*.objectId | string | | 59f51194-1998-4932-a8ac-468e59374edc |
action_result.data.\*.objectType | string | | User |
action_result.data.\*.officeLocation | string | | |
action_result.data.\*.onPremisesDistinguishedName | string | | |
action_result.data.\*.onPremisesSecurityIdentifier | string | | |
action_result.data.\*.otherMails | string | `email` | user@test.com |
action_result.data.\*.passwordPolicies | string | | |
action_result.data.\*.passwordProfile.enforceChangePasswordPolicy | boolean | | True False |
action_result.data.\*.passwordProfile.forceChangePasswordNextLogin | boolean | | True False |
action_result.data.\*.passwordProfile.password | string | | |
action_result.data.\*.physicalDeliveryOfficeName | string | | |
action_result.data.\*.postalCode | string | | |
action_result.data.\*.preferredLanguage | string | | |
action_result.data.\*.provisionedPlans.\*.capabilityStatus | string | | Enabled |
action_result.data.\*.provisionedPlans.\*.provisioningStatus | string | | Success |
action_result.data.\*.provisionedPlans.\*.service | string | | exchange |
action_result.data.\*.proxyAddresses | string | | SMTP:test_shared_mailbox@test.com |
action_result.data.\*.refreshTokensValidFromDateTime | string | | 2019-05-16T19:54:18Z |
action_result.data.\*.showInAddressList | string | | |
action_result.data.\*.sipProxyAddress | string | `email` | |
action_result.data.\*.state | string | | |
action_result.data.\*.streetAddress | string | | |
action_result.data.\*.surname | string | | |
action_result.data.\*.telephoneNumber | string | | |
action_result.data.\*.thumbnailPhoto@odata.mediaEditLink | string | | directoryObjects/59f12345-1998-4932-a8ac-468e59374edc/test.DirectoryServices.User/thumbnailPhoto |
action_result.data.\*.usageLocation | string | | US |
action_result.data.\*.userPrincipalName | string | `user id` | user@test.com |
action_result.data.\*.userState | string | | |
action_result.data.\*.userStateChangedOn | string | | |
action_result.data.\*.userType | string | | Member |
action_result.summary.status | string | | Successfully retrieved attributes for user user@test.com Successfully retrieved user attributes |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'set user attribute'

Set an attribute for a user

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user_id** | required | User ID - can be user principal name or object ID | string | `user id` |
**attribute** | required | Attribute to set | string | |
**attribute_value** | required | Value of attribute to set | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.user_id | string | `user id` | |
action_result.parameter.attribute | string | | |
action_result.parameter.attribute_value | string | | |
action_result.summary.status | string | | Successfully updated user attribute |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'remove user'

Remove a user from a specified group

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**group_object_id** | required | Object ID of group | string | `group object id` |
**user_id** | required | User ID to remove from group | string | `user id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.group_object_id | string | `group object id` | |
action_result.parameter.user_id | string | `user id` | |
action_result.summary.status | string | | Successfully removed user from group User not in group |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'add user'

Add a user to a specified group

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**group_object_id** | required | Object ID of group | string | `group object id` |
**user_id** | required | User ID to add to group | string | `user id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.group_object_id | string | `group object id` | |
action_result.parameter.user_id | string | `user id` | |
action_result.summary.status | string | | Successfully added user to group User already in group |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list groups'

List groups in the organization

Type: **investigate** <br>
Read only: **True**

By default, only a limited set of properties are returned, to return an alternative property set use $select query parameter. For more information on using the select_string and expand_string parameters, refer to https://docs.microsoft.com/en-us/graph/query-parameters.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**filter_string** | optional | Filter string to apply to group listing | string | |
**select_string** | optional | Select string to get additional group properties. Separate multiple values with commas | string | |
**expand_string** | optional | Expand string to get a resource or collection referenced by a single relationship | string | |
**use_advanced_query** | optional | Use advanced query capabilities | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.filter_string | string | | |
action_result.parameter.select_string | string | | |
action_result.parameter.expand_string | string | | |
action_result.parameter.use_advanced_query | boolean | | |
action_result.data.\*.classification | string | | |
action_result.data.\*.createdDateTime | string | | 2021-03-25T18:40:53Z |
action_result.data.\*.deletedDateTime | string | | |
action_result.data.\*.deletionTimestamp | string | | |
action_result.data.\*.displayName | string | | Test-site |
action_result.data.\*.description | string | | This is for testing purpose |
action_result.data.\*.dirSyncEnabled | string | | |
action_result.data.\*.expirationDateTime | string | | |
action_result.data.\*.id | string | `group object id` | 2a201c95-101b-42d9-a7af-9a2fdf8193f1 |
action_result.data.\*.isAssignableToRole | string | | |
action_result.data.\*.lastDirSyncTime | string | | |
action_result.data.\*.mail | string | `email` | Test-site@test.com |
action_result.data.\*.mailEnabled | boolean | | True False |
action_result.data.\*.mailNickname | string | | Test-site |
action_result.data.\*.membershipRule | string | | |
action_result.data.\*.membershipRuleProcessingState | string | | |
action_result.data.\*.objectType | string | | Group |
action_result.data.\*.odata.type | string | | test.DirectoryServices.Group |
action_result.data.\*.onPremisesDomainName | string | `domain` | |
action_result.data.\*.onPremisesLastSyncDateTime | string | | |
action_result.data.\*.onPremisesNetBiosName | string | | |
action_result.data.\*.onPremisesSamAccountName | string | | |
action_result.data.\*.onPremisesSecurityIdentifier | string | | |
action_result.data.\*.onPremisesSyncEnabled | string | | |
action_result.data.\*.preferredDataLocation | string | | |
action_result.data.\*.preferredLanguage | string | | |
action_result.data.\*.proxyAddresses | string | | SMTP:test-h@test.com |
action_result.data.\*.renewedDateTime | string | | 2021-03-25T18:40:53Z |
action_result.data.\*.securityEnabled | boolean | | True False |
action_result.data.\*.securityIdentifier | string | | S-1-12-1-294681889-1319597617-672379543-28952017 |
action_result.data.\*.theme | string | | |
action_result.data.\*.visibility | string | | Private |
action_result.summary.num_groups | numeric | | 7 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get group'

Get information about a group

Type: **investigate** <br>
Read only: **True**

By default, only a limited set of properties are returned, to return an alternative property set use $select query parameter. For more information on using the select_string and expand_string parameters, refer to https://docs.microsoft.com/en-us/graph/query-parameters.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**object_id** | required | Object ID of group | string | `group object id` |
**select_string** | optional | Select string to get additional group properties. Separate multiple values with commas | string | |
**expand_string** | optional | Expand string to get a resource or collection referenced by a single relationship | string | |
**use_advanced_query** | optional | Use advanced query capabilities | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.object_id | string | `group object id` | |
action_result.parameter.select_string | string | | |
action_result.parameter.expand_string | string | | |
action_result.parameter.use_advanced_query | boolean | | |
action_result.data.\*.odata.metadata | string | | https://graph.windows.net/1t309est-db6c-4tes-t1d2-12bf3456d78d/$metadata#directoryObjects/@Element |
action_result.data.\*.odata.type | string | | test.DirectoryServices.Group |
action_result.data.\*.classification | string | | |
action_result.data.\*.createdDateTime | string | | 2020-08-05T11:59:49Z |
action_result.data.\*.deletedDateTime | string | | |
action_result.data.\*.deletionTimestamp | string | | |
action_result.data.\*.description | string | | This is the office 365 group |
action_result.data.\*.dirSyncEnabled | string | | |
action_result.data.\*.displayName | string | | o365group |
action_result.data.\*.expirationDateTime | string | | |
action_result.data.\*.id | string | `group object id` | ddb876b3-603a-437b-9814-2d46a2219a1e |
action_result.data.\*.isAssignableToRole | string | | |
action_result.data.\*.lastDirSyncTime | string | | |
action_result.data.\*.mail | string | `email` | bc7f9cabe@test.com |
action_result.data.\*.securityEnabled | boolean | | True False |
action_result.data.\*.mailEnabled | boolean | | True False |
action_result.data.\*.mailNickname | string | | bc7f9cabe |
action_result.data.\*.membershipRule | string | | |
action_result.data.\*.membershipRuleProcessingState | string | | |
action_result.data.\*.objectType | string | | Group |
action_result.data.\*.onPremisesDomainName | string | `domain` | |
action_result.data.\*.onPremisesLastSyncDateTime | string | | |
action_result.data.\*.onPremisesNetBiosName | string | | |
action_result.data.\*.onPremisesSamAccountName | string | | |
action_result.data.\*.onPremisesSecurityIdentifier | string | | |
action_result.data.\*.onPremisesSyncEnabled | string | | |
action_result.data.\*.preferredDataLocation | string | | |
action_result.data.\*.preferredLanguage | string | | |
action_result.data.\*.proxyAddresses | string | | SMTP:bc7f9cabe@test.com |
action_result.data.\*.renewedDateTime | string | | 2020-08-05T11:59:49Z |
action_result.data.\*.securityIdentifier | string | | S-1-12-1-909260723-1083662375-1952945031-2402852259 |
action_result.data.\*.theme | string | | |
action_result.data.\*.visibility | string | | |
action_result.summary.status | string | | Successfully retrieved group group-id |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list group members'

List the members in a group

Type: **investigate** <br>
Read only: **True**

By default, only a limited set of properties are returned, to return an alternative property set use $select query parameter. For more information on using the select_string and expand_string parameters, refer to https://docs.microsoft.com/en-us/graph/query-parameters.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**group_object_id** | required | Object ID of group | string | `group object id` |
**select_string** | optional | Select string to get additional properties. Separate multiple values with commas | string | |
**expand_string** | optional | Expand string to get a resource or collection referenced by a single relationship | string | |
**use_advanced_query** | optional | Use advanced query capabilities | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.group_object_id | string | `group object id` | |
action_result.parameter.select_string | string | | |
action_result.parameter.expand_string | string | | |
action_result.parameter.use_advanced_query | boolean | | |
action_result.data.\*.odata.type | string | | #test.graph.user |
action_result.data.\*.accountEnabled | boolean | | True False |
action_result.data.\*.ageGroup | string | | |
action_result.data.\*.assignedLicenses.\*.skuId | string | | 189a915c-fe4f-4ffa-bde4-85b9628d07a0 |
action_result.data.\*.assignedPlans.\*.assignedDateTime | string | | 2022-11-03T15:12:28Z |
action_result.data.\*.assignedPlans.\*.capabilityStatus | string | | Deleted |
action_result.data.\*.assignedPlans.\*.service | string | | AADPremiumService |
action_result.data.\*.assignedPlans.\*.servicePlanId | string | | eec0eb4f-6444-4f95-aba0-50c24d67f998 |
action_result.data.\*.city | string | | Palo Alto |
action_result.data.\*.companyName | string | | |
action_result.data.\*.consentProvidedForMinor | string | | |
action_result.data.\*.country | string | | US |
action_result.data.\*.createdDateTime | string | | 2016-06-09T18:33:27Z |
action_result.data.\*.creationType | string | | |
action_result.data.\*.deletedDateTime | string | | |
action_result.data.\*.department | string | | |
action_result.data.\*.displayName | string | | Firstname Lastname |
action_result.data.\*.employeeHireDate | string | | |
action_result.data.\*.employeeId | string | | |
action_result.data.\*.employeeOrgData | string | | |
action_result.data.\*.employeeType | string | | |
action_result.data.\*.externalUserState | string | | |
action_result.data.\*.externalUserStateChangeDateTime | string | | |
action_result.data.\*.faxNumber | string | | |
action_result.data.\*.givenName | string | | |
action_result.data.\*.id | string | `user id` | 17be76d0-35ed-4881-ab62-d2eb73c2ebe3 |
action_result.data.\*.identities.\*.issuer | string | | test.com |
action_result.data.\*.identities.\*.issuerAssignedId | string | | test@user.test.com |
action_result.data.\*.identities.\*.signInType | string | | userPrincipalName |
action_result.data.\*.isResourceAccount | string | | |
action_result.data.\*.jobTitle | string | | |
action_result.data.\*.legalAgeGroupClassification | string | | |
action_result.data.\*.mail | string | | |
action_result.data.\*.mailNickname | string | | User |
action_result.data.\*.mobilePhone | string | | |
action_result.data.\*.officeLocation | string | | |
action_result.data.\*.onPremisesDistinguishedName | string | | |
action_result.data.\*.onPremisesDomainName | string | | |
action_result.data.\*.onPremisesExtensionAttributes.extensionAttribute1 | string | | |
action_result.data.\*.onPremisesExtensionAttributes.extensionAttribute10 | string | | |
action_result.data.\*.onPremisesExtensionAttributes.extensionAttribute11 | string | | |
action_result.data.\*.onPremisesExtensionAttributes.extensionAttribute12 | string | | |
action_result.data.\*.onPremisesExtensionAttributes.extensionAttribute13 | string | | |
action_result.data.\*.onPremisesExtensionAttributes.extensionAttribute14 | string | | |
action_result.data.\*.onPremisesExtensionAttributes.extensionAttribute15 | string | | |
action_result.data.\*.onPremisesExtensionAttributes.extensionAttribute2 | string | | |
action_result.data.\*.onPremisesExtensionAttributes.extensionAttribute3 | string | | |
action_result.data.\*.onPremisesExtensionAttributes.extensionAttribute4 | string | | |
action_result.data.\*.onPremisesExtensionAttributes.extensionAttribute5 | string | | |
action_result.data.\*.onPremisesExtensionAttributes.extensionAttribute6 | string | | |
action_result.data.\*.onPremisesExtensionAttributes.extensionAttribute7 | string | | |
action_result.data.\*.onPremisesExtensionAttributes.extensionAttribute8 | string | | |
action_result.data.\*.onPremisesExtensionAttributes.extensionAttribute9 | string | | |
action_result.data.\*.onPremisesImmutableId | string | | |
action_result.data.\*.onPremisesLastSyncDateTime | string | | |
action_result.data.\*.onPremisesSamAccountName | string | | |
action_result.data.\*.onPremisesSecurityIdentifier | string | | |
action_result.data.\*.onPremisesSyncEnabled | string | | |
action_result.data.\*.onPremisesUserPrincipalName | string | | |
action_result.data.\*.passwordPolicies | string | | |
action_result.data.\*.passwordProfile | string | | |
action_result.data.\*.postalCode | string | | 94303 |
action_result.data.\*.preferredDataLocation | string | | |
action_result.data.\*.preferredLanguage | string | | |
action_result.data.\*.provisionedPlans.\*.capabilityStatus | string | | Enabled |
action_result.data.\*.provisionedPlans.\*.provisioningStatus | string | | Success |
action_result.data.\*.provisionedPlans.\*.service | string | | testCommunicationsOnline |
action_result.data.\*.refreshTokensValidFromDateTime | string | | 2022-08-08T13:00:58Z |
action_result.data.\*.showInAddressList | string | | |
action_result.data.\*.signInSessionsValidFromDateTime | string | | 2022-08-08T13:00:58Z |
action_result.data.\*.state | string | | CA |
action_result.data.\*.streetAddress | string | | 2479 E. Bayshore Rd. |
action_result.data.\*.surname | string | | |
action_result.data.\*.usageLocation | string | | US |
action_result.data.\*.userPrincipalName | string | `user id` | ews_retest@test.com |
action_result.data.\*.userType | string | | Member |
action_result.summary.num_users | numeric | | 8 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'validate group'

Returns true if a user is in a group; otherwise, false

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**group_object_id** | required | Object ID of group | string | `group object id` |
**user_id** | required | User ID to validate | string | `user id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.group_object_id | string | `group object id` | |
action_result.parameter.user_id | string | `user id` | |
action_result.data.\*.@odata.context | string | | https://graph.test.com/v1.0/$metadata#directoryObjects |
action_result.data.\*.odata.type | string | | #test.graph.group |
action_result.data.\*.user_in_group | boolean | | True False |
action_result.data.\*.value.\*.@odata.type | string | | |
action_result.data.\*.value.\*.odata.type | string | | #test.graph.group |
action_result.data.\*.value.\*.classification | string | | |
action_result.data.\*.value.\*.createdDateTime | string | | 2022-02-25T12:05:22Z |
action_result.data.\*.value.\*.deletedDateTime | string | | |
action_result.data.\*.value.\*.description | string | | Test group for MSGraph |
action_result.data.\*.value.\*.displayName | string | | Test group for MSGraph |
action_result.data.\*.value.\*.expirationDateTime | string | | |
action_result.data.\*.value.\*.id | string | `user id` | 49233413-24c6-4516-a9e1-4d5f87fe34fd |
action_result.data.\*.value.\*.isAssignableToRole | string | | |
action_result.data.\*.value.\*.mail | string | | test@user.test.com |
action_result.data.\*.value.\*.mailEnabled | boolean | | True False |
action_result.data.\*.value.\*.mailNickname | string | | TestgroupforMSGraph |
action_result.data.\*.value.\*.membershipRule | string | | |
action_result.data.\*.value.\*.membershipRuleProcessingState | string | | |
action_result.data.\*.value.\*.onPremisesDomainName | string | | |
action_result.data.\*.value.\*.onPremisesLastSyncDateTime | string | | |
action_result.data.\*.value.\*.onPremisesNetBiosName | string | | |
action_result.data.\*.value.\*.onPremisesSamAccountName | string | | |
action_result.data.\*.value.\*.onPremisesSecurityIdentifier | string | | |
action_result.data.\*.value.\*.onPremisesSyncEnabled | string | | |
action_result.data.\*.value.\*.preferredDataLocation | string | | |
action_result.data.\*.value.\*.preferredLanguage | string | | |
action_result.data.\*.value.\*.renewedDateTime | string | | 2022-02-25T12:05:22Z |
action_result.data.\*.value.\*.securityEnabled | boolean | | True False |
action_result.data.\*.value.\*.securityIdentifier | string | | S-1-12-1-1227043859-1159079110-1598939561-4248108679 |
action_result.data.\*.value.\*.theme | string | | |
action_result.data.\*.value.\*.visibility | string | | Private |
action_result.summary.user_in_group | boolean | | True False |
action_result.summary.message | string | | User is a member of the group User is not a member of the group |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list directory roles'

List the directory roles that are activated in the tenant

Type: **investigate** <br>
Read only: **True**

<p>Pagination is not implemented for this action as this endpoint does not support pagination. Here is the <b><a href='https://docs.microsoft.com/en-us/graph/paging' target='_blank'>Documentation</a></b> for the same.</p>

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.data.\*.deletedDateTime | string | | |
action_result.data.\*.deletionTimestamp | string | | |
action_result.data.\*.description | string | | Can read basic directory information. For granting access to applications, not intended for users. |
action_result.data.\*.displayName | string | | Directory Readers |
action_result.data.\*.id | string | `directory object id` | 02b238cb-0d15-454b-aae6-0e94993a3207 |
action_result.data.\*.isSystem | boolean | | True False |
action_result.data.\*.objectType | string | | Role |
action_result.data.\*.odata.type | string | | test.DirectoryServices.DirectoryRole |
action_result.data.\*.roleTemplateId | string | `role template id` | 88d8e3e3-8f55-4a1e-953a-9b9898b8876b |
action_result.summary.num_directory_roles | numeric | | 5 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list named locations'

List named locations in Entra Conditional Access

Type: **investigate** <br>
Read only: **True**

For more information on using the filter and select parameters, refer to https://learn.microsoft.com/en-us/graph/filter-query-parameter and https://learn.microsoft.com/en-us/graph/query-parameters#select-parameter.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**location_type** | optional | Type of named locations to return | string | |
**filter** | optional | Optional OData filter, for example contains(displayName,'Blocked') | string | |
**select** | optional | Optional select string to get specific properties. Separate multiple values with commas | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.location_type | string | | |
action_result.parameter.filter | string | | |
action_result.parameter.select | string | | |
action_result.data.\*.@odata.type | string | | |
action_result.data.\*.odata.type | string | | #microsoft.graph.iPv6CidrRange #microsoft.graph.iPv4CidrRange |
action_result.data.\*.id | string | `directory object id` | 0c0c6d27-93e7-4fd7-88a4-952c6d61a697 |
action_result.data.\*.displayName | string | | Named locations to be blocked |
action_result.data.\*.createdDateTime | string | `datetime` | 2021-03-23T04:59:25.8014022Z |
action_result.data.\*.modifiedDateTime | string | `datetime` | 2021-03-23T08:05:02.1027085Z |
action_result.data.\*.isTrusted | boolean | | True False |
action_result.data.\*.ipRanges.\*.@odata.type | string | | |
action_result.data.\*.ipRanges.\*.odata.type | string | | #microsoft.graph.iPv6CidrRange #microsoft.graph.iPv4CidrRange |
action_result.data.\*.ipRanges.\*.cidrAddress | string | `ip` `cidr` | 127.0.0.1/32 2001:8000::/20 |
action_result.data.\*.countriesAndRegions.\* | string | | US CA |
action_result.data.\*.countryLookupMethod | string | | clientIpAddress authenticatorAppGps |
action_result.data.\*.includeUnknownCountriesAndRegions | boolean | | True False |
action_result.summary.num_named_locations | numeric | | 3 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'add cidr to named location'

Add a CIDR range to an IP-based named location in Entra Conditional Access

Type: **contain** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**cidr_range** | required | IPv4 or IPv6 CIDR range, for example 1.1.1.0/24 or 2001:db8::/32 | string | `ip` `cidr` |
**location_id** | required | Object ID of the IP-based named location | string | `directory object id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.cidr_range | string | `ip` `cidr` | |
action_result.parameter.location_id | string | `directory object id` | |
action_result.summary.status | string | | Successfully added 1.1.1.0/24 CIDR already present |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'remove cidr from named location'

Remove a CIDR range from an IP-based named location in Entra Conditional Access

Type: **correct** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**cidr_range** | required | IPv4 or IPv6 CIDR range, for example 1.1.1.0/24 or 2001:db8::/32 | string | `ip` `cidr` |
**location_id** | required | Object ID of the IP-based named location | string | `directory object id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.cidr_range | string | `ip` `cidr` | |
action_result.parameter.location_id | string | `directory object id` | |
action_result.summary.status | string | | Successfully removed 1.1.1.0/24 CIDR not present |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'generate token'

Generate a token

Type: **generic** <br>
Read only: **False**

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'make request'

Call Microsoft Graph with the asset's authentication; return its HTTP status and raw body.

Uses the asset's configured Microsoft cloud. Supply an explicit /v1.0/ or
/beta/ path. Redirects are not followed. HTTP errors are returned as data;
invalid inputs, authentication and transport failures fail the action.
One response is returned; pagination is not followed automatically.

Type: **generic** <br>
Read only: **False**

'make request' action for the app. Used to handle arbitrary HTTP requests with the app's asset

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**http_method** | required | The HTTP method to use for the request. | string | |
**endpoint** | required | Microsoft Graph path beginning with /v1.0/ or /beta/. Do not include the base URL. | string | |
**headers** | optional | The headers to send with the request (JSON object). An example is {'Content-Type': 'application/json'} | string | |
**query_parameters** | optional | Parameters to append to the URL (JSON object or query string). An example is ?key=value&key2=value2 | string | |
**body** | optional | The body to send with the request (JSON object). An example is {'key': 'value', 'key2': 'value2'} | string | |
**timeout** | optional | The timeout for the request in seconds. | numeric | |
**verify_ssl** | optional | Whether to verify the SSL certificate. Default is True. | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.http_method | string | | |
action_result.parameter.endpoint | string | | |
action_result.parameter.headers | string | | |
action_result.parameter.query_parameters | string | | |
action_result.parameter.body | string | | |
action_result.parameter.timeout | numeric | | |
action_result.parameter.verify_ssl | boolean | | |
action_result.data.\*.status_code | numeric | | 200 404 500 |
action_result.data.\*.response_body | string | | {"key": "value"} |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2026 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
