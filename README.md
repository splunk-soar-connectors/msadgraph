[comment]: # "Auto-generated SOAR connector documentation"
# MS Graph for Active Directory

Publisher: Splunk  
Connector Version: 1\.2\.0  
Product Vendor: Microsoft  
Product Name: MS Graph for Active Directory  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.4\.0  

Connects to Microsoft Active Directory using MS Graph REST API services to support various generic and investigative actions

[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2022-2023 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
## Authentication

### Microsoft Azure Application creation

This app requires creating a Microsoft Azure Application. To do so, navigate to
<https://portal.azure.com> in a browser and log in with a Microsoft account, then select **Azure
Active Directory** .

1.  Go to **App Registrations** and click on **+ New registration** .
2.  Give the app an appropriate name.
3.  Select a supported account type (configure the application to be multitenant).
4.  Click on the **Register** .
    -   Under **Certificates & secrets** , add **New client secret** . Note this key somewhere
        secure, as it cannot be retrieved after closing the window.
    -   Under **Redirect URIs** we will be updating the entry of https://phantom.local to reflect
        the actual redirect URI. We will get this from the SOAR asset we create below in the section
        titled "Configure the MS Graph for Active Directory SOAR app Asset"

### Delegated Permissions configuration

Use this procedure to provide non-admin permissions to the app. To do so, navigate to
<https://portal.azure.com> in a browser and log in with a Microsoft account, then navigate to the
previously created app configuration.

1.  Under **API Permissions** , click on **Add a permission** .
2.  Go to **Microsoft Graph Permissions** , the following **Delegated Permissions** need to be
    added:
    -   User.ReadWrite.All
    -   Directory.ReadWrite.All
    -   Directory.AccessAsUser.All
    -   User.ManageIdentities.All
    -   Group.ReadWrite.All
    -   GroupMember.ReadWrite.All
    -   RoleManagement.ReadWrite.Directory
    -   offline_access
3.  Click on the **Add permissions** .
4.  After making these changes, click on **Grant admin consent** .

### Application Permissions configuration

Use this procedure to provide admin permissions to the app. To do so, navigate to
<https://portal.azure.com> in a browser and log in with a Microsoft account, then navigate to the
previously created app configuration.

1.  Under **API Permissions** , click on **Add a permission** .
2.  Go to **Microsoft Graph Permissions** , the following **Application Permissions** need to be
    added:
    -   User.ReadWrite.All
    -   Directory.ReadWrite.All
    -   User.ManageIdentities.All
    -   Group.ReadWrite.All
    -   GroupMember.ReadWrite.All
    -   RoleManagement.ReadWrite.Directory
3.  Click on the **Add permissions** .
4.  After making these changes, click on **Grant admin consent** .

#### Note: **reset password** action is not supported with Application permissions

## Configure the MS Graph for Active Directory SOAR app Asset

When creating an asset for the **MS Graph for Active Directory** app, place the **Application ID**
of the app created during the previous step in the **Client ID** field and place the password
generated during the app creation process in the **Client Secret** field. Then, after filling out
the **Tenant** field, click **SAVE** .

After saving, a new field will appear in the **Asset Settings** tab. Take the URL found in the
**POST incoming for MS Graph to this location** field and place it in the **Redirect URIs** field of
the Azure Application configuration page. To this URL, add **/result** . After doing so the URL
should look something like:

https://\<phantom_host>/rest/handler/msgraphforactivedirectory_f2a239df-acb2-47d6-861c-726a435cfe76/\<asset_name>/result

  
Once again, click on Save.

## Enable Application Permissions

If you have received admin consent to use application permissions, make sure to check the **Admin
Access Required** and **Admin Consent Already Provided** checkboxes on the asset.

## User Permissions

To complete the authorization process, this app needs permission to view assets, which is not
granted by default. First, under **asset settings** , check which user is listed under **Select a
user on behalf of which automated actions can be executed** . By default, the user will be
**automation** , but this user can be changed by clicking **EDIT** at the bottom of the window. To
give this user permission to view assets, follow these steps:

-   In the main drop-down menu, select **Administration** , then select the **User Management** ,
    and under that tab, select **Roles** . Finally, click **+ ROLE** .
-   In the **Add Role** wizard, give the role a name (e.g **Asset Viewer** ), and provide a
    description. Subsequently, under **Available Users** , add the user assigned to the asset viewed
    earlier. Then click the **Permissions** tab.
-   On the permission tab, under **Available Privileges** , give the role the **View Assets**
    privilege. Then click **SAVE** .

## Method to Run Test Connectivity (for delegated permissions)

After setting up the asset and user, click the **TEST CONNECTIVITY** button. A window should pop up
and display a URL. Navigate to this URL in a separate browser tab. This new tab will redirect to a
Microsoft login page. Log in to a Microsoft account with administrator privileges to the Microsoft
AD environment. After logging in, review the requested permissions listed, then click **Accept** .
Finally, close that tab. The test connectivity window should show a success.

The app should now be ready to use.

## State File Permissions

Please check the permissions for the state file as mentioned below.

#### State Filepath

-   For Root Install Instance:
    /opt/phantom/local_data/app_states/f2a239df-acb2-47d6-861c-726a435cfe76/{asset_id}\_state.json
-   For Non-Root Install Instance:
    /\<PHANTOM_HOME_DIRECTORY>/local_data/app_states/f2a239df-acb2-47d6-861c-726a435cfe76/{asset_id}\_state.json

#### State File Permissions

-   File Rights: rw-rw-r-- (664) (The SOAR user should have read and write access for the state
    file)
-   File Owner: appropriate SOAR user

## Port Details

The app uses HTTP/ HTTPS protocol for communicating with the Microsoft Graph server. Below are the
default ports used by the Splunk SOAR Connector.

| Service Name | Transport Protocol | Port |
|--------------|--------------------|------|
| https        | tcp                | 443  |


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a MS Graph for Active Directory asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**tenant\_id** |  required  | string | Tenant \(Tenant ID or Tenant Name\)
**client\_id** |  required  | string | Application ID
**client\_secret** |  required  | password | Client Secret
**region** |  optional  | string | Microsoft AD Region
**admin\_access\_required** |  optional  | boolean | Admin Access Required
**admin\_access\_granted** |  optional  | boolean | Admin Consent Already Provided

### Supported Actions  
[test connectivity](#action-test-connectivity) - Use supplied credentials to generate a token with MS Graph  
[list users](#action-list-users) - Get a list of users  
[reset password](#action-reset-password) - Reset or set a user's password in an Microsoft AD environment  
[disable tokens](#action-disable-tokens) - Invalidate all active refresh tokens for a user in a Microsoft AD environment  
[enable user](#action-enable-user) - Enable a user  
[disable user](#action-disable-user) - Disable a user  
[list user devices](#action-list-user-devices) - List devices for a specified user  
[list user attributes](#action-list-user-attributes) - List attributes for all or a specified user  
[set user attribute](#action-set-user-attribute) - Set an attribute for a user  
[remove user](#action-remove-user) - Remove a user from a specified group  
[add user](#action-add-user) - Add a user to a specified group  
[list groups](#action-list-groups) - List groups in the organization  
[get group](#action-get-group) - Get information about a group  
[list group members](#action-list-group-members) - List the members in a group  
[validate group](#action-validate-group) - Returns true if a user is in a group; otherwise, false  
[list directory roles](#action-list-directory-roles) - List the directory roles that are activated in the tenant  
[generate token](#action-generate-token) - Generate a token or regenerates token when the token expires  

## action: 'test connectivity'
Use supplied credentials to generate a token with MS Graph

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'list users'
Get a list of users

Type: **investigate**  
Read only: **True**

For more information on using the filter\_string, select\_string and expand\_string parameters, refer to https\://docs\.microsoft\.com/en\-us/graph/query\-parameters\. By default, only a limited set of properties are returned, to return an alternative property set use $select query parameter\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**filter\_string** |  optional  | Filter string to apply to user listing | string | 
**select\_string** |  optional  | Select string to get additional user properties\. Separate multiple values with commas | string | 
**expand\_string** |  optional  | Expand string to get a resource or collection referenced by a single relationship | string | 
**use\_advanced\_query** |  optional  | Use advanced query capabilities | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action\_result\.status | string |  |   success  failed 
action\_result\.parameter\.filter\_string | string |  |   startswith\(displayName,'User'\) 
action\_result\.parameter\.select\_string | string |  |   displayName 
action\_result\.parameter\.expand\_string | string |  |   manager  memberOf 
action\_result\.parameter\.use\_advanced\_query | boolean |  |   True  False 
action\_result\.data\.\*\.accountEnabled | boolean |  |   True  False 
action\_result\.data\.\*\.ageGroup | string |  |  
action\_result\.data\.\*\.assignedLicenses\.\*\.skuId | string |  |   189a915c\-fe4f\-4ffa\-bde4\-85b9628d07a0 
action\_result\.data\.\*\.assignedPlans\.\*\.assignedTimestamp | string |  |   2017\-08\-29T02\:31\:40Z 
action\_result\.data\.\*\.assignedPlans\.\*\.capabilityStatus | string |  |   Enabled 
action\_result\.data\.\*\.assignedPlans\.\*\.service | string |  |   OfficeForms 
action\_result\.data\.\*\.assignedPlans\.\*\.servicePlanId | string |  |   e212cbc7\-0961\-4c40\-9825\-01117710dcb1 
action\_result\.data\.\*\.city | string |  |   Palo Alto 
action\_result\.data\.\*\.companyName | string |  |  
action\_result\.data\.\*\.consentProvidedForMinor | string |  |  
action\_result\.data\.\*\.country | string |  |   US 
action\_result\.data\.\*\.createdDateTime | string |  |   2019\-05\-21T22\:27\:20Z 
action\_result\.data\.\*\.creationType | string |  |  
action\_result\.data\.\*\.deletionTimestamp | string |  |  
action\_result\.data\.\*\.department | string |  |   Sales 
action\_result\.data\.\*\.dirSyncEnabled | string |  |  
action\_result\.data\.\*\.displayName | string |  |   User 
action\_result\.data\.\*\.employeeId | string |  |  
action\_result\.data\.\*\.facsimileTelephoneNumber | string |  |  
action\_result\.data\.\*\.givenName | string |  |   testuser 
action\_result\.data\.\*\.id | string |  `user id`  |   e4c722ac\-3b83\-478d\-8f52\-c388885dc30f 
action\_result\.data\.\*\.immutableId | string |  |  
action\_result\.data\.\*\.isCompromised | string |  |  
action\_result\.data\.\*\.jobTitle | string |  |   Sales Manager 
action\_result\.data\.\*\.lastDirSyncTime | string |  |  
action\_result\.data\.\*\.legalAgeGroupClassification | string |  |  
action\_result\.data\.\*\.mail | string |  `email`  |   user\@test\.onmicrosoft\.com 
action\_result\.data\.\*\.mailNickname | string |  |   testmail 
action\_result\.data\.\*\.mobile | string |  |   \+1 5556378688 
action\_result\.data\.\*\.mobilePhone | string |  |  
action\_result\.data\.\*\.objectType | string |  |   User 
action\_result\.data\.\*\.odata\.type | string |  |   Microsoft\.DirectoryServices\.User 
action\_result\.data\.\*\.officeLocation | string |  |  
action\_result\.data\.\*\.onPremisesDistinguishedName | string |  |  
action\_result\.data\.\*\.onPremisesSecurityIdentifier | string |  |  
action\_result\.data\.\*\.otherMails | string |  `email`  |   user\.test\@outlook\.com 
action\_result\.data\.\*\.passwordPolicies | string |  |   None 
action\_result\.data\.\*\.passwordProfile | string |  |  
action\_result\.data\.\*\.passwordProfile\.enforceChangePasswordPolicy | boolean |  |   True  False 
action\_result\.data\.\*\.passwordProfile\.forceChangePasswordNextLogin | boolean |  |   True  False 
action\_result\.data\.\*\.passwordProfile\.password | string |  |  
action\_result\.data\.\*\.physicalDeliveryOfficeName | string |  |  
action\_result\.data\.\*\.postalCode | string |  |   94303 
action\_result\.data\.\*\.preferredLanguage | string |  |   en\-US 
action\_result\.data\.\*\.provisionedPlans\.\*\.capabilityStatus | string |  |   Enabled 
action\_result\.data\.\*\.provisionedPlans\.\*\.provisioningStatus | string |  |   Success 
action\_result\.data\.\*\.provisionedPlans\.\*\.service | string |  |   exchange 
action\_result\.data\.\*\.proxyAddresses | string |  |   SMTP\:user1\@test\.onmicrosoft\.com 
action\_result\.data\.\*\.refreshTokensValidFromDateTime | string |  |   2017\-09\-27T22\:54\:59Z  2018\-01\-10T22\:18\:17Z 
action\_result\.data\.\*\.showInAddressList | string |  |  
action\_result\.data\.\*\.sipProxyAddress | string |  `email`  |   user\@test\.onmicrosoft\.com 
action\_result\.data\.\*\.state | string |  |   CA 
action\_result\.data\.\*\.streetAddress | string |  |   2479 E\. Bayshore Rd\. 
action\_result\.data\.\*\.surname | string |  |   Test\_surname 
action\_result\.data\.\*\.telephoneNumber | string |  |  
action\_result\.data\.\*\.thumbnailPhoto\@odata\.mediaEditLink | string |  |   directoryObjects/6132ca31\-7a09\-434f\-a269\-abe836d0c01e/Microsoft\.DirectoryServices\.User/thumbnailPhoto 
action\_result\.data\.\*\.usageLocation | string |  |   US 
action\_result\.data\.\*\.userPrincipalName | string |  `user id`  |   user\@test\.onmicrosoft\.com 
action\_result\.data\.\*\.userState | string |  |  
action\_result\.data\.\*\.userStateChangedOn | string |  |  
action\_result\.data\.\*\.userType | string |  |   Member 
action\_result\.summary\.num\_users | numeric |  |   8 
action\_result\.summary\.result\_found | boolean |  |   True  False 
action\_result\.summary\.total\_results | numeric |  |   7 
action\_result\.message | string |  |   Successfully listed users 
summary\.total\_objects | numeric |  |   1 
summary\.total\_objects\_successful | numeric |  |   1   

## action: 'reset password'
Reset or set a user's password in an Microsoft AD environment

Type: **contain**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user\_id** |  required  | User ID to change password \- can be user principal name or object ID | string |  `user id` 
**force\_change** |  optional  | Force user to change password on next login | boolean | 
**temp\_password** |  required  | Temporary password for user | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action\_result\.status | string |  |   success  failed 
action\_result\.parameter\.force\_change | boolean |  |   True  False 
action\_result\.parameter\.temp\_password | string |  |   Temp\_PA$$w0rd 
action\_result\.parameter\.user\_id | string |  `user id`  |   ee3dc4f2\-70f9\-446f\-a19e\-6b4e95ba030d  user\@test\.onmicrosoft\.com 
action\_result\.data | string |  |  
action\_result\.summary\.status | string |  |   Successfully reset user password 
action\_result\.message | string |  |   Status\: Successfully reset user password 
summary\.total\_objects | numeric |  |   1 
summary\.total\_objects\_successful | numeric |  |   1   

## action: 'disable tokens'
Invalidate all active refresh tokens for a user in a Microsoft AD environment

Type: **contain**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user\_id** |  required  | User ID to disable tokens of \- can be user principal name or object ID | string |  `user id` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action\_result\.status | string |  |   success  failed 
action\_result\.parameter\.user\_id | string |  `user id`  |   ee3dc4f2\-70f9\-446f\-a19e\-6b4e95ba030d  user\@test\.onmicrosoft\.com 
action\_result\.data | string |  |  
action\_result\.data\.\*\.\@odata\.context | string |  |   https\://graph\.microsoft\.com/v1\.0/$metadata\#Edm\.Boolean 
action\_result\.data\.\*\.odata\.metadata | string |  `url`  |   https\://graph\.windows\.net/1t309est\-db6c\-4tes\-t1d2\-12bf3456d78d/$metadata\#Edm\.Null 
action\_result\.data\.\*\.odata\.null | boolean |  |   True  False 
action\_result\.data\.\*\.value | boolean |  |   True  False 
action\_result\.summary\.status | string |  |   Successfully disabled tokens 
action\_result\.message | string |  |   Successfully invalidated tokens  Status\: Successfully disabled tokens 
summary\.total\_objects | numeric |  |   1 
summary\.total\_objects\_successful | numeric |  |   1   

## action: 'enable user'
Enable a user

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user\_id** |  required  | User ID to enable \- can be user principal name or object ID | string |  `user id` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action\_result\.status | string |  |   success  failed 
action\_result\.parameter\.user\_id | string |  `user id`  |   user\@test\.onmicrosoft\.com 
action\_result\.data | string |  |  
action\_result\.summary\.status | string |  |   Successfully enabled user user\@test\.onmicrosoft\.com 
action\_result\.message | string |  |   Status\: Successfully enabled user user\@test\.onmicrosoft\.com 
summary\.total\_objects | numeric |  |   1 
summary\.total\_objects\_successful | numeric |  |   1   

## action: 'disable user'
Disable a user

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user\_id** |  required  | User ID to disable \- can be user principal name or object ID | string |  `user id` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action\_result\.status | string |  |   success  failed 
action\_result\.parameter\.user\_id | string |  `user id`  |   user\@test\.onmicrosoft\.com 
action\_result\.data | string |  |  
action\_result\.summary\.status | string |  |   Successfully disabled user user\@test\.onmicrosoft\.com 
action\_result\.message | string |  |   Status\: Successfully disabled user user\@test\.onmicrosoft\.com 
summary\.total\_objects | numeric |  |   1 
summary\.total\_objects\_successful | numeric |  |   1   

## action: 'list user devices'
List devices for a specified user

Type: **investigate**  
Read only: **True**

By default, only a limited set of properties are returned, to return an alternative property set use $select query parameter\. For more information on using the select\_string parameter, refer to <a href='https\://docs\.microsoft\.com/en\-us/graph/query\-parameters\#select\-parameter' target='\_blank'>this</a> documentation\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user\_id** |  required  | User ID \- can be user principal name or object ID | string |  `user id` 
**select\_string** |  optional  | Select string to get additional user properties\. Separate multiple values with commas | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action\_result\.status | string |  |   success  failed 
action\_result\.parameter\.select\_string | string |  |   displayName 
action\_result\.parameter\.user\_id | string |  `user id`  |   user\@test\.onmicrosoft\.com 
action\_result\.data\.\*\.\@odata\.type | string |  |   \#microsoft\.graph\.device 
action\_result\.data\.\*\.accountEnabled | boolean |  |   True  False 
action\_result\.data\.\*\.alternativeSecurityIds\.\*\.identityProvider | string |  |  
action\_result\.data\.\*\.alternativeSecurityIds\.\*\.key | string |  |   WAA1ADAAOQA6ADwAUwBIAEEAMQAtAFQAUAAtAFAAVQBCAEsARQBZAD4AOQA5AEEARQAwADgAOABDAEUANAA1ADgAMABCADcAQgBGAEEARQA2ADEAQQBCADYANAA3ADYANgA5ADUAOAAzAEQANABFAEYARQA5ADYAOAAyAHkAcQBSAEIANwBrAGEAMQA4AEoATAByACsAegB4AE8AYwB6AE8AYgBNAFEANQBZAEgAbgB0AFQAdgBOAG0AbgA5AEQAZQA2AFgAVQBUAGgAcwBFAD0A 
action\_result\.data\.\*\.alternativeSecurityIds\.\*\.type | numeric |  |   2 
action\_result\.data\.\*\.approximateLastSignInDateTime | string |  |   2019\-09\-26T03\:42\:15Z 
action\_result\.data\.\*\.complianceExpirationDateTime | string |  |  
action\_result\.data\.\*\.createdDateTime | string |  |   2019\-09\-26T03\:42\:15Z 
action\_result\.data\.\*\.deletedDateTime | string |  |  
action\_result\.data\.\*\.deviceCategory | string |  |  
action\_result\.data\.\*\.deviceId | string |  |  
action\_result\.data\.\*\.deviceMetadata | string |  |  
action\_result\.data\.\*\.deviceOwnership | string |  |  
action\_result\.data\.\*\.deviceVersion | numeric |  |  
action\_result\.data\.\*\.displayName | string |  |  
action\_result\.data\.\*\.domainName | string |  |  
action\_result\.data\.\*\.enrollmentProfileName | string |  |  
action\_result\.data\.\*\.enrollmentType | string |  |  
action\_result\.data\.\*\.extensionAttributes\.extensionAttribute1 | string |  |  
action\_result\.data\.\*\.extensionAttributes\.extensionAttribute10 | string |  |  
action\_result\.data\.\*\.extensionAttributes\.extensionAttribute11 | string |  |  
action\_result\.data\.\*\.extensionAttributes\.extensionAttribute12 | string |  |  
action\_result\.data\.\*\.extensionAttributes\.extensionAttribute13 | string |  |  
action\_result\.data\.\*\.extensionAttributes\.extensionAttribute14 | string |  |  
action\_result\.data\.\*\.extensionAttributes\.extensionAttribute15 | string |  |  
action\_result\.data\.\*\.extensionAttributes\.extensionAttribute2 | string |  |  
action\_result\.data\.\*\.extensionAttributes\.extensionAttribute3 | string |  |  
action\_result\.data\.\*\.extensionAttributes\.extensionAttribute4 | string |  |  
action\_result\.data\.\*\.extensionAttributes\.extensionAttribute5 | string |  |  
action\_result\.data\.\*\.extensionAttributes\.extensionAttribute6 | string |  |  
action\_result\.data\.\*\.extensionAttributes\.extensionAttribute7 | string |  |  
action\_result\.data\.\*\.extensionAttributes\.extensionAttribute8 | string |  |  
action\_result\.data\.\*\.extensionAttributes\.extensionAttribute9 | string |  |  
action\_result\.data\.\*\.externalSourceName | string |  |  
action\_result\.data\.\*\.id | string |  |  
action\_result\.data\.\*\.isCompliant | boolean |  |  
action\_result\.data\.\*\.isManaged | boolean |  |  
action\_result\.data\.\*\.isRooted | string |  |  
action\_result\.data\.\*\.managementType | string |  |  
action\_result\.data\.\*\.manufacturer | string |  |  
action\_result\.data\.\*\.mdmAppId | string |  |  
action\_result\.data\.\*\.model | string |  |  
action\_result\.data\.\*\.onPremisesLastSyncDateTime | string |  |  
action\_result\.data\.\*\.onPremisesSyncEnabled | boolean |  |  
action\_result\.data\.\*\.operatingSystem | string |  |   Windows 
action\_result\.data\.\*\.operatingSystemVersion | string |  |   10\.0\.18362\.0 
action\_result\.data\.\*\.profileType | string |  |   RegisteredDevice 
action\_result\.data\.\*\.registrationDateTime | string |  |   2019\-09\-26T03\:42\:15Z 
action\_result\.data\.\*\.sourceType | string |  |  
action\_result\.data\.\*\.trustType | string |  |   Workplace 
action\_result\.summary | string |  |  
action\_result\.summary\.status | string |  |   Successfully retrieved owned devices for user test\@user\.onmicrosoft\.com 
action\_result\.message | string |  |   Status\: Successfully retrieved owned devices for user test\@user\.onmicrosoft\.com 
summary\.total\_objects | numeric |  |   1 
summary\.total\_objects\_successful | numeric |  |   1   

## action: 'list user attributes'
List attributes for all or a specified user

Type: **investigate**  
Read only: **True**

By default, only a limited set of properties are returned, to return an alternative property set use $select query parameter\. For more information on using the select\_string and expand\_string parameters, refer to https\://docs\.microsoft\.com/en\-us/graph/query\-parameters\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user\_id** |  optional  | User ID \- can be user principal name or object ID | string |  `user id` 
**select\_string** |  optional  | Select string to get additional user properties\. Separate multiple values with commas | string | 
**expand\_string** |  optional  | Expand string to get a resource or collection referenced by a single relationship | string | 
**use\_advanced\_query** |  optional  | Use advanced query capabilities | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action\_result\.status | string |  |   success  failed 
action\_result\.parameter\.select\_string | string |  |   displayName 
action\_result\.parameter\.expand\_string | string |  |   manager  memberOf 
action\_result\.parameter\.use\_advanced\_query | boolean |  |   True  False 
action\_result\.parameter\.user\_id | string |  `user id`  |   user\@test\.onmicrosoft\.com 
action\_result\.data\.\*\.\@odata\.context | string |  |   https\://graph\.microsoft\.com/v1\.0/$metadata\#users/$entity 
action\_result\.data\.\*\.accountEnabled | boolean |  |   True  False 
action\_result\.data\.\*\.ageGroup | string |  |  
action\_result\.data\.\*\.assignedLicenses\.\*\.skuId | string |  |   f30db892\-07e9\-47e9\-837c\-80727f46fd3d 
action\_result\.data\.\*\.assignedPlans\.\*\.assignedTimestamp | string |  |   2019\-04\-26T07\:21\:18Z 
action\_result\.data\.\*\.assignedPlans\.\*\.capabilityStatus | string |  |   Enabled 
action\_result\.data\.\*\.assignedPlans\.\*\.service | string |  |   exchange 
action\_result\.data\.\*\.assignedPlans\.\*\.servicePlanId | string |  |   33c4f319\-9bdd\-48d6\-9c4d\-410b750a4a5a 
action\_result\.data\.\*\.city | string |  |  
action\_result\.data\.\*\.companyName | string |  |  
action\_result\.data\.\*\.consentProvidedForMinor | string |  |  
action\_result\.data\.\*\.country | string |  |  
action\_result\.data\.\*\.createdDateTime | string |  |   2019\-05\-02T20\:27\:59Z 
action\_result\.data\.\*\.creationType | string |  |  
action\_result\.data\.\*\.deletionTimestamp | string |  |  
action\_result\.data\.\*\.department | string |  |   Sales 
action\_result\.data\.\*\.dirSyncEnabled | string |  |  
action\_result\.data\.\*\.displayName | string |  |   Test User 
action\_result\.data\.\*\.employeeId | string |  |  
action\_result\.data\.\*\.facsimileTelephoneNumber | string |  |  
action\_result\.data\.\*\.givenName | string |  |  
action\_result\.data\.\*\.id | string |  `user id`  |   7d55d7e6\-cf5a\-4dd2\-a176\-57a3c33b7fa9 
action\_result\.data\.\*\.identities\.\*\.issuer | string |  |   test\.onmicrosoft\.com 
action\_result\.data\.\*\.identities\.\*\.issuerAssignedId | string |  |   test2\@user\.onmicrosoft\.com 
action\_result\.data\.\*\.identities\.\*\.signInType | string |  |   userPrincipalName 
action\_result\.data\.\*\.immutableId | string |  |  
action\_result\.data\.\*\.isCompromised | string |  |  
action\_result\.data\.\*\.jobTitle | string |  |  
action\_result\.data\.\*\.lastDirSyncTime | string |  |  
action\_result\.data\.\*\.legalAgeGroupClassification | string |  |  
action\_result\.data\.\*\.mail | string |  `email`  |  
action\_result\.data\.\*\.mailNickname | string |  |   test 
action\_result\.data\.\*\.mobile | string |  |  
action\_result\.data\.\*\.mobilePhone | string |  |  
action\_result\.data\.\*\.objectId | string |  |   59f51194\-1998\-4932\-a8ac\-468e59374edc 
action\_result\.data\.\*\.objectType | string |  |   User 
action\_result\.data\.\*\.odata\.metadata | string |  |   https\://graph\.windows\.net/1t309est\-db6c\-4tes\-t1d2\-12bf3456d78d/$metadata\#directoryObjects/\@Element 
action\_result\.data\.\*\.odata\.type | string |  |   Microsoft\.DirectoryServices\.User 
action\_result\.data\.\*\.officeLocation | string |  |  
action\_result\.data\.\*\.onPremisesDistinguishedName | string |  |  
action\_result\.data\.\*\.onPremisesSecurityIdentifier | string |  |  
action\_result\.data\.\*\.otherMails | string |  `email`  |   user\@test\.com 
action\_result\.data\.\*\.passwordPolicies | string |  |  
action\_result\.data\.\*\.passwordProfile | string |  |  
action\_result\.data\.\*\.passwordProfile\.enforceChangePasswordPolicy | boolean |  |   True  False 
action\_result\.data\.\*\.passwordProfile\.forceChangePasswordNextLogin | boolean |  |   True  False 
action\_result\.data\.\*\.passwordProfile\.password | string |  |  
action\_result\.data\.\*\.physicalDeliveryOfficeName | string |  |  
action\_result\.data\.\*\.postalCode | string |  |  
action\_result\.data\.\*\.preferredLanguage | string |  |  
action\_result\.data\.\*\.provisionedPlans\.\*\.capabilityStatus | string |  |   Enabled 
action\_result\.data\.\*\.provisionedPlans\.\*\.provisioningStatus | string |  |   Success 
action\_result\.data\.\*\.provisionedPlans\.\*\.service | string |  |   exchange 
action\_result\.data\.\*\.proxyAddresses | string |  |   SMTP\:test\_shared\_mailbox\@test\.onmicrosoft\.com 
action\_result\.data\.\*\.refreshTokensValidFromDateTime | string |  |   2019\-05\-16T19\:54\:18Z 
action\_result\.data\.\*\.showInAddressList | string |  |  
action\_result\.data\.\*\.sipProxyAddress | string |  `email`  |  
action\_result\.data\.\*\.state | string |  |  
action\_result\.data\.\*\.streetAddress | string |  |  
action\_result\.data\.\*\.surname | string |  |  
action\_result\.data\.\*\.telephoneNumber | string |  |  
action\_result\.data\.\*\.thumbnailPhoto\@odata\.mediaEditLink | string |  |   directoryObjects/59f12345\-1998\-4932\-a8ac\-468e59374edc/Microsoft\.DirectoryServices\.User/thumbnailPhoto 
action\_result\.data\.\*\.usageLocation | string |  |   US 
action\_result\.data\.\*\.userPrincipalName | string |  `user id`  |   user\@test\.onmicrosoft\.com 
action\_result\.data\.\*\.userState | string |  |  
action\_result\.data\.\*\.userStateChangedOn | string |  |  
action\_result\.data\.\*\.userType | string |  |   Member 
action\_result\.summary\.status | string |  |   Successfully retrieved user attributes  Successfully retrieved attributes for user user\@test\.onmicrosoft\.com 
action\_result\.message | string |  |   Status\: Successfully retrieved user attributes  Status\: Successfully retrieved attributes for user user\@test\.onmicrosoft\.com, User enabled\: False 
summary\.total\_objects | numeric |  |   1 
summary\.total\_objects\_successful | numeric |  |   1   

## action: 'set user attribute'
Set an attribute for a user

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user\_id** |  required  | User ID \- can be user principal name or object ID | string |  `user id` 
**attribute** |  required  | Attribute to set | string | 
**attribute\_value** |  required  | Value of attribute to set | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action\_result\.status | string |  |   success  failed 
action\_result\.parameter\.attribute | string |  |   department 
action\_result\.parameter\.attribute\_value | string |  |   Sales 
action\_result\.parameter\.user\_id | string |  `user id`  |   user\@test\.onmicrosoft\.com 
action\_result\.data | string |  |  
action\_result\.data\.\*\.classification | string |  |  
action\_result\.data\.\*\.createdDateTime | string |  |   2021\-03\-25T18\:40\:53Z 
action\_result\.data\.\*\.deletedDateTime | string |  |  
action\_result\.data\.\*\.deletionTimestamp | string |  |  
action\_result\.data\.\*\.description | string |  |   This is for testing purpose 
action\_result\.data\.\*\.dirSyncEnabled | string |  |  
action\_result\.data\.\*\.displayName | string |  |   Test\-site 
action\_result\.data\.\*\.expirationDateTime | string |  |  
action\_result\.data\.\*\.id | string |  `user id`  |   2a201c95\-101b\-42d9\-a7af\-9a2fdf8193f1 
action\_result\.data\.\*\.isAssignableToRole | string |  |  
action\_result\.data\.\*\.lastDirSyncTime | string |  |  
action\_result\.data\.\*\.mail | string |  `email`  |   Test\-site\@test\.onmicrosoft\.com 
action\_result\.data\.\*\.mailEnabled | boolean |  |   True  False 
action\_result\.data\.\*\.mailNickname | string |  |   Test\-site 
action\_result\.data\.\*\.membershipRule | string |  |  
action\_result\.data\.\*\.membershipRuleProcessingState | string |  |  
action\_result\.data\.\*\.objectType | string |  |   Group 
action\_result\.data\.\*\.odata\.type | string |  |   Microsoft\.DirectoryServices\.Group 
action\_result\.data\.\*\.onPremisesDomainName | string |  `domain`  |  
action\_result\.data\.\*\.onPremisesLastSyncDateTime | string |  |  
action\_result\.data\.\*\.onPremisesNetBiosName | string |  |  
action\_result\.data\.\*\.onPremisesSamAccountName | string |  |  
action\_result\.data\.\*\.onPremisesSecurityIdentifier | string |  |  
action\_result\.data\.\*\.onPremisesSyncEnabled | string |  |  
action\_result\.data\.\*\.preferredDataLocation | string |  |  
action\_result\.data\.\*\.preferredLanguage | string |  |  
action\_result\.data\.\*\.proxyAddresses | string |  |   SMTP\:test\-h\@test\.onmicrosoft\.com 
action\_result\.data\.\*\.renewedDateTime | string |  |   2021\-03\-25T18\:40\:53Z 
action\_result\.data\.\*\.securityEnabled | boolean |  |   True  False 
action\_result\.data\.\*\.securityIdentifier | string |  |   S\-1\-12\-1\-294681889\-1319597617\-672379543\-28952017 
action\_result\.data\.\*\.theme | string |  |  
action\_result\.data\.\*\.visibility | string |  |   Private 
action\_result\.summary\.status | string |  |   Successfully enabled user user\@test\.onmicrosoft\.com 
action\_result\.message | string |  |   Status\: Successfully enabled user user\@test\.onmicrosoft\.com 
summary\.total\_objects | numeric |  |   1 
summary\.total\_objects\_successful | numeric |  |   1   

## action: 'remove user'
Remove a user from a specified group

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**group\_object\_id** |  required  | Object ID of group | string |  `group object id` 
**user\_id** |  required  | User ID to remove from group | string |  `user id` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action\_result\.status | string |  |   success  failed 
action\_result\.parameter\.group\_object\_id | string |  `group object id`  |   ddb876b3\-603a\-437b\-9814\-2d46a2219a1e 
action\_result\.parameter\.user\_id | string |  `user id`  |   17be76d0\-35ed\-4881\-ab62\-d2eb73c2ebe3 
action\_result\.data | string |  |  
action\_result\.summary\.status | string |  |   Successfully removed user from group  User not in group 
action\_result\.message | string |  |   Status\: Successfully removed user from group  Status\: User not in group 
summary\.total\_objects | numeric |  |   1 
summary\.total\_objects\_successful | numeric |  |   1   

## action: 'add user'
Add a user to a specified group

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**group\_object\_id** |  required  | Object ID of group | string |  `group object id` 
**user\_id** |  required  | User ID to add to group | string |  `user id` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action\_result\.status | string |  |   success  failed 
action\_result\.parameter\.group\_object\_id | string |  `group object id`  |   ddb876b3\-603a\-437b\-9814\-2d46a2219a1e 
action\_result\.parameter\.user\_id | string |  `user id`  |   17be76d0\-35ed\-4881\-ab62\-d2eb73c2ebe3 
action\_result\.data | string |  |  
action\_result\.summary\.status | string |  |   Successfully added user to group  User already in group 
action\_result\.message | string |  |   Status\: Successfully added user to group  Status\: User already in group 
summary\.total\_objects | numeric |  |   1 
summary\.total\_objects\_successful | numeric |  |   1   

## action: 'list groups'
List groups in the organization

Type: **investigate**  
Read only: **True**

By default, only a limited set of properties are returned, to return an alternative property set use $select query parameter\. For more information on using the select\_string and expand\_string parameters, refer to https\://docs\.microsoft\.com/en\-us/graph/query\-parameters\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**filter\_string** |  optional  | Filter string to apply to group listing | string | 
**select\_string** |  optional  | Select string to get additional group properties\. Separate multiple values with commas | string | 
**expand\_string** |  optional  | Expand string to get a resource or collection referenced by a single relationship | string | 
**use\_advanced\_query** |  optional  | Use advanced query capabilities | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action\_result\.status | string |  |   success  failed 
action\_result\.parameter\.filter\_string | string |  |   createdDateTime ge '2014\-01\-01T00\:00\:00Z' 
action\_result\.parameter\.select\_string | string |  |   displayName 
action\_result\.parameter\.expand\_string | string |  |   members 
action\_result\.parameter\.use\_advanced\_query | boolean |  |   True  False 
action\_result\.data\.\*\.classification | string |  |  
action\_result\.data\.\*\.createdDateTime | string |  |   2021\-03\-25T18\:40\:53Z 
action\_result\.data\.\*\.deletedDateTime | string |  |  
action\_result\.data\.\*\.deletionTimestamp | string |  |  
action\_result\.data\.\*\.description | string |  |   This is for testing purpose 
action\_result\.data\.\*\.dirSyncEnabled | string |  |  
action\_result\.data\.\*\.displayName | string |  |   Test\-site 
action\_result\.data\.\*\.expirationDateTime | string |  |  
action\_result\.data\.\*\.id | string |  `group object id`  |   2a201c95\-101b\-42d9\-a7af\-9a2fdf8193f1 
action\_result\.data\.\*\.isAssignableToRole | string |  |  
action\_result\.data\.\*\.lastDirSyncTime | string |  |  
action\_result\.data\.\*\.mail | string |  `email`  |   Test\-site\@test\.onmicrosoft\.com 
action\_result\.data\.\*\.mailEnabled | boolean |  |   True  False 
action\_result\.data\.\*\.mailNickname | string |  |   Test\-site 
action\_result\.data\.\*\.membershipRule | string |  |  
action\_result\.data\.\*\.membershipRuleProcessingState | string |  |  
action\_result\.data\.\*\.objectType | string |  |   Group 
action\_result\.data\.\*\.odata\.type | string |  |   Microsoft\.DirectoryServices\.Group 
action\_result\.data\.\*\.onPremisesDomainName | string |  `domain`  |  
action\_result\.data\.\*\.onPremisesLastSyncDateTime | string |  |  
action\_result\.data\.\*\.onPremisesNetBiosName | string |  |  
action\_result\.data\.\*\.onPremisesSamAccountName | string |  |  
action\_result\.data\.\*\.onPremisesSecurityIdentifier | string |  |  
action\_result\.data\.\*\.onPremisesSyncEnabled | string |  |  
action\_result\.data\.\*\.preferredDataLocation | string |  |  
action\_result\.data\.\*\.preferredLanguage | string |  |  
action\_result\.data\.\*\.proxyAddresses | string |  |   SMTP\:test\-h\@test\.onmicrosoft\.com 
action\_result\.data\.\*\.renewedDateTime | string |  |   2021\-03\-25T18\:40\:53Z 
action\_result\.data\.\*\.securityEnabled | boolean |  |   True  False 
action\_result\.data\.\*\.securityIdentifier | string |  |   S\-1\-12\-1\-294681889\-1319597617\-672379543\-28952017 
action\_result\.data\.\*\.theme | string |  |  
action\_result\.data\.\*\.visibility | string |  |   Private 
action\_result\.summary\.num\_groups | numeric |  |   7 
action\_result\.message | string |  |   Num groups\: 7 
summary\.total\_objects | numeric |  |   1 
summary\.total\_objects\_successful | numeric |  |   1   

## action: 'get group'
Get information about a group

Type: **investigate**  
Read only: **True**

By default, only a limited set of properties are returned, to return an alternative property set use $select query parameter\. For more information on using the select\_string and expand\_string parameters, refer to https\://docs\.microsoft\.com/en\-us/graph/query\-parameters\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**object\_id** |  required  | Object ID of group | string |  `group object id` 
**select\_string** |  optional  | Select string to get additional group properties\. Separate multiple values with commas | string | 
**expand\_string** |  optional  | Expand string to get a resource or collection referenced by a single relationship | string | 
**use\_advanced\_query** |  optional  | Use advanced query capabilities | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action\_result\.status | string |  |   success  failed 
action\_result\.parameter\.object\_id | string |  `group object id`  |   ddb876b3\-603a\-437b\-9814\-2d46a2219a1e 
action\_result\.parameter\.select\_string | string |  |   displayName 
action\_result\.parameter\.expand\_string | string |  |   members 
action\_result\.parameter\.use\_advanced\_query | boolean |  |   True  False 
action\_result\.data\.\*\.\@odata\.context | string |  |   https\://graph\.microsoft\.com/v1\.0/$metadata\#groups\(id,displayName\)/$entity 
action\_result\.data\.\*\.classification | string |  |  
action\_result\.data\.\*\.createdDateTime | string |  |   2020\-08\-05T11\:59\:49Z 
action\_result\.data\.\*\.deletedDateTime | string |  |  
action\_result\.data\.\*\.deletionTimestamp | string |  |  
action\_result\.data\.\*\.description | string |  |   This is the office 365 group 
action\_result\.data\.\*\.dirSyncEnabled | string |  |  
action\_result\.data\.\*\.displayName | string |  |   o365group 
action\_result\.data\.\*\.expirationDateTime | string |  |  
action\_result\.data\.\*\.id | string |  `group object id`  |   ddb876b3\-603a\-437b\-9814\-2d46a2219a1e 
action\_result\.data\.\*\.isAssignableToRole | string |  |  
action\_result\.data\.\*\.lastDirSyncTime | string |  |  
action\_result\.data\.\*\.mail | string |  `email`  |   bc7f9cabe\@test\.onmicrosoft\.com 
action\_result\.data\.\*\.mailEnabled | boolean |  |   True  False 
action\_result\.data\.\*\.mailNickname | string |  |   bc7f9cabe 
action\_result\.data\.\*\.membershipRule | string |  |  
action\_result\.data\.\*\.membershipRuleProcessingState | string |  |  
action\_result\.data\.\*\.objectType | string |  |   Group 
action\_result\.data\.\*\.odata\.metadata | string |  |   https\://graph\.windows\.net/1t309est\-db6c\-4tes\-t1d2\-12bf3456d78d/$metadata\#directoryObjects/\@Element 
action\_result\.data\.\*\.odata\.type | string |  |   Microsoft\.DirectoryServices\.Group 
action\_result\.data\.\*\.onPremisesDomainName | string |  `domain`  |  
action\_result\.data\.\*\.onPremisesLastSyncDateTime | string |  |  
action\_result\.data\.\*\.onPremisesNetBiosName | string |  |  
action\_result\.data\.\*\.onPremisesSamAccountName | string |  |  
action\_result\.data\.\*\.onPremisesSecurityIdentifier | string |  |  
action\_result\.data\.\*\.onPremisesSyncEnabled | string |  |  
action\_result\.data\.\*\.preferredDataLocation | string |  |  
action\_result\.data\.\*\.preferredLanguage | string |  |  
action\_result\.data\.\*\.proxyAddresses | string |  |   SMTP\:bc7f9cabe\@test\.onmicrosoft\.com 
action\_result\.data\.\*\.renewedDateTime | string |  |   2020\-08\-05T11\:59\:49Z 
action\_result\.data\.\*\.securityEnabled | boolean |  |   True  False 
action\_result\.data\.\*\.securityIdentifier | string |  |   S\-1\-12\-1\-909260723\-1083662375\-1952945031\-2402852259 
action\_result\.data\.\*\.theme | string |  |  
action\_result\.data\.\*\.visibility | string |  |  
action\_result\.summary\.display\_name | string |  |   o365group 
action\_result\.summary\.status | string |  |   Successfully retrieved group 104d4576\-1544\-48b5\-bb7e\-9f8f871aa824 
action\_result\.message | string |  |   Display name\: o365group 
summary\.total\_objects | numeric |  |   1 
summary\.total\_objects\_successful | numeric |  |   1   

## action: 'list group members'
List the members in a group

Type: **investigate**  
Read only: **True**

By default, only a limited set of properties are returned, to return an alternative property set use $select query parameter\. For more information on using the select\_string and expand\_string parameters, refer to https\://docs\.microsoft\.com/en\-us/graph/query\-parameters\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**group\_object\_id** |  required  | Object ID of group | string |  `group object id` 
**select\_string** |  optional  | Select string to get additional properties\. Separate multiple values with commas | string | 
**expand\_string** |  optional  | Expand string to get a resource or collection referenced by a single relationship | string | 
**use\_advanced\_query** |  optional  | Use advanced query capabilities | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action\_result\.status | string |  |   success  failed 
action\_result\.parameter\.group\_object\_id | string |  `group object id`  |   ebcd3130\-55a1\-4cbf\-81b2\-86408ff21203 
action\_result\.parameter\.select\_string | string |  |   displayName 
action\_result\.parameter\.expand\_string | string |  |   manager 
action\_result\.parameter\.use\_advanced\_query | boolean |  |   True  False 
action\_result\.data\.\*\.\@odata\.type | string |  |   \#microsoft\.graph\.user 
action\_result\.data\.\*\.accountEnabled | boolean |  |   True 
action\_result\.data\.\*\.ageGroup | string |  |  
action\_result\.data\.\*\.assignedLicenses\.\*\.skuId | string |  |   189a915c\-fe4f\-4ffa\-bde4\-85b9628d07a0 
action\_result\.data\.\*\.assignedPlans\.\*\.assignedDateTime | string |  |   2022\-11\-03T15\:12\:28Z 
action\_result\.data\.\*\.assignedPlans\.\*\.capabilityStatus | string |  |   Deleted 
action\_result\.data\.\*\.assignedPlans\.\*\.service | string |  |   AADPremiumService 
action\_result\.data\.\*\.assignedPlans\.\*\.servicePlanId | string |  |   eec0eb4f\-6444\-4f95\-aba0\-50c24d67f998 
action\_result\.data\.\*\.city | string |  |   Palo Alto 
action\_result\.data\.\*\.companyName | string |  |  
action\_result\.data\.\*\.consentProvidedForMinor | string |  |  
action\_result\.data\.\*\.country | string |  |   US 
action\_result\.data\.\*\.createdDateTime | string |  |   2016\-06\-09T18\:33\:27Z 
action\_result\.data\.\*\.creationType | string |  |  
action\_result\.data\.\*\.deletedDateTime | string |  |  
action\_result\.data\.\*\.department | string |  |  
action\_result\.data\.\*\.displayName | string |  |   Firstname Lastname 
action\_result\.data\.\*\.employeeHireDate | string |  |  
action\_result\.data\.\*\.employeeId | string |  |  
action\_result\.data\.\*\.employeeOrgData | string |  |  
action\_result\.data\.\*\.employeeType | string |  |  
action\_result\.data\.\*\.externalUserState | string |  |  
action\_result\.data\.\*\.externalUserStateChangeDateTime | string |  |  
action\_result\.data\.\*\.faxNumber | string |  |  
action\_result\.data\.\*\.givenName | string |  |  
action\_result\.data\.\*\.id | string |  `user id`  |   17be76d0\-35ed\-4881\-ab62\-d2eb73c2ebe3 
action\_result\.data\.\*\.identities\.\*\.issuer | string |  |   test\.onmicrosoft\.com 
action\_result\.data\.\*\.identities\.\*\.issuerAssignedId | string |  |   test\@user\.onmicrosoft\.com 
action\_result\.data\.\*\.identities\.\*\.signInType | string |  |   userPrincipalName 
action\_result\.data\.\*\.isResourceAccount | string |  |  
action\_result\.data\.\*\.jobTitle | string |  |  
action\_result\.data\.\*\.legalAgeGroupClassification | string |  |  
action\_result\.data\.\*\.mail | string |  |  
action\_result\.data\.\*\.mailNickname | string |  |   User 
action\_result\.data\.\*\.mobilePhone | string |  |  
action\_result\.data\.\*\.officeLocation | string |  |  
action\_result\.data\.\*\.onPremisesDistinguishedName | string |  |  
action\_result\.data\.\*\.onPremisesDomainName | string |  |  
action\_result\.data\.\*\.onPremisesExtensionAttributes\.extensionAttribute1 | string |  |  
action\_result\.data\.\*\.onPremisesExtensionAttributes\.extensionAttribute10 | string |  |  
action\_result\.data\.\*\.onPremisesExtensionAttributes\.extensionAttribute11 | string |  |  
action\_result\.data\.\*\.onPremisesExtensionAttributes\.extensionAttribute12 | string |  |  
action\_result\.data\.\*\.onPremisesExtensionAttributes\.extensionAttribute13 | string |  |  
action\_result\.data\.\*\.onPremisesExtensionAttributes\.extensionAttribute14 | string |  |  
action\_result\.data\.\*\.onPremisesExtensionAttributes\.extensionAttribute15 | string |  |  
action\_result\.data\.\*\.onPremisesExtensionAttributes\.extensionAttribute2 | string |  |  
action\_result\.data\.\*\.onPremisesExtensionAttributes\.extensionAttribute3 | string |  |  
action\_result\.data\.\*\.onPremisesExtensionAttributes\.extensionAttribute4 | string |  |  
action\_result\.data\.\*\.onPremisesExtensionAttributes\.extensionAttribute5 | string |  |  
action\_result\.data\.\*\.onPremisesExtensionAttributes\.extensionAttribute6 | string |  |  
action\_result\.data\.\*\.onPremisesExtensionAttributes\.extensionAttribute7 | string |  |  
action\_result\.data\.\*\.onPremisesExtensionAttributes\.extensionAttribute8 | string |  |  
action\_result\.data\.\*\.onPremisesExtensionAttributes\.extensionAttribute9 | string |  |  
action\_result\.data\.\*\.onPremisesImmutableId | string |  |  
action\_result\.data\.\*\.onPremisesLastSyncDateTime | string |  |  
action\_result\.data\.\*\.onPremisesSamAccountName | string |  |  
action\_result\.data\.\*\.onPremisesSecurityIdentifier | string |  |  
action\_result\.data\.\*\.onPremisesSyncEnabled | string |  |  
action\_result\.data\.\*\.onPremisesUserPrincipalName | string |  |  
action\_result\.data\.\*\.passwordPolicies | string |  |  
action\_result\.data\.\*\.passwordProfile | string |  |  
action\_result\.data\.\*\.postalCode | string |  |   94303 
action\_result\.data\.\*\.preferredDataLocation | string |  |  
action\_result\.data\.\*\.preferredLanguage | string |  |  
action\_result\.data\.\*\.provisionedPlans\.\*\.capabilityStatus | string |  |   Enabled 
action\_result\.data\.\*\.provisionedPlans\.\*\.provisioningStatus | string |  |   Success 
action\_result\.data\.\*\.provisionedPlans\.\*\.service | string |  |   MicrosoftCommunicationsOnline 
action\_result\.data\.\*\.refreshTokensValidFromDateTime | string |  |   2022\-08\-08T13\:00\:58Z 
action\_result\.data\.\*\.showInAddressList | string |  |  
action\_result\.data\.\*\.signInSessionsValidFromDateTime | string |  |   2022\-08\-08T13\:00\:58Z 
action\_result\.data\.\*\.state | string |  |   CA 
action\_result\.data\.\*\.streetAddress | string |  |   2479 E\. Bayshore Rd\. 
action\_result\.data\.\*\.surname | string |  |  
action\_result\.data\.\*\.usageLocation | string |  |   US 
action\_result\.data\.\*\.userPrincipalName | string |  |   ews\_retest\@test\.onmicrosoft\.com 
action\_result\.data\.\*\.userType | string |  |   Member 
action\_result\.summary\.num\_members | numeric |  `user id`  |   3 
action\_result\.summary\.num\_users | numeric |  |   3 
action\_result\.message | string |  |   Num members\: 3 
summary\.total\_objects | numeric |  |   1 
summary\.total\_objects\_successful | numeric |  |   1   

## action: 'validate group'
Returns true if a user is in a group; otherwise, false

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**group\_object\_id** |  required  | Object ID of group | string |  `group object id` 
**user\_id** |  required  | User ID to validate | string |  `user id` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action\_result\.status | string |  |   success  failed 
action\_result\.parameter\.group\_object\_id | string |  `group object id`  |   ebcd3130\-55a1\-4cbf\-81b2\-86408ff21203 
action\_result\.parameter\.user\_id | string |  `user id`  |   user\@test\.onmicrosoft\.com 
action\_result\.data\.\*\.\@odata\.context | string |  |   https\://graph\.microsoft\.com/v1\.0/$metadata\#directoryObjects 
action\_result\.data\.\*\.user\_in\_group | string |  |  
action\_result\.data\.\*\.value\.\*\.\@odata\.type | string |  |   \#microsoft\.graph\.group 
action\_result\.data\.\*\.value\.\*\.classification | string |  |  
action\_result\.data\.\*\.value\.\*\.createdDateTime | string |  |   2022\-02\-25T12\:05\:22Z 
action\_result\.data\.\*\.value\.\*\.deletedDateTime | string |  |  
action\_result\.data\.\*\.value\.\*\.description | string |  |   Test group for MSGraph 
action\_result\.data\.\*\.value\.\*\.displayName | string |  |   Test group for MSGraph 
action\_result\.data\.\*\.value\.\*\.expirationDateTime | string |  |  
action\_result\.data\.\*\.value\.\*\.id | string |  `user id`  |   49233413\-24c6\-4516\-a9e1\-4d5f87fe34fd 
action\_result\.data\.\*\.value\.\*\.isAssignableToRole | string |  |  
action\_result\.data\.\*\.value\.\*\.mail | string |  |   test\@user\.onmicrosoft\.com 
action\_result\.data\.\*\.value\.\*\.mailEnabled | boolean |  |   True 
action\_result\.data\.\*\.value\.\*\.mailNickname | string |  |   TestgroupforMSGraph 
action\_result\.data\.\*\.value\.\*\.membershipRule | string |  |  
action\_result\.data\.\*\.value\.\*\.membershipRuleProcessingState | string |  |  
action\_result\.data\.\*\.value\.\*\.onPremisesDomainName | string |  |  
action\_result\.data\.\*\.value\.\*\.onPremisesLastSyncDateTime | string |  |  
action\_result\.data\.\*\.value\.\*\.onPremisesNetBiosName | string |  |  
action\_result\.data\.\*\.value\.\*\.onPremisesSamAccountName | string |  |  
action\_result\.data\.\*\.value\.\*\.onPremisesSecurityIdentifier | string |  |  
action\_result\.data\.\*\.value\.\*\.onPremisesSyncEnabled | string |  |  
action\_result\.data\.\*\.value\.\*\.preferredDataLocation | string |  |  
action\_result\.data\.\*\.value\.\*\.preferredLanguage | string |  |  
action\_result\.data\.\*\.value\.\*\.renewedDateTime | string |  |   2022\-02\-25T12\:05\:22Z 
action\_result\.data\.\*\.value\.\*\.securityEnabled | boolean |  |   True 
action\_result\.data\.\*\.value\.\*\.securityIdentifier | string |  |   S\-1\-12\-1\-1227043859\-1159079110\-1598939561\-4248108679 
action\_result\.data\.\*\.value\.\*\.theme | string |  |  
action\_result\.data\.\*\.value\.\*\.visibility | string |  |   Private 
action\_result\.summary\.message | string |  |   User is member of group 
action\_result\.summary\.user\_in\_group | string |  |  
action\_result\.message | string |  |   User in group\: True 
summary\.total\_objects | numeric |  |   1 
summary\.total\_objects\_successful | numeric |  |   1   

## action: 'list directory roles'
List the directory roles that are activated in the tenant

Type: **investigate**  
Read only: **True**

<p>Pagination is not implemented for this action as this endpoint does not support pagination\. Here is the <b><a href='https\://docs\.microsoft\.com/en\-us/graph/paging' target='\_blank'>Documentation</a></b> for the same\.</p>

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action\_result\.status | string |  |   success  failed 
action\_result\.data\.\*\.deletedDateTime | string |  |  
action\_result\.data\.\*\.deletionTimestamp | string |  |  
action\_result\.data\.\*\.description | string |  |   Can read basic directory information\. For granting access to applications, not intended for users\. 
action\_result\.data\.\*\.displayName | string |  |   Directory Readers 
action\_result\.data\.\*\.id | string |  `directory object id`  |   02b238cb\-0d15\-454b\-aae6\-0e94993a3207 
action\_result\.data\.\*\.isSystem | boolean |  |   True  False 
action\_result\.data\.\*\.objectType | string |  |   Role 
action\_result\.data\.\*\.odata\.type | string |  |   Microsoft\.DirectoryServices\.DirectoryRole 
action\_result\.data\.\*\.roleTemplateId | string |  `role template id`  |   88d8e3e3\-8f55\-4a1e\-953a\-9b9898b8876b 
action\_result\.summary\.num\_directory\_roles | numeric |  |   9 
action\_result\.message | string |  |   Num directory roles\: 9 
summary\.total\_objects | numeric |  |   1 
summary\.total\_objects\_successful | numeric |  |   1   

## action: 'generate token'
Generate a token or regenerates token when the token expires

Type: **generic**  
Read only: **False**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action\_result\.status | string |  |   success  failed 
action\_result\.data | string |  |  
action\_result\.summary | string |  |  
action\_result\.message | string |  |   Token generated 
summary\.total\_objects | numeric |  |   1 
summary\.total\_objects\_successful | numeric |  |   1 