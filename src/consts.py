# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

MICROSOFT_LOGIN_BASE_URLS = {
    "Global": "https://login.microsoftonline.com",
    "US Gov L4": "https://login.microsoftonline.us",
    "US Gov L5 (DOD)": "https://login.microsoftonline.us",
    "Germany": "https://login.microsoftonline.de",
    "China (21Vianet)": "https://login.chinacloudapi.cn",
}
MICROSOFT_GRAPH_BASE_URLS = {
    "Global": "https://graph.microsoft.com/v1.0",
    "US Gov L4": "https://graph.microsoft.us/v1.0",
    "US Gov L5 (DOD)": "https://dod-graph.microsoft.us/v1.0",
    "Germany": "https://graph.microsoft.de/v1.0",
    "China (21Vianet)": "https://microsoftgraph.chinacloudapi.cn/v1.0",
}

MICROSOFT_GRAPH_DELEGATED_SCOPE = (
    "offline_access Group.ReadWrite.All User.Read.All User.ReadWrite.All "
    "Directory.ReadWrite.All Directory.AccessAsUser.All "
    "User.ManageIdentities.All GroupMember.ReadWrite.All "
    "RoleManagement.ReadWrite.Directory Policy.Read.All "
    "Policy.ReadWrite.ConditionalAccess"
)
OAUTH_START_ROUTE = "oauth_start"
OAUTH_CALLBACK_ROUTE = "oauth_callback"

AUTHORIZATION_ERROR_STATE_KEY = "authorization_error"
AUTHORIZATION_URL_STATE_KEY = "authorization_url"
REDIRECT_URI_STATE_KEY = "redirect_uri"
AUTH_FLOW_MODE_STATE_KEY = "auth_flow_mode"
ADMIN_CONSENT_STATE_KEY = "admin_consent"
ADMIN_CONSENT_COMPLETE_STATE_KEY = "admin_consent_complete"
ADMIN_CONSENT_NONCE_STATE_KEY = "admin_consent_nonce"

AUTH_FLOW_MODE_DELEGATED = "delegated"
AUTH_FLOW_MODE_ADMIN_CONSENT = "admin_consent"

TEST_CONNECTIVITY_PASSED = "Test Connectivity Passed"
TEST_CONNECTIVITY_FAILED = "Test Connectivity Failed"
AUTHORIZATION_ERROR_MESSAGE = "Authorization code not received or not given"
ADMIN_CONSENT_ERROR_MESSAGE = "Admin consent not received"
