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
import ast
import unittest
from pathlib import Path
from types import SimpleNamespace


CONNECTOR = Path(__file__).resolve().parents[1] / "msadgraph_connector.py"
NOW = 1_700_000_000


def _load_token_policy():
    source = CONNECTOR.read_text()
    tree = ast.parse(source)
    connector = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "MSADGraphConnector")
    methods = [node for node in connector.body if isinstance(node, ast.FunctionDef) and node.name in {"_get_token", "_make_rest_call_helper"}]
    policy = ast.ClassDef(name="TokenPolicy", bases=[], keywords=[], body=methods, decorator_list=[])
    namespace = {
        "time": SimpleNamespace(time=lambda: NOW),
        "phantom": SimpleNamespace(APP_SUCCESS=0, APP_ERROR=-1, is_fail=lambda status: status != 0),
        "RetVal": lambda status, response: (status, response),
        "MS_AZURE_TOKEN_STRING": "token",
        "MS_AZURE_ACCESS_TOKEN_STRING": "access_token",
        "MS_AZURE_REFRESH_TOKEN_STRING": "refresh_token",
        "MS_AZURE_EXPIRES_IN_STRING": "expires_in",
        "MS_AZURE_EXPIRES_AT_STRING": "expires_at",
        "MS_AZURE_TOKEN_EXPIRY_BUFFER": 60,
        "MS_AZURE_CODE_GENERATION_SCOPE": "scope",
        "SERVER_TOKEN_URL": "https://login.microsoftonline.com/{0}/oauth2/v2.0/token",
    }
    exec(compile(ast.fix_missing_locations(ast.Module(body=[policy], type_ignores=[])), str(CONNECTOR), "exec"), namespace)
    return namespace["TokenPolicy"]


class ActionResult:
    def __init__(self):
        self.status = 0
        self.message = None

    def set_status(self, status, message):
        self.status = status
        self.message = message
        return status

    def get_status(self):
        return self.status

    def get_message(self):
        return self.message


class TokenExpiryTests(unittest.TestCase):
    def _connector(self, token, admin_access=True, token_status=0):
        policy = _load_token_policy()

        class Connector(policy):
            def __init__(self):
                self._state = {"token": token, "redirect_uri": "https://soar.example/result"}
                self._base_url = "https://graph.microsoft.com/v1.0"
                self._tenant = "tenant"
                self._client_id = "client"
                self._client_secret = ""
                self._access_token = token.get("access_token")
                self._refresh_token = token.get("refresh_token")
                self._admin_access_required = admin_access
                self._admin_access_granted = admin_access
                self.calls = []
                self.progress = []

            def save_progress(self, message):
                self.progress.append(message)

            def debug_print(self, *args):
                pass

            def _make_rest_call(self, endpoint, action_result, verify=True, headers=None, params=None, data=None, json=None, method="get"):
                self.calls.append({"method": method, "headers": dict(headers or {}), "data": data})
                if method == "post":
                    if token_status:
                        return action_result.set_status(token_status, "Token request failed"), None
                    return 0, {"access_token": "new-token", "refresh_token": "new-refresh", "expires_in": 3600}
                return 0, {"value": []}

        return Connector()

    def test_legacy_token_refreshes_before_graph_request(self):
        connector = self._connector({"access_token": "old-token", "refresh_token": "old-refresh"}, admin_access=False)

        status, response = connector._make_rest_call_helper(ActionResult(), "/users")

        self.assertEqual(status, 0)
        self.assertEqual(response, {"value": []})
        self.assertEqual([call["method"] for call in connector.calls], ["post", "get"])
        self.assertEqual(connector.calls[0]["data"]["grant_type"], "refresh_token")
        self.assertEqual(connector.calls[1]["headers"]["Authorization"], "Bearer new-token")
        self.assertEqual(connector._state["token"]["expires_at"], NOW + 3540)

    def test_legacy_token_without_refresh_credentials_is_reused(self):
        connector = self._connector({"access_token": "current-token"}, admin_access=False)

        status, _ = connector._make_rest_call_helper(ActionResult(), "/users")

        self.assertEqual(status, 0)
        self.assertEqual([call["method"] for call in connector.calls], ["get"])
        self.assertEqual(connector.calls[0]["headers"]["Authorization"], "Bearer current-token")

    def test_valid_token_is_reused(self):
        connector = self._connector({"access_token": "current-token", "expires_at": NOW + 120})

        status, _ = connector._make_rest_call_helper(ActionResult(), "/users")

        self.assertEqual(status, 0)
        self.assertEqual([call["method"] for call in connector.calls], ["get"])
        self.assertEqual(connector.calls[0]["headers"]["Authorization"], "Bearer current-token")

    def test_success_does_not_retry_for_stale_error_message(self):
        connector = self._connector({"access_token": "current-token", "expires_at": NOW + 120})
        action_result = ActionResult()
        action_result.message = "token expired"

        status, _ = connector._make_rest_call_helper(action_result, "/users")

        self.assertEqual(status, 0)
        self.assertEqual([call["method"] for call in connector.calls], ["get"])

    def test_expired_token_refreshes_before_graph_request(self):
        connector = self._connector({"access_token": "old-token", "expires_at": NOW})

        status, _ = connector._make_rest_call_helper(ActionResult(), "/users")

        self.assertEqual(status, 0)
        self.assertEqual([call["method"] for call in connector.calls], ["post", "get"])
        self.assertEqual(connector.calls[1]["headers"]["Authorization"], "Bearer new-token")

    def test_failed_refresh_does_not_call_graph(self):
        connector = self._connector({"access_token": "old-token", "expires_at": NOW - 1}, token_status=-1)

        status, response = connector._make_rest_call_helper(ActionResult(), "/users")

        self.assertEqual(status, -1)
        self.assertIsNone(response)
        self.assertEqual([call["method"] for call in connector.calls], ["post"])


if __name__ == "__main__":
    unittest.main()
