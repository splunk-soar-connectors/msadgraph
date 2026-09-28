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
import math
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
        "math": math,
        "MS_AZURE_CODE_GENERATION_SCOPE": "scope",
        "SERVER_TOKEN_URL": "https://login.microsoftonline.com/{0}/oauth2/v2.0/token",
    }
    exec(compile(ast.fix_missing_locations(ast.Module(body=[policy], type_ignores=[])), str(CONNECTOR), "exec"), namespace)
    return namespace["TokenPolicy"]


class ActionResult:
    def __init__(self):
        self.status = 0
        self.message = None

    def set_status(self, status, message=None):
        self.status = status
        self.message = message
        return status

    def get_status(self):
        return self.status

    def get_message(self):
        return self.message


class TokenExpiryTests(unittest.TestCase):
    def _connector(self, token, admin_access=True, token_status=0, graph_error_message=None, token_response=None):
        policy = _load_token_policy()
        if token_response is None:
            token_response = {"access_token": "new-token", "refresh_token": "new-refresh", "expires_in": 3600}

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
                self.graph_failure_sent = False

            def save_progress(self, message):
                self.progress.append(message)

            def debug_print(self, *args):
                pass

            def _make_rest_call(self, endpoint, action_result, verify=True, headers=None, params=None, data=None, json=None, method="get"):
                self.calls.append({"endpoint": endpoint, "method": method, "headers": dict(headers or {}), "data": data, "json": json})
                if endpoint.startswith("https://login.microsoftonline.com/"):
                    if token_status:
                        return action_result.set_status(token_status, "Token request failed"), None
                    return 0, dict(token_response)
                if graph_error_message and not self.graph_failure_sent:
                    self.graph_failure_sent = True
                    return action_result.set_status(-1, graph_error_message), None
                return 0, {"value": []}

        return Connector()

    def test_legacy_token_with_refresh_credentials_is_reused(self):
        connector = self._connector({"access_token": "current-token", "refresh_token": "old-refresh"}, admin_access=False, token_status=-1)

        status, response = connector._make_rest_call_helper(ActionResult(), "/users")

        self.assertEqual(status, 0)
        self.assertEqual(response, {"value": []})
        self.assertEqual([call["method"] for call in connector.calls], ["get"])
        self.assertEqual(connector.calls[0]["headers"]["Authorization"], "Bearer current-token")

    def test_expired_legacy_token_refreshes_after_graph_rejection(self):
        connector = self._connector(
            {"access_token": "old-token", "refresh_token": "old-refresh"},
            admin_access=False,
            graph_error_message="401 InvalidAuthenticationToken: Invalid token lifetime",
        )

        action_result = ActionResult()
        status, response = connector._make_rest_call_helper(action_result, "/users")

        self.assertEqual(status, 0)
        self.assertEqual(response, {"value": []})
        self.assertEqual([call["method"] for call in connector.calls], ["get", "post", "get"])
        self.assertEqual(connector.calls[1]["data"]["grant_type"], "refresh_token")
        self.assertEqual(connector.calls[2]["headers"]["Authorization"], "Bearer new-token")
        self.assertEqual(connector._state["token"]["expires_at"], NOW + 3540)
        self.assertEqual(action_result.get_status(), 0)
        self.assertFalse(action_result.get_message())

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

    def test_malformed_cached_expiry_uses_graph_and_reactive_refresh(self):
        for expires_at in ("invalid", {"value": NOW}, True):
            with self.subTest(expires_at=expires_at):
                connector = self._connector(
                    {"access_token": "old-token", "refresh_token": "old-refresh", "expires_at": expires_at},
                    admin_access=False,
                    graph_error_message="401 InvalidAuthenticationToken: Invalid token lifetime",
                )

                status, response = connector._make_rest_call_helper(ActionResult(), "/users")

                self.assertEqual((status, response), (0, {"value": []}))
                self.assertEqual([call["method"] for call in connector.calls], ["get", "post", "get"])
                self.assertEqual(connector.calls[2]["headers"]["Authorization"], "Bearer new-token")

    def test_malformed_token_lifetime_does_not_block_graph_request(self):
        for expires_in in ("invalid", {}, True, float("nan"), float("inf"), 10**400, 0):
            with self.subTest(expires_in=expires_in):
                connector = self._connector(
                    {"access_token": "old-token", "expires_at": NOW - 1},
                    token_response={"access_token": "new-token", "expires_in": expires_in},
                )

                status, response = connector._make_rest_call_helper(ActionResult(), "/users")

                self.assertEqual((status, response), (0, {"value": []}))
                self.assertEqual([call["method"] for call in connector.calls], ["post", "get"])
                self.assertNotIn("expires_at", connector._state["token"])

    def test_numeric_string_token_lifetime_records_expiry(self):
        connector = self._connector(
            {"access_token": "old-token", "expires_at": NOW - 1},
            token_response={"access_token": "new-token", "expires_in": "3600"},
        )

        status, _ = connector._make_rest_call_helper(ActionResult(), "/users")

        self.assertEqual(status, 0)
        self.assertEqual(connector._state["token"]["expires_at"], NOW + 3540)

    def test_successful_mutation_does_not_retry_for_stale_error_message(self):
        connector = self._connector({"access_token": "current-token", "expires_at": NOW + 120})
        action_result = ActionResult()
        action_result.message = "InvalidAuthenticationToken: Invalid token lifetime"

        status, _ = connector._make_rest_call_helper(action_result, "/users", method="post")

        self.assertEqual(status, 0)
        self.assertEqual([call["method"] for call in connector.calls], ["post"])
        self.assertTrue(connector.calls[0]["endpoint"].endswith("/users"))

    def test_invalid_token_lifetime_refreshes_and_retries(self):
        for error_message in (
            "401 InvalidAuthenticationToken: Invalid token lifetime",
            "401 InvalidAuthenticationToken",
            "401 Invalid token lifetime",
        ):
            with self.subTest(error_message=error_message):
                connector = self._connector(
                    {"access_token": "old-token", "refresh_token": "old-refresh", "expires_at": NOW + 120},
                    admin_access=False,
                    graph_error_message=error_message,
                )

                status, response = connector._make_rest_call_helper(ActionResult(), "/users")

                self.assertEqual(status, 0)
                self.assertEqual(response, {"value": []})
                self.assertEqual([call["method"] for call in connector.calls], ["get", "post", "get"])
                self.assertEqual(connector.calls[1]["data"]["grant_type"], "refresh_token")
                self.assertEqual(connector.calls[2]["headers"]["Authorization"], "Bearer new-token")

    def test_other_graph_error_does_not_refresh_or_retry(self):
        connector = self._connector(
            {"access_token": "current-token", "expires_at": NOW + 120},
            graph_error_message="403 Authorization_RequestDenied: Insufficient privileges",
        )

        status, response = connector._make_rest_call_helper(ActionResult(), "/users")

        self.assertEqual(status, -1)
        self.assertIsNone(response)
        self.assertEqual([call["method"] for call in connector.calls], ["get"])

    def test_mutating_request_retries_once_with_original_body_after_token_rejection(self):
        connector = self._connector(
            {"access_token": "old-token", "refresh_token": "old-refresh", "expires_at": NOW + 120},
            admin_access=False,
            graph_error_message="401 InvalidAuthenticationToken: Invalid token lifetime",
        )
        body = {"accountEnabled": False}

        status, response = connector._make_rest_call_helper(ActionResult(), "/users/user-id", method="patch", json=body)

        self.assertEqual(status, 0)
        self.assertEqual(response, {"value": []})
        self.assertEqual([call["method"] for call in connector.calls], ["patch", "post", "patch"])
        self.assertEqual([connector.calls[index]["json"] for index in (0, 2)], [body, body])
        self.assertEqual(connector.calls[0]["headers"]["Authorization"], "Bearer old-token")
        self.assertEqual(connector.calls[2]["headers"]["Authorization"], "Bearer new-token")

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

    def test_failed_refresh_after_graph_rejection_does_not_retry(self):
        connector = self._connector(
            {"access_token": "old-token", "refresh_token": "old-refresh"},
            admin_access=False,
            token_status=-1,
            graph_error_message="401 InvalidAuthenticationToken: Invalid token lifetime",
        )
        action_result = ActionResult()

        status, response = connector._make_rest_call_helper(action_result, "/users")

        self.assertEqual(status, -1)
        self.assertIsNone(response)
        self.assertEqual(action_result.get_message(), "Token request failed")
        self.assertEqual([call["method"] for call in connector.calls], ["get", "post"])
        self.assertEqual(connector._access_token, "old-token")

    def test_missing_delegated_token_without_refresh_credentials_fails_before_graph(self):
        connector = self._connector({}, admin_access=False)

        status, response = connector._make_rest_call_helper(ActionResult(), "/users")

        self.assertEqual(status, -1)
        self.assertIsNone(response)
        self.assertEqual(connector.calls, [])


if __name__ == "__main__":
    unittest.main()
