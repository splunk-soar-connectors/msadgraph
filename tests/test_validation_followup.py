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
import json
import types
import unittest
import urllib.parse
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONNECTOR = ROOT / "msadgraph_connector.py"
MANIFEST = ROOT / "msadgraph.json"


def _load_quote_helper():
    tree = ast.parse(CONNECTOR.read_text())
    helper = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "_quote_path_segment")
    namespace = {"urlparse": urllib.parse}
    exec(compile(ast.fix_missing_locations(ast.Module(body=[helper], type_ignores=[])), str(CONNECTOR), "exec"), namespace)
    return namespace["_quote_path_segment"]


def _function_source(name):
    tree = ast.parse(CONNECTOR.read_text())
    helper = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name)
    return ast.get_source_segment(CONNECTOR.read_text(), helper)


def _load_connector_method(name, namespace):
    tree = ast.parse(CONNECTOR.read_text())
    connector_class = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "MSADGraphConnector")
    method = next(node for node in connector_class.body if isinstance(node, ast.FunctionDef) and node.name == name)
    exec(compile(ast.fix_missing_locations(ast.Module(body=[method], type_ignores=[])), str(CONNECTOR), "exec"), namespace)
    return namespace[name]


class _FakeActionResult:
    def __init__(self, param):
        self.param = param
        self.data = []
        self.summary = {}
        self.message = None

    def add_data(self, data):
        self.data.append(data)

    def update_summary(self, summary):
        self.summary = summary
        return self.summary

    def set_status(self, status, message=None):
        self.message = message
        return status


class _FakeResetPasswordConnector:
    def __init__(self, rest_status="success"):
        self.action_result = None
        self.rest_status = rest_status
        self.rest_request = None

    def save_progress(self, _message):
        return None

    def get_action_identifier(self):
        return "reset_password"

    def add_action_result(self, action_result):
        self.action_result = action_result
        return action_result

    def get_container_id(self):
        return 42

    def _get_error_message_from_exception(self, exc):
        return str(exc)

    def _make_rest_call_helper(self, action_result, endpoint, **kwargs):
        self.rest_request = (action_result, endpoint, kwargs)
        return self.rest_status, None


class ValidationFollowupTests(unittest.TestCase):
    def test_quote_path_segment_rejects_encoded_dot_segments(self):
        for value in (".", "..", "%2e", "%2E%2e", "%252e%252e"):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "must not be dot segments"):
                _load_quote_helper()(value)

    def test_quote_path_segment_preserves_opaque_identifiers(self):
        self.assertEqual(_load_quote_helper()("user/name@example.com"), "user%2Fname%40example.com")

    def test_disable_user_discloses_residual_access_token_lifetime(self):
        manifest = json.loads(MANIFEST.read_text())
        action = next(item for item in manifest["actions"] if item["identifier"] == "disable_user")
        self.assertIn("non-CAE resources may remain valid until they expire", action["description"])

    def test_oauth_handoff_uses_connector_state_api(self):
        source = CONNECTOR.read_text()
        self.assertIn("connector.load_state()", source)
        self.assertIn("connector.save_state(state)", source)

    def test_connector_module_has_one_base_connector_subclass(self):
        tree = ast.parse(CONNECTOR.read_text())
        connector_classes = [
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef) and any(isinstance(base, ast.Name) and base.id == "BaseConnector" for base in node.bases)
        ]
        self.assertEqual([node.name for node in connector_classes], ["MSADGraphConnector"])

    def test_temporary_password_is_replaced_by_a_vault_reference(self):
        manifest = json.loads(MANIFEST.read_text())
        action = next(item for item in manifest["actions"] if item["identifier"] == "reset_password")
        output_types = {item["data_path"]: item["data_type"] for item in action["output"]}
        self.assertNotIn("action_result.parameter.temp_password", output_types)
        self.assertEqual(output_types["action_result.data.*.temp_password_vault_id"], "string")
        self.assertEqual(output_types["action_result.summary.temp_password_vault_id"], "string")

        tree = ast.parse(CONNECTOR.read_text())
        connector_class = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "MSADGraphConnector")
        method = next(node for node in connector_class.body if isinstance(node, ast.FunctionDef) and node.name == "_handle_reset_password")
        source = ast.get_source_segment(CONNECTOR.read_text(), method)
        self.assertIn('safe_param.pop("temp_password", None)', source)
        self.assertIn("Vault.create_attachment", source)
        self.assertIn('temp_password.encode("utf-8")', source)
        self.assertIn('action_result.add_data({"temp_password_vault_id": vault_id})', source)

    def test_reset_password_returns_temp_password_vault_id(self):
        class FakeVault:
            call = None

            @classmethod
            def create_attachment(cls, contents, container_id, file_name):
                cls.call = (contents, container_id, file_name)
                return {"succeeded": True, "vault_id": "vault-reference"}

        phantom = types.SimpleNamespace(APP_SUCCESS="success", APP_ERROR="error", is_fail=lambda status: status != "success")
        handler = _load_connector_method(
            "_handle_reset_password",
            {
                "ActionResult": _FakeActionResult,
                "Vault": FakeVault,
                "phantom": phantom,
                "secrets": types.SimpleNamespace(token_hex=lambda _length: "0123456789abcdef"),
                "_quote_path_segment": urllib.parse.quote,
            },
        )
        connector = _FakeResetPasswordConnector()

        status = handler(
            connector,
            {"user_id": "user@example.com", "force_change": True, "temp_password": "Temporary secret"},
        )

        self.assertEqual(status, "success")
        self.assertEqual(
            FakeVault.call,
            (b"Temporary secret", 42, "msadgraph-temp-password-0123456789abcdef.txt"),
        )
        self.assertNotIn("temp_password", connector.action_result.param)
        self.assertEqual(connector.action_result.data, [{"temp_password_vault_id": "vault-reference"}])
        self.assertEqual(connector.action_result.summary["temp_password_vault_id"], "vault-reference")
        self.assertEqual(connector.rest_request[2]["json"]["passwordProfile"]["password"], "Temporary secret")

    def test_reset_password_stops_before_graph_when_vault_write_fails(self):
        class FakeVault:
            @staticmethod
            def create_attachment(_contents, _container_id, file_name):
                return {"succeeded": False, "vault_id": None, "file_name": file_name}

        phantom = types.SimpleNamespace(APP_SUCCESS="success", APP_ERROR="error", is_fail=lambda status: status != "success")
        handler = _load_connector_method(
            "_handle_reset_password",
            {
                "ActionResult": _FakeActionResult,
                "Vault": FakeVault,
                "phantom": phantom,
                "secrets": types.SimpleNamespace(token_hex=lambda _length: "0123456789abcdef"),
                "_quote_path_segment": urllib.parse.quote,
            },
        )
        connector = _FakeResetPasswordConnector()

        status = handler(connector, {"user_id": "user@example.com", "temp_password": "Temporary secret"})

        self.assertEqual(status, "error")
        self.assertIsNone(connector.rest_request)
        self.assertNotIn("temp_password", connector.action_result.param)

    def test_save_state_encrypts_a_copy(self):
        tree = ast.parse(CONNECTOR.read_text())
        connector_class = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "MSADGraphConnector")
        method = next(node for node in connector_class.body if isinstance(node, ast.FunctionDef) and node.name == "save_state")
        source = ast.get_source_segment(CONNECTOR.read_text(), method)
        self.assertIn("encrypted_state = _encrypt_state(copy.deepcopy(state)", source)
        self.assertIn("super().save_state(encrypted_state)", source)

    def test_oauth_flow_does_not_manage_state_files(self):
        source = CONNECTOR.read_text()
        self.assertNotIn("PHANTOM_APP_STATES", source)
        self.assertNotIn("set_app_file_perms", source)
        self.assertNotIn("tempfile", source)
