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

    def test_temporary_password_remains_an_action_output(self):
        manifest = json.loads(MANIFEST.read_text())
        action = next(item for item in manifest["actions"] if item["identifier"] == "reset_password")
        output_paths = {item["data_path"] for item in action["output"]}
        self.assertIn("action_result.parameter.temp_password", output_paths)

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
