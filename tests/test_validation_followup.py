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

    def test_start_oauth_requires_the_pending_flow_nonce(self):
        source = _function_source("_handle_login_redirect")
        self.assertIn('request.GET.get("state_nonce", "")', source)
        self.assertIn("hmac.compare_digest(stored_nonce, presented_nonce)", source)

    def test_start_oauth_link_carries_the_pending_flow_nonce(self):
        source = CONNECTOR.read_text()
        self.assertIn("'state_nonce': oauth_state_nonce", source)
