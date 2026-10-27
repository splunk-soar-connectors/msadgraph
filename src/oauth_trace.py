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
"""TEMPORARY diagnostic build: observe real SDK state operations, never replace them.

No locks, retries, state changes or simulated responses are added. State labels
are one-way hashes; token values and authorization codes are never serialized.
Remove this module and its app wiring after the authorized diagnostic run.
"""

import base64
import hashlib
import json
import os
import time
from urllib.parse import parse_qs, urlsplit

from soar_sdk.actions_manager import ActionsManager
from soar_sdk.app import App
from soar_sdk.shims.phantom.encryption_helper import encryption_helper


def state_labels(state: dict, asset_id: str) -> dict:
    partition = state.get("auth")
    auth = (
        partition
        if isinstance(partition, dict)
        else json.loads(encryption_helper.decrypt(partition, asset_id))
        if partition
        else {}
    )
    session = auth.get("oauth", {}).get("session") or {}
    url = auth.get("authorization_url") or ""

    def label(value):
        return (
            hashlib.sha256(value.encode()).hexdigest()[:16]
            if isinstance(value, str) and value
            else None
        )

    return {
        "nonce": label(auth.get("authorization_nonce")),
        "session": label(session.get("state")),
        "url": label(parse_qs(urlsplit(url).query).get("state", [None])[0]),
    }


class TraceActionsManager(ActionsManager):
    """Delegate each storage operation unchanged and record its safe boundaries."""

    def __init__(self):
        super().__init__()
        self.trace_asset_id = None
        self.trace_actor = "action"
        self.trace_events = []
        self.trace_errors = 0
        self.trace_dropped = 0

    def arm_trace(self, asset_id, actor):
        self.trace_asset_id = str(asset_id)
        self.trace_actor = actor
        self.trace_events = []
        self.trace_errors = 0
        self.trace_dropped = 0

    def _record(self, phase, snapshot=None, *, disk=False):
        if not self.trace_asset_id:
            return
        try:
            event = {"t": time.time_ns(), "seq": len(self.trace_events), "phase": phase}
            if snapshot is not None:
                event["state"] = state_labels(snapshot, self.trace_asset_id)
            if disk:
                # A direct read only: do not call SDK force_reload to observe it.
                current = super().load_state_from_file(self.trace_asset_id)
                event["disk"] = state_labels(current, self.trace_asset_id)
            if len(self.trace_events) < 500:
                self.trace_events.append(event)
            else:
                self.trace_dropped += 1
        except Exception:
            # Diagnostics must not replace an action failure with a tracing error.
            # Expose the count, never the exception text or the original state.
            self.trace_errors += 1

    def trace_frame(self, max_bytes=None):
        frame = {
            "pid": os.getpid(),
            "actor": self.trace_actor,
            "asset_id": self.trace_asset_id,
            "errors": self.trace_errors,
            "dropped": self.trace_dropped,
            "events": list(self.trace_events),
            "truncated": False,
        }
        while True:
            encoded = (
                base64.urlsafe_b64encode(
                    json.dumps(frame, separators=(",", ":")).encode()
                )
                .decode()
                .rstrip("=")
            )
            if max_bytes is None or len(encoded) <= max_bytes:
                return encoded
            frame["events"] = frame["events"][1:]
            frame["truncated"] = True

    def load_state_from_file(self, asset_id):
        result = super().load_state_from_file(asset_id)
        self._record("file.read", result)
        return result

    def reload_state_from_file(self, asset_id):
        self._record("reload.begin", disk=True)
        result = super().reload_state_from_file(asset_id)
        self._record("reload.end", result, disk=True)
        return result

    def save_state(self, state):
        self._record("save.begin", state, disk=True)
        result = super().save_state(state)
        self._record("save.end", state, disk=True)
        return result

    def save_state_to_file(self, asset_id, state):
        self._record("file.save.begin", state, disk=True)
        result = super().save_state_to_file(asset_id, state)
        self._record("file.save.end", state, disk=True)
        return result


class TraceApp(App):
    def handle_webhook(
        self, method, headers, path_parts, query, body, asset, soar_rest_client
    ):
        manager = self.actions_manager
        manager.arm_trace(soar_rest_client.asset_id, "webhook")
        response = super().handle_webhook(
            method, headers, path_parts, query, body, asset, soar_rest_client
        )
        # Transport only safe trace data; no new endpoint or authentication rule.
        # Bound the header below normal proxy limits.
        response["headers"].append(
            ("X-MSADGraph-OAuth-Trace", manager.trace_frame(max_bytes=6000))
        )
        return response
