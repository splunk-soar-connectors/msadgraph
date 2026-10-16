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
from typing import Any

import httpx


def get_graph_response(
    response: httpx.Response, *, allow_empty: bool = False
) -> dict[str, Any]:
    """Parse a Graph object response or report its HTTP/API failure."""
    if allow_empty and not response.content and response.is_success:
        return {}

    try:
        payload = response.json()
    except ValueError as error:
        if response.is_success:
            raise RuntimeError(
                "Unable to parse JSON response from Microsoft Graph"
            ) from error
        response.raise_for_status()
        raise

    if not response.is_success:
        detail: object = payload
        graph_error = payload.get("error") if isinstance(payload, dict) else None
        if isinstance(graph_error, dict):
            detail = graph_error.get("message") or graph_error
        elif graph_error:
            detail = graph_error
        raise RuntimeError(
            "Error from server. "
            f"Status Code: {response.status_code}. "
            f"Data from server: \n{detail}\n"
        )

    if not isinstance(payload, dict):
        raise RuntimeError("Microsoft Graph returned a non-object JSON response")
    return payload
