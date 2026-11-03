# Copyright (c) 2026 Splunk Inc.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
from typing import Any
from urllib.parse import quote, unquote


def quote_path_segment(value: str) -> str:
    raw_value = str(value)
    canonical_value = raw_value
    for _ in range(5):
        decoded_value = unquote(canonical_value)
        if decoded_value == canonical_value:
            break
        canonical_value = decoded_value
    if canonical_value in {".", ".."}:
        raise ValueError("Microsoft Graph path identifiers must not be dot segments")
    return quote(raw_value, safe="")


def normalize_odata_object(value: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(value)
    odata = {
        key.removeprefix("@odata."): item
        for key, item in value.items()
        if key.startswith("@odata.")
    }
    if odata:
        existing = normalized.get("odata", {})
        if isinstance(existing, dict):
            normalized["odata"] = {**odata, **existing}
    return normalized


def normalize_odata(value: Any) -> Any:
    if isinstance(value, list):
        return [normalize_odata(item) for item in value]
    if not isinstance(value, dict):
        return value
    normalized = {key: normalize_odata(item) for key, item in value.items()}
    odata = {
        key.removeprefix("@odata."): normalize_odata(item)
        for key, item in value.items()
        if key.startswith("@odata.")
    }
    if odata:
        existing = normalized.get("odata", {})
        if isinstance(existing, dict):
            normalized["odata"] = {**odata, **existing}
    return normalized
