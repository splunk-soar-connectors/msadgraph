# Copyright (c) 2026 Splunk Inc.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
from typing import Any

from soar_sdk.action_results import ActionOutput, OutputField


class OdataOutput(ActionOutput):
    type: str = OutputField()
    context: str = OutputField()
    nextLink: str = OutputField()


def normalize_odata(value: Any) -> Any:
    """Add nested annotation aliases without replacing Graph's original fields."""
    if isinstance(value, list):
        return [normalize_odata(item) for item in value]
    if not isinstance(value, dict):
        return value

    normalized = {key: normalize_odata(item) for key, item in value.items()}
    aliases = {
        key.removeprefix("@odata."): normalized[key]
        for key in value
        if key.startswith("@odata.") and key != "@odata."
    }
    if aliases:
        existing = normalized.get("odata", {})
        if isinstance(existing, dict):
            normalized["odata"] = {**aliases, **existing}
    return normalized
