# Copyright (c) 2026 Splunk Inc.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
from collections.abc import Iterable
from typing import Any

from soar_sdk.action_results import ActionOutput, ActionResult
from soar_sdk.params import Params


def failed_result(
    params: Params,
    message: str,
    *,
    data: Iterable[dict[str, Any]] = (),
    summary: ActionOutput | None = None,
    exclude: set[str] | None = None,
) -> ActionResult:
    """Keep safe inputs and any retrieved data on a failed action result."""
    excluded = set(exclude or ())
    for name, field in type(params).model_fields.items():
        metadata = field.json_schema_extra
        if isinstance(metadata, dict) and metadata.get("sensitive"):
            excluded.add(name)
    result = ActionResult(False, message, params.model_dump(exclude=excluded))
    for record in data:
        result.add_data(record)
    if summary is not None:
        result.set_summary(summary.model_dump())
    return result
