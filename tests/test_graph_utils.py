# Copyright (c) 2026 Splunk Inc.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
import pytest

from src.graph_utils import quote_path_segment


@pytest.mark.parametrize(
    "identifier,encoded",
    [
        ("user@example.com", "user%40example.com"),
        ("a/b?#%", "a%2Fb%3F%23%25"),
        ("a%2Fb", "a%252Fb"),
        ("display name", "display%20name"),
    ],
)
def test_identifier_is_one_encoded_path_segment(identifier, encoded):
    assert quote_path_segment(identifier) == encoded


@pytest.mark.parametrize("identifier", [".", "..", "%2e", "%2E%2e", "%252e%252e"])
def test_encoded_dot_segments_are_rejected(identifier):
    with pytest.raises(ValueError, match="must not be dot segments"):
        quote_path_segment(identifier)
