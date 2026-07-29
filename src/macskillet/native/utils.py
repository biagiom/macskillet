#!/usr/bin/env python3
"""
utils.py — Shared utilities for the macOS native analysis stack.
"""

import collections
import json
import math
import re


def _entropy(data: bytes) -> float:
    """Shannon entropy of a byte sequence. Returns 0.0 for empty input."""
    if not data:
        return 0.0
    counts = collections.Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _parse_json_verdict(text: str) -> dict | None:
    """Extract a JSON verdict dict from LLM output text.

    Tries fenced ```json``` blocks, generic ``` blocks, inline {..."verdict"...},
    and finally the whole text as JSON.
    """
    if not text:
        return None
    for pattern in [
        r"```json\s*(\{.*?\})\s*```",
        r"```\s*(\{.*?\})\s*```",
        r"(\{[^{}]*\"verdict\"[^{}]*\})",
    ]:
        match = re.search(pattern, text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1))
            except json.JSONDecodeError:
                continue
    try:
        return json.loads(text.strip())
    except json.JSONDecodeError:
        return None
