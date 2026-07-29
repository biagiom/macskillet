"""Shared primitives used by both the native and cross-platform pipelines."""

from macskillet.common.strings import (
    SUSPICIOUS_PATTERNS,
    Risk,
    StringPattern,
    count_categories,
    extract_strings_of_interest,
    is_base64,
    iter_strings,
    read_strings,
    scan,
)

__all__ = [
    "SUSPICIOUS_PATTERNS",
    "Risk",
    "StringPattern",
    "count_categories",
    "extract_strings_of_interest",
    "is_base64",
    "iter_strings",
    "read_strings",
    "scan",
]
