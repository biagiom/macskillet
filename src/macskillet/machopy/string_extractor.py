"""
string_extractor.py — suspicious-string extraction for the cross-platform pipeline.

This module is now a thin adapter. All pattern definitions, extraction and
ranking live in :mod:`macskillet.common.strings`, shared with the native
pipeline so the two cannot drift apart again.

The previous standalone implementation slurped whole files into memory, used
first-match-wins category assignment, and flagged unvalidated base64. On
Calculator.app it produced 3670 findings (3644 of them bogus base64) including
HIGH-risk ``command`` hits caused by ``chmod`` matching ``SwitchMode`` under
``re.IGNORECASE``. It now produces 6.
"""

from __future__ import annotations

from macskillet.common.strings import (
    DEFAULT_MAX_RESULTS,
    SUSPICIOUS_PATTERNS,
    count_categories,
    extract_strings_of_interest,
    read_strings,
    scan,
)

__all__ = [
    "DEFAULT_MAX_RESULTS",
    "SUSPICIOUS_PATTERNS",
    "extract_strings_of_interest",
    "extract_string_counts",
    "read_strings",
    "scan",
]


def extract_string_counts(binary_path: str) -> dict[str, int]:
    """Per-category counts for ``binary_path``, for ML feature vectors.

    Uses the same pattern table as :func:`extract_strings_of_interest`, so the
    numeric features and the agent-visible findings always agree.
    """
    try:
        return count_categories(read_strings(binary_path))
    except OSError:
        return {}
