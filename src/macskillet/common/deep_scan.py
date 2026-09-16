#!/usr/bin/env python3
"""
deep_scan.py — Bucketing/selection logic for --deep bundle-internal scanning.

Both pipelines already collect ``bundle_info["all_binaries"]`` (every Mach-O
found under the bundle) and ``bundle_info["embedded_scripts"]`` (script files
by extension) as a byproduct of the existing bundle walk. This module decides
*which* of those candidates get statically analyzed when a caller requests a
deep scan with a limit, and in what priority order — it does not implement the
per-item analysis itself, since that differs by backend (native vs. LIEF).

Priority order, filled in sequence until the limit is reached:
  1. AppleScript files  (.scpt / .applescript / .scptd) — common ClickFix Chain-B vector
  2. Dylibs              (path ends .dylib, or lives under a .framework/ dir)
  3. Other Mach-O binaries (helper tools, XPC services, framework executables)
"""

from __future__ import annotations

import os

from macskillet.common.strings import iter_strings, scan

#: .scptd is a script *bundle* (a directory containing
#: Contents/Resources/Scripts/main.scpt), not a plain file — the bundle
#: analyzers record the bundle path itself, and scan_applescript_item()
#: below resolves it to that inner file before reading.
APPLESCRIPT_EXTENSIONS = (".scpt", ".applescript", ".scptd")
_SCPTD_INNER_SCRIPT = os.path.join("Contents", "Resources", "Scripts", "main.scpt")

#: Categories that revoke signing trust when found in a deep-scanned item
#: (mirrors common.signature_trust._SUSPICIOUS_CATEGORIES).
_TRUST_REVOKING_CATEGORIES = frozenset({
    "gatekeeper_bypass", "automation", "download_execute",
    "cloud_c2_exfil", "malware_family_marker",
})

# 0xFADEDEAD — marker in run-only (source-stripped) AppleScript script data.
_APPLESCRIPT_RUNONLY_MAGIC = b"\xfa\xde\xde\xad"
# Header of compiled AppleScript (.scpt) data.
_APPLESCRIPT_COMPILED_MAGIC = b"FasdUAS"


def scan_runonly_applescript(data: bytes) -> dict:
    """Detect run-only / compiled AppleScript embedded in a byte blob.

    Run-only AppleScript has its source stripped and carries the 0xFADEDEAD
    marker; `osadecompile` cannot recover it. AMOS/ClickFix payloads ship
    run-only applets to hide their logic from static analysis, so the marker
    itself is a high-value obfuscation signal. Pure byte matching — no macOS
    calls — so it lives here rather than under native/, where both pipelines
    (and native's own obfuscation_detector.py) can share one copy.
    """
    runonly = _APPLESCRIPT_RUNONLY_MAGIC in data
    compiled = _APPLESCRIPT_COMPILED_MAGIC in data
    indicators = []
    if runonly:
        indicators.append(
            "0xFADEDEAD run-only AppleScript marker — source stripped, osadecompile fails"
        )
    if compiled:
        indicators.append("FasdUAS compiled-AppleScript header")
    return {
        "runonly_applescript": runonly,
        "compiled_applescript": compiled,
        "indicators": indicators,
        "detail": "; ".join(indicators) if indicators else "no AppleScript script data found",
    }


#: Read caps matching native's original inline implementation this function replaces.
_MAIN_BINARY_READ_LIMIT = 2_000_000
_BUNDLE_SCRIPT_READ_LIMIT = 1_000_000


def scan_applescript_analysis(main_binary_path: str, applescript_paths: list[str]) -> dict:
    """Combined run-only/compiled-AppleScript analysis across a main binary and
    a set of bundle AppleScript files (already filtered to AppleScript-flavored
    extensions, e.g. via ``APPLESCRIPT_EXTENSIONS`` or ``bucket_candidates``).

    Shared by both pipelines' main-binary analysis — this is the same check
    already run per-item inside a --deep scan (``scan_applescript_item``), just
    combined across the main binary plus every bundle script into one result,
    for callers that want this signal without requesting a full --deep scan.
    A ``.scptd`` entry is resolved to its inner compiled script first, same as
    ``scan_applescript_item``. Unreadable paths are skipped rather than raising
    — a missing or unreadable bundle script isn't grounds to abort the rest of
    the analysis.
    """
    combined = {"runonly_applescript": False, "compiled_applescript": False, "indicators": []}

    blobs = []
    try:
        with open(main_binary_path, "rb") as f:
            blobs.append(f.read(_MAIN_BINARY_READ_LIMIT))
    except OSError:
        pass

    for path in applescript_paths:
        resolved = path
        if resolved.lower().endswith(".scptd") and os.path.isdir(resolved):
            resolved = os.path.join(resolved, _SCPTD_INNER_SCRIPT)
        try:
            with open(resolved, "rb") as f:
                blobs.append(f.read(_BUNDLE_SCRIPT_READ_LIMIT))
        except OSError:
            pass

    for blob in blobs:
        r = scan_runonly_applescript(blob)
        combined["runonly_applescript"] = combined["runonly_applescript"] or r["runonly_applescript"]
        combined["compiled_applescript"] = combined["compiled_applescript"] or r["compiled_applescript"]
        combined["indicators"].extend(i for i in r["indicators"] if i not in combined["indicators"])

    combined["detail"] = (
        "; ".join(combined["indicators"]) if combined["indicators"]
        else "no AppleScript script data found"
    )
    return combined


def bucket_candidates(
    all_binaries: list[str],
    embedded_scripts: list[str],
    main_binary: str | None = None,
) -> dict[str, list[str]]:
    """Classify bundle-internal candidates into applescript/dylib/binary buckets.

    ``main_binary`` (already analyzed separately as the main executable) is
    excluded from the candidate pool if present in ``all_binaries``.
    """
    applescript = [
        p for p in embedded_scripts
        if p.lower().endswith(APPLESCRIPT_EXTENSIONS)
    ]

    dylib = []
    binary = []
    for path in all_binaries:
        if path == main_binary:
            continue
        if path.lower().endswith(".dylib") or ".framework/" in path:
            dylib.append(path)
        else:
            binary.append(path)

    return {"applescript": applescript, "dylib": dylib, "binary": binary}


def select_within_limit(
    buckets: dict[str, list[str]],
    limit: int,
) -> tuple[list[tuple[str, str]], dict[str, int]]:
    """Fill from buckets in priority order (applescript, dylib, binary) up to ``limit``.

    Returns ``(selected, skipped_by_kind)`` where ``selected`` is a list of
    ``(path, kind)`` tuples in priority order, and ``skipped_by_kind`` counts
    candidates that didn't fit within the limit, keyed by bucket name.
    """
    selected: list[tuple[str, str]] = []
    skipped_by_kind: dict[str, int] = {}
    remaining = max(limit, 0)

    for kind in ("applescript", "dylib", "binary"):
        candidates = buckets.get(kind, [])
        take = candidates[:remaining]
        skip = candidates[remaining:]
        selected.extend((path, kind) for path in take)
        remaining -= len(take)
        if skip:
            skipped_by_kind[kind] = len(skip)

    return selected, skipped_by_kind


def scan_applescript_item(path: str) -> dict:
    """Analyze one embedded AppleScript file or .scptd script bundle. Identical
    on both pipelines — pure byte/string content analysis, no Mach-O parsing
    involved.

    A .scptd path is a directory; resolve it to its inner compiled script
    (Contents/Resources/Scripts/main.scpt) before reading. Plain .scpt/
    .applescript files are read as-is.
    """
    if path.lower().endswith(".scptd") and os.path.isdir(path):
        path = os.path.join(path, _SCPTD_INNER_SCRIPT)
    with open(path, "rb") as f:
        data = f.read()
    return {
        "strings_of_interest": scan(list(iter_strings(data))),
        "applescript_analysis": scan_runonly_applescript(data),
    }


def _is_flagged(analysis: dict) -> bool:
    if analysis.get("applescript_analysis", {}).get("runonly_applescript"):
        return True
    return any(
        f.get("category") in _TRUST_REVOKING_CATEGORIES
        for f in analysis.get("strings_of_interest", [])
    )


def build_deep_scan_result(
    scanned: list[dict],
    skipped_by_kind: dict[str, int],
    limit: int,
) -> dict:
    """Assemble the final ``features["deep_scan"]`` dict from per-item results.

    ``scanned`` entries are ``{"path", "kind", "analysis"}`` (or ``"error"``
    instead of ``"analysis"`` if that item's analysis raised). Identical
    assembly logic on both pipelines — only how each entry's ``analysis`` was
    produced differs (backend-specific Mach-O analysis vs. the shared
    :func:`scan_applescript_item`).
    """
    skipped_count = sum(skipped_by_kind.values())
    flagged = [e["path"] for e in scanned if _is_flagged(e.get("analysis", {}))]
    summary = (
        f"{len(scanned)} embedded item(s) scanned, {skipped_count} skipped"
        + (f", {len(flagged)} flagged: {', '.join(os.path.basename(p) for p in flagged)}"
           if flagged else "")
        + "."
    )
    return {
        "enabled": True,
        "limit": limit,
        "scanned": scanned,
        "skipped_count": skipped_count,
        "skipped_by_kind": skipped_by_kind,
        "summary": summary,
    }
