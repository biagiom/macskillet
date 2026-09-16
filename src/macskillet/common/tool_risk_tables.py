#!/usr/bin/env python3
"""
tool_risk_tables.py — Shared risk-lookup tables for agent tools.

Both pipelines' entitlement and dylib-path risk assessment tools
(``get_entitlements``/``check_entitlement``, ``get_dylibs``) read from these
tables, so a risk classification can never drift between backends. Reconciled
from native's and portable's previously-separate, already-drifted copies
(748 vs 984 chars, different content) — the union of both, deduplicated.

The ``com.apple.private`` prefix is deliberately NOT a table entry: any key
containing it is flagged HIGH via an explicit substring check in each
pipeline's ``get_entitlements`` tool (a prefix match, not a specific
entitlement key). Native previously had both the substring check AND a
``"com.apple.private"`` table entry, causing a private entitlement to be
flagged twice — removed here.
"""

from __future__ import annotations

ENTITLEMENT_RISK_DB = {
    "com.apple.security.app-sandbox": ("LOW", "Sandboxed app — restricted"),
    "get-task-allow": ("HIGH", "Debug entitlement — should NOT be in release apps"),
    "com.apple.system-task-ports": ("CRITICAL", "Access to all process task ports"),
    "com.apple.security.cs.disable-library-validation": ("MEDIUM", "Can load unsigned/arbitrary dylibs"),
    "com.apple.security.cs.allow-unsigned-executable-memory": ("MEDIUM", "JIT or injection"),
    "com.apple.security.automation.apple-events": ("LOW", "Can send Apple Events"),
    "com.apple.security.network.client": ("LOW", "Outbound network access"),
    "com.apple.security.network.server": ("MEDIUM", "Can listen for connections"),
    "com.apple.security.files.all": ("HIGH", "Full filesystem access"),
    "com.apple.security.personal-information.contacts": ("MEDIUM", "Read contacts"),
    "com.apple.security.personal-information.location": ("MEDIUM", "Location access"),
}

SUSPICIOUS_DYLIB_PATTERNS = [
    (r"^/tmp/", "CRITICAL", "Loads from /tmp/ — staging path"),
    (r"^/var/folders/", "HIGH", "Loads from temp folder"),
    (r"~/", "HIGH", "Loads from user home (unusual for distribution)"),
    (r"@executable_path/\.", "MEDIUM", "Loads from executable dir (check for hijacking)"),
    (r"(inject|hook|patch|swizzle)", "HIGH", "Dylib name suggests hooking/injection"),
    (r"[a-z]{8,}\.(dylib|framework)", "MEDIUM", "Random-looking dylib name"),
]
