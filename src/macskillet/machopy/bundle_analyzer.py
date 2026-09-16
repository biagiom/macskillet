"""
bundle_analyzer.py — macOS .app bundle structure analysis.

Parses Info.plist, detects persistence directories, and enumerates Mach-O
binaries and embedded scripts within an application bundle.

Runs anywhere. The previous implementation shelled out to ``plutil`` and
``find``, so off macOS it silently returned an empty result — which left the
"cross-platform" pipeline blind to bundle structure, one of the richest sources
of macOS persistence signal. Both are now pure Python: ``plistlib`` reads XML
*and* binary plists, and ``os.walk`` replaces ``find``.
"""

from __future__ import annotations

import os
import plistlib

from macskillet.machopy.macho_analyzer import is_macho

__all__ = ["analyze_bundle", "load_plist"]

#: Info.plist keys worth surfacing to the agent: privacy usage descriptions,
#: sandbox/hardened-runtime state, AppleScript enablement, principal class.
_INTERESTING_KEY_MARKERS = (
    "NSApple",
    "com.apple.security",
    "Privacy",
    "Usage",
    "NSPrincipal",
)

#: Extensions treated as embedded scripts. A script inside a signed .app is a
#: common way to keep malicious logic out of the notarized Mach-O.
_SCRIPT_EXTENSIONS = (
    ".sh", ".py", ".rb", ".pl", ".js", ".bash", ".scpt", ".applescript", ".command",
)

#: Directories inside a bundle that imply a persistence mechanism.
_LAUNCH_AGENT_DIRS = ("Contents/Library/LaunchAgents", "Contents/Library/LoginItems")
_LAUNCH_DAEMON_DIRS = ("Contents/Library/LaunchDaemons",)

#: Traversal cap, so a pathological or hostile bundle cannot hang extraction.
_MAX_FILES = 20000


def load_plist(plist_path: str) -> dict:
    """Read a plist in either XML or binary format. Returns ``{}`` on failure.

    ``plistlib`` sniffs the format itself, so this handles the binary plists
    Xcode emits by default without needing ``plutil -convert``.
    """
    try:
        with open(plist_path, "rb") as fh:
            data = plistlib.load(fh)
    except (OSError, plistlib.InvalidFileException, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def analyze_bundle(app_path: str) -> dict:
    """Parse .app bundle structure and Info.plist."""
    result = {
        "bundle_id": None,
        "bundle_version": None,
        "main_executable": None,
        "lsui_element": False,
        "ls_background_only": False,
        "has_launch_agent": False,
        "has_launch_daemon": False,
        "embedded_scripts": [],
        "all_binaries": [],
        "info_plist_keys": {},
        "info_plist_raw": {},
    }

    plist = load_plist(os.path.join(app_path, "Contents", "Info.plist"))
    if plist:
        result["info_plist_raw"] = plist
        result["bundle_id"] = plist.get("CFBundleIdentifier")
        result["bundle_version"] = (
            plist.get("CFBundleShortVersionString") or plist.get("CFBundleVersion")
        )
        result["main_executable"] = plist.get("CFBundleExecutable")
        result["lsui_element"] = bool(plist.get("LSUIElement", False))
        result["ls_background_only"] = bool(plist.get("LSBackgroundOnly", False))
        result["info_plist_keys"] = {
            key: value
            for key, value in plist.items()
            if any(marker in key for marker in _INTERESTING_KEY_MARKERS)
        }

    result["has_launch_agent"] = any(
        os.path.isdir(os.path.join(app_path, d)) for d in _LAUNCH_AGENT_DIRS
    )
    result["has_launch_daemon"] = any(
        os.path.isdir(os.path.join(app_path, d)) for d in _LAUNCH_DAEMON_DIRS
    )

    seen = 0
    for dirpath, dirnames, filenames in os.walk(app_path, followlinks=False):
        # .scptd script bundles are directories (Contents/Resources/Scripts/main.scpt
        # inside), not plain files — record the bundle path itself and prune it from
        # further traversal so its inner main.scpt isn't also picked up as a bare
        # .scpt file below (same in-place os.walk pruning trick used for .app bundles).
        for dirname in list(dirnames):
            if dirname.lower().endswith(".scptd"):
                result["embedded_scripts"].append(os.path.join(dirpath, dirname))
                dirnames.remove(dirname)
        for filename in filenames:
            seen += 1
            if seen > _MAX_FILES:
                return result
            filepath = os.path.join(dirpath, filename)
            if os.path.islink(filepath):
                continue
            if os.path.splitext(filename)[1].lower() in _SCRIPT_EXTENSIONS:
                result["embedded_scripts"].append(filepath)
            elif is_macho(filepath):
                result["all_binaries"].append(filepath)

    return result
