"""Tests for machopy.bundle_analyzer."""

import json
import os
import sys
from pathlib import Path

import pytest


from macskillet.machopy.bundle_analyzer import analyze_bundle


def _make_app_bundle(tmp_path, bundle_id="com.test.app", main_exec="TestApp", plist_extras=None) -> str:
    """Create a minimal .app bundle structure."""
    app = tmp_path / "Test.app"
    macos = app / "Contents" / "MacOS"
    macos.mkdir(parents=True)

    plist = {
        "CFBundleIdentifier": bundle_id,
        "CFBundleExecutable": main_exec,
        "CFBundleShortVersionString": "1.0",
    }
    if plist_extras:
        plist.update(plist_extras)

    # Write Info.plist as JSON (plutil-compatible)
    plist_path = app / "Contents" / "Info.plist"
    import subprocess
    # Write as plain JSON first, then convert to binary plist via plutil
    json_plist = app / "Contents" / "Info.json"
    json_plist.write_text(json.dumps(plist))
    subprocess.run(
        ["plutil", "-convert", "xml1", "-o", str(plist_path), str(json_plist)],
        check=True, capture_output=True
    )
    json_plist.unlink()

    # Create a dummy executable (text file, not a real Mach-O)
    (macos / main_exec).write_bytes(b"\x00" * 4)

    return str(app)


# ---------------------------------------------------------------------------
# analyze_bundle
# ---------------------------------------------------------------------------

def test_analyze_bundle_returns_dict():
    result = analyze_bundle("/nonexistent/path.app")
    assert isinstance(result, dict)


def test_analyze_bundle_has_required_keys():
    result = analyze_bundle("/nonexistent/path.app")
    required = [
        "bundle_id", "bundle_version", "main_executable",
        "lsui_element", "ls_background_only",
        "has_launch_agent", "has_launch_daemon",
        "embedded_scripts", "all_binaries", "info_plist_keys", "info_plist_raw",
    ]
    for key in required:
        assert key in result, f"missing key: {key}"


def test_analyze_bundle_missing_plist_returns_defaults():
    result = analyze_bundle("/nonexistent/path.app")
    assert result["bundle_id"] is None
    assert result["lsui_element"] is False
    assert result["has_launch_agent"] is False


@pytest.mark.integration
def test_analyze_bundle_reads_plist(tmp_path):
    app_path = _make_app_bundle(tmp_path, bundle_id="com.example.test", main_exec="TestBin")
    result = analyze_bundle(app_path)
    assert result["bundle_id"] == "com.example.test"
    assert result["main_executable"] == "TestBin"
    assert result["bundle_version"] == "1.0"


@pytest.mark.integration
def test_analyze_bundle_lsui_element_detected(tmp_path):
    app_path = _make_app_bundle(tmp_path, plist_extras={"LSUIElement": True})
    result = analyze_bundle(app_path)
    assert result["lsui_element"] is True


@pytest.mark.integration
def test_analyze_bundle_detects_launch_agent(tmp_path):
    app_path = _make_app_bundle(tmp_path)
    la_dir = Path(app_path) / "Contents" / "Library" / "LaunchAgents"
    la_dir.mkdir(parents=True)
    (la_dir / "com.evil.plist").write_text("<plist/>")
    result = analyze_bundle(app_path)
    assert result["has_launch_agent"] is True


@pytest.mark.integration
def test_analyze_bundle_finds_embedded_script(tmp_path):
    app_path = _make_app_bundle(tmp_path)
    resources = Path(app_path) / "Contents" / "Resources"
    resources.mkdir(parents=True)
    (resources / "setup.sh").write_text("#!/bin/bash\necho hi\n")
    result = analyze_bundle(app_path)
    assert any(f.endswith(".sh") for f in result["embedded_scripts"])


@pytest.mark.integration
def test_analyze_bundle_finds_embedded_applescript_and_bash(tmp_path):
    app_path = _make_app_bundle(tmp_path)
    resources = Path(app_path) / "Contents" / "Resources"
    resources.mkdir(parents=True)
    (resources / "installer.scpt").write_bytes(b"FasdUAS\x00")
    (resources / "helper.applescript").write_text("do shell script \"echo hi\"\n")
    (resources / "run.command").write_text("#!/bin/bash\necho hi\n")
    (resources / "extra.bash").write_text("#!/bin/bash\necho hi\n")
    result = analyze_bundle(app_path)
    scripts = result["embedded_scripts"]
    assert any(f.endswith(".scpt") for f in scripts)
    assert any(f.endswith(".applescript") for f in scripts)
    assert any(f.endswith(".command") for f in scripts)
    assert any(f.endswith(".bash") for f in scripts)


@pytest.mark.integration
def test_analyze_bundle_records_scptd_bundle_path_not_inner_file(tmp_path):
    """.scptd is a script *bundle* (directory) — the container path should be
    recorded, not the nested Contents/Resources/Scripts/main.scpt file inside it,
    and traversal must not double-count the inner file separately."""
    app_path = _make_app_bundle(tmp_path)
    scptd_scripts = Path(app_path) / "Contents" / "Resources" / "installer.scptd" / "Contents" / "Resources" / "Scripts"
    scptd_scripts.mkdir(parents=True)
    (scptd_scripts / "main.scpt").write_bytes(b"FasdUAS\x00")
    result = analyze_bundle(app_path)
    scripts = result["embedded_scripts"]
    assert any(f.endswith("installer.scptd") for f in scripts)
    assert not any("main.scpt" in f for f in scripts)
