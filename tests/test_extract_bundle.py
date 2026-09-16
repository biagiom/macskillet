import os
from pathlib import Path

import pytest

from macskillet.native.feature_extractor import analyze_bundle


def _make_app_bundle(tmp_path) -> str:
    app_path = str(tmp_path / "Test.app")
    contents = Path(app_path) / "Contents"
    (contents / "MacOS").mkdir(parents=True)
    (contents / "Info.plist").write_text(
        "<?xml version='1.0'?><plist><dict>"
        "<key>CFBundleExecutable</key><string>Test</string>"
        "</dict></plist>"
    )
    return app_path


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
    and find -type f traversal must not double-count the inner file separately."""
    app_path = _make_app_bundle(tmp_path)
    scptd_scripts = Path(app_path) / "Contents" / "Resources" / "installer.scptd" / "Contents" / "Resources" / "Scripts"
    scptd_scripts.mkdir(parents=True)
    (scptd_scripts / "main.scpt").write_bytes(b"FasdUAS\x00")
    result = analyze_bundle(app_path)
    scripts = result["embedded_scripts"]
    assert any(f.endswith("installer.scptd") for f in scripts)
    assert not any("main.scpt" in f for f in scripts)
