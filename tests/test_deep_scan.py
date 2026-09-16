from macskillet.common.deep_scan import bucket_candidates, scan_applescript_analysis, select_within_limit


def test_bucket_candidates_classifies_applescript_dylib_binary():
    buckets = bucket_candidates(
        all_binaries=[
            "/App.app/Contents/Frameworks/Foo.framework/Versions/A/Foo",
            "/App.app/Contents/Frameworks/libbar.dylib",
            "/App.app/Contents/MacOS/helper",
        ],
        embedded_scripts=[
            "/App.app/Contents/Resources/installer.scpt",
            "/App.app/Contents/Resources/setup.sh",
        ],
    )
    assert buckets["applescript"] == ["/App.app/Contents/Resources/installer.scpt"]
    assert buckets["dylib"] == [
        "/App.app/Contents/Frameworks/Foo.framework/Versions/A/Foo",
        "/App.app/Contents/Frameworks/libbar.dylib",
    ]
    assert buckets["binary"] == ["/App.app/Contents/MacOS/helper"]


def test_bucket_candidates_excludes_main_binary():
    buckets = bucket_candidates(
        all_binaries=["/App.app/Contents/MacOS/Test", "/App.app/Contents/MacOS/helper"],
        embedded_scripts=[],
        main_binary="/App.app/Contents/MacOS/Test",
    )
    assert buckets["binary"] == ["/App.app/Contents/MacOS/helper"]


def test_bucket_candidates_non_applescript_scripts_not_scanned():
    buckets = bucket_candidates(
        all_binaries=[],
        embedded_scripts=["/App.app/Contents/Resources/setup.sh", "/App.app/Contents/Resources/run.command"],
    )
    assert buckets["applescript"] == []


def test_select_within_limit_under_limit_selects_everything():
    buckets = {"applescript": ["a.scpt"], "dylib": ["b.dylib"], "binary": []}
    selected, skipped = select_within_limit(buckets, limit=10)
    assert selected == [("a.scpt", "applescript"), ("b.dylib", "dylib")]
    assert skipped == {}


def test_select_within_limit_exact_limit():
    buckets = {"applescript": ["a.scpt"], "dylib": ["b.dylib"], "binary": []}
    selected, skipped = select_within_limit(buckets, limit=2)
    assert len(selected) == 2
    assert skipped == {}


def test_select_within_limit_over_limit_priority_order():
    buckets = {
        "applescript": ["a1.scpt", "a2.scpt"],
        "dylib": [f"d{i}.dylib" for i in range(5)],
        "binary": [f"b{i}" for i in range(4)],
    }
    selected, skipped = select_within_limit(buckets, limit=3)
    assert selected == [("a1.scpt", "applescript"), ("a2.scpt", "applescript"), ("d0.dylib", "dylib")]
    assert skipped == {"dylib": 4, "binary": 4}


def test_select_within_limit_empty_candidates():
    selected, skipped = select_within_limit({"applescript": [], "dylib": [], "binary": []}, limit=10)
    assert selected == []
    assert skipped == {}


def test_select_within_limit_fills_applescript_before_dylib_before_binary():
    buckets = {
        "applescript": ["a.scpt"],
        "dylib": ["d.dylib"],
        "binary": ["helper"],
    }
    selected, _ = select_within_limit(buckets, limit=2)
    assert selected == [("a.scpt", "applescript"), ("d.dylib", "dylib")]


_RUNONLY_MARKER = b"\xfa\xde\xde\xad"
_COMPILED_HEADER = b"FasdUAS"


def test_scan_applescript_analysis_flags_main_binary_marker(tmp_path):
    binary = tmp_path / "main_binary"
    binary.write_bytes(b"\x00" * 20 + _RUNONLY_MARKER + b"\x00" * 20)
    result = scan_applescript_analysis(str(binary), [])
    assert result["runonly_applescript"] is True
    assert result["compiled_applescript"] is False


def test_scan_applescript_analysis_flags_bundle_applescript_file(tmp_path):
    binary = tmp_path / "main_binary"
    binary.write_bytes(b"clean binary content, no markers here")
    script = tmp_path / "installer.applescript"
    script.write_bytes(_COMPILED_HEADER + b"\x00" * 10 + _RUNONLY_MARKER)

    result = scan_applescript_analysis(str(binary), [str(script)])
    assert result["runonly_applescript"] is True
    assert result["compiled_applescript"] is True


def test_scan_applescript_analysis_resolves_scptd_bundle(tmp_path):
    binary = tmp_path / "main_binary"
    binary.write_bytes(b"clean")
    scptd = tmp_path / "installer.scptd"
    inner = scptd / "Contents" / "Resources" / "Scripts"
    inner.mkdir(parents=True)
    (inner / "main.scpt").write_bytes(_RUNONLY_MARKER)

    result = scan_applescript_analysis(str(binary), [str(scptd)])
    assert result["runonly_applescript"] is True


def test_scan_applescript_analysis_deduplicates_indicators(tmp_path):
    binary = tmp_path / "main_binary"
    binary.write_bytes(_RUNONLY_MARKER)
    script = tmp_path / "installer.scpt"
    script.write_bytes(_RUNONLY_MARKER)

    result = scan_applescript_analysis(str(binary), [str(script)])
    assert result["indicators"].count(
        "0xFADEDEAD run-only AppleScript marker — source stripped, osadecompile fails"
    ) == 1


def test_scan_applescript_analysis_clean_sample_reports_no_findings(tmp_path):
    binary = tmp_path / "main_binary"
    binary.write_bytes(b"nothing suspicious here")
    result = scan_applescript_analysis(str(binary), [])
    assert result["runonly_applescript"] is False
    assert result["compiled_applescript"] is False
    assert result["indicators"] == []
    assert result["detail"] == "no AppleScript script data found"
