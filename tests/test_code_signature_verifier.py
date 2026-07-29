"""Tests for machopy.code_signature_verifier — the offline four-link verifier.

Split into two tiers:

* Synthetic-bytes unit tests for the SuperBlob/CodeDirectory parser — fast,
  deterministic, no real binary needed.
* Integration tests against real signed binaries already present on any
  macOS host (``/bin/ls``, ``/usr/bin/osascript``) plus one crafted forgery
  and one crafted tamper case, cross-checked against ``codesign``'s own
  verdict where practical.
"""

from __future__ import annotations

import hashlib
import struct
from pathlib import Path

import pytest

from macskillet.machopy.code_signature_verifier import (
    CERTS_DIR,
    CSMAGIC_CODEDIRECTORY,
    CSMAGIC_EMBEDDED_SIGNATURE,
    CSSLOT_CODEDIRECTORY,
    CSSLOT_ENTITLEMENTS,
    CSSLOT_SIGNATURESLOT,
    _parse_code_directory,
    _parse_superblob,
    _verify_chain,
    _verify_slice,
    load_pinned_roots,
    verify_code_signature,
)

REAL_SIGNED_BINARY = "/bin/ls"
DONOR_BINARY = "/usr/bin/osascript"


# ---------------------------------------------------------------------------
# Synthetic SuperBlob / CodeDirectory construction
# ---------------------------------------------------------------------------

def _build_code_directory(identifier=b"com.test.sample", n_code_slots=2,
                          hash_type=2, page_size_log=12, page_hashes=None) -> bytes:
    hash_size = {1: 20, 2: 32, 3: 20, 4: 48}[hash_type]
    ident = identifier + b"\x00"
    ident_offset = 44
    hash_offset = ident_offset + len(ident)

    if page_hashes is None:
        page_hashes = [hashlib.sha256(bytes([i]) * 16).digest()[:hash_size] for i in range(n_code_slots)]

    header = (
        struct.pack(">III", CSMAGIC_CODEDIRECTORY, 0, 0x20001)  # magic, length (patched below), version
        + struct.pack(">IIIIII", 0, hash_offset, ident_offset, 0, n_code_slots,
                      n_code_slots * (1 << page_size_log))  # flags, offsets, slot counts, codeLimit
        + struct.pack(">BBBB", hash_size, hash_type, 0, page_size_log)
        + struct.pack(">I", 0)  # spare2
    )
    assert len(header) == 44
    body = header + ident + b"".join(page_hashes)
    # patch the length field now that we know the total size
    body = body[:4] + struct.pack(">I", len(body)) + body[8:]
    return body


def _build_superblob(blobs: dict[int, bytes]) -> bytes:
    """blobs: {index_type: blob_bytes}."""
    header_size = 12 + 8 * len(blobs)
    index = b""
    payload = b""
    offset = header_size
    for index_type, blob in blobs.items():
        index += struct.pack(">II", index_type, offset)
        payload += blob
        offset += len(blob)
    total_len = header_size + len(payload)
    header = struct.pack(">III", CSMAGIC_EMBEDDED_SIGNATURE, total_len, len(blobs))
    return header + index + payload


class TestSuperBlobParsing:

    def test_parses_index_entries(self):
        cd = _build_code_directory()
        sb = _build_superblob({CSSLOT_CODEDIRECTORY: cd})
        entries = _parse_superblob(sb)
        assert CSSLOT_CODEDIRECTORY in entries

    def test_wrong_magic_returns_none(self):
        garbage = struct.pack(">III", 0xDEADBEEF, 12, 0)
        assert _parse_superblob(garbage) is None

    def test_truncated_blob_returns_none(self):
        assert _parse_superblob(b"\x00\x00") is None

    def test_multiple_slots(self):
        cd = _build_code_directory()
        ent = struct.pack(">II", 0xFADE7171, 8) + b"<plist/>"
        sb = _build_superblob({CSSLOT_CODEDIRECTORY: cd, CSSLOT_ENTITLEMENTS: ent})
        entries = _parse_superblob(sb)
        assert set(entries) == {CSSLOT_CODEDIRECTORY, CSSLOT_ENTITLEMENTS}


class TestCodeDirectoryParsing:

    def test_parses_identifier(self):
        cd_bytes = _build_code_directory(identifier=b"com.example.thing")
        cd = _parse_code_directory(cd_bytes, 0)
        assert cd.identifier == "com.example.thing"

    def test_parses_slot_counts(self):
        cd_bytes = _build_code_directory(n_code_slots=5)
        cd = _parse_code_directory(cd_bytes, 0)
        assert cd.n_code_slots == 5

    def test_page_size_resolved_from_log2(self):
        cd_bytes = _build_code_directory(page_size_log=12)
        cd = _parse_code_directory(cd_bytes, 0)
        assert cd.page_size == 4096

    def test_wrong_magic_returns_none(self):
        assert _parse_code_directory(b"\x00" * 44, 0) is None

    def test_offset_parameter_is_respected(self):
        """A CD embedded at a nonzero offset within a larger buffer."""
        cd_bytes = _build_code_directory(identifier=b"com.offset.test")
        padded = b"\x00" * 20 + cd_bytes
        cd = _parse_code_directory(padded, 20)
        assert cd.identifier == "com.offset.test"
        assert cd.offset == 20


class TestHashSlotRecomputation:

    def test_correct_hashes_verify(self, tmp_path):
        page_size_log = 12
        page_size = 1 << page_size_log
        pages = [bytes([i]) * page_size for i in range(3)]
        hashes = [hashlib.sha256(p).digest() for p in pages]
        cd_bytes = _build_code_directory(n_code_slots=3, page_size_log=page_size_log,
                                         page_hashes=hashes)
        sb = _build_superblob({CSSLOT_CODEDIRECTORY: cd_bytes})

        binary_path = tmp_path / "sample"
        binary_path.write_bytes(b"".join(pages))

        with open(binary_path, "rb") as fh:
            result = _verify_slice(fh, 0, sb, pinned_roots=[])
        assert result["page_hashes_valid"] is True
        assert result["tamper_detected"] is False

    def test_tampered_page_fails(self, tmp_path):
        page_size_log = 12
        page_size = 1 << page_size_log
        pages = [bytes([i]) * page_size for i in range(3)]
        hashes = [hashlib.sha256(p).digest() for p in pages]
        cd_bytes = _build_code_directory(n_code_slots=3, page_size_log=page_size_log,
                                         page_hashes=hashes)
        sb = _build_superblob({CSSLOT_CODEDIRECTORY: cd_bytes})

        # Write DIFFERENT content than what was hashed.
        binary_path = tmp_path / "sample"
        tampered_pages = list(pages)
        tampered_pages[1] = bytes([0xFF]) * page_size
        binary_path.write_bytes(b"".join(tampered_pages))

        with open(binary_path, "rb") as fh:
            result = _verify_slice(fh, 0, sb, pinned_roots=[])
        assert result["page_hashes_valid"] is False
        assert result["tamper_detected"] is True
        assert result["fully_verified"] is False

    def test_no_code_directory_flags_as_tamper(self, tmp_path):
        sb = _build_superblob({0x999: b"\x00" * 12})  # not a real CD slot
        binary_path = tmp_path / "sample"
        binary_path.write_bytes(b"\x00" * 4096)
        with open(binary_path, "rb") as fh:
            result = _verify_slice(fh, 0, sb, pinned_roots=[])
        assert result["tamper_detected"] is True

    def test_unsigned_binary_reports_not_signed(self, tmp_path):
        binary_path = tmp_path / "sample"
        binary_path.write_bytes(b"\x00" * 100)
        with open(binary_path, "rb") as fh:
            result = _verify_slice(fh, 0, b"not a superblob", pinned_roots=[])
        assert result["signed"] is False
        assert result["fully_verified"] is False
        assert result["tamper_detected"] is False  # absence isn't evidence


# ---------------------------------------------------------------------------
# Pinned roots
# ---------------------------------------------------------------------------

class TestPinnedRoots:

    def test_certs_dir_exists(self):
        assert CERTS_DIR.is_dir()

    def test_loads_apple_root_ca(self):
        roots = load_pinned_roots()
        subjects = [r.subject.rfc4514_string() for r in roots]
        assert any("Apple Root CA" in s and "G2" not in s and "G3" not in s for s in subjects)

    def test_missing_dir_returns_empty(self, tmp_path):
        assert load_pinned_roots(tmp_path / "nonexistent") == []

    def test_at_least_developer_id_and_a_root_present(self):
        roots = load_pinned_roots()
        subjects = "\n".join(r.subject.rfc4514_string() for r in roots)
        assert "Developer ID Certification Authority" in subjects


# ---------------------------------------------------------------------------
# Forged-root rejection (the core security property)
# ---------------------------------------------------------------------------

class TestForgedRootRejection:
    """A same-named self-signed certificate must not pass as a pinned root.

    This is the exact gap a substring/regex identity check has: a binary can
    embed a certificate that merely *claims* to be "Apple Root CA". Only
    verifying its signature against the real pinned public key catches that
    the claim is false.
    """

    @staticmethod
    def _make_cert(subject_cn, issuer_cn, signing_key, public_key=None):
        import datetime

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        if public_key is None:
            public_key = signing_key.public_key()
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
        issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)])
        return (
            x509.CertificateBuilder()
            .subject_name(subject).issuer_name(issuer)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime(2020, 1, 1))
            .not_valid_after(datetime.datetime(2040, 1, 1))
            .sign(signing_key, hashes.SHA256())
        )

    def test_forged_root_with_correct_name_is_rejected(self):
        from cryptography.hazmat.primitives.asymmetric import rsa

        fake_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        fake_root = self._make_cert("Apple Root CA", "Apple Root CA", fake_key)
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        fake_leaf = self._make_cert("Developer ID Application: Evil Corp", "Apple Root CA",
                                    fake_key, public_key=leaf_key.public_key())

        result = _verify_chain([fake_leaf, fake_root], load_pinned_roots())
        assert result["valid"] is False
        assert result["matched_root"] is None

    def test_genuine_intermediate_signed_by_real_pinned_root_is_accepted(self):
        """Sanity check the accept path isn't just always False."""
        roots = load_pinned_roots()
        developer_id_ca = next(
            r for r in roots if "Developer ID Certification Authority" in r.subject.rfc4514_string()
        )
        apple_root = next(
            r for r in roots
            if r.subject.rfc4514_string() == "CN=Apple Root CA,OU=Apple Certification Authority,O=Apple Inc.,C=US"
        )
        # The real DeveloperIDCA cert, verified against the real pinned Apple
        # Root CA, must validate -- it's the same certificate.
        result = _verify_chain([developer_id_ca], [apple_root])
        assert result["valid"] is True
        assert result["matched_root"] == apple_root.subject.rfc4514_string()

    def test_empty_pinned_roots_reports_environment_error_not_tamper(self):
        fake_key_holder = load_pinned_roots()
        result = _verify_chain(fake_key_holder[:1], [])
        assert result["valid"] is False
        assert result["environment_errors"]
        assert result["errors"] == []


# ---------------------------------------------------------------------------
# Integration: real signed binaries on this machine
# ---------------------------------------------------------------------------

@pytest.mark.integration
class TestRealBinaries:

    def test_ls_fully_verifies(self):
        result = verify_code_signature(REAL_SIGNED_BINARY)
        assert result["fully_verified"] is True
        assert result["tamper_detected"] is False
        assert result["slices"]

    def test_every_slice_reaches_apple_root(self):
        result = verify_code_signature(REAL_SIGNED_BINARY)
        for arch, s in result["slices"].items():
            assert s["chain"]["valid"] is True, arch
            assert "Apple" in s["chain"]["matched_root"]

    def test_cd_hash_matches_cms_message_digest(self):
        result = verify_code_signature(REAL_SIGNED_BINARY)
        for s in result["slices"].values():
            assert s["cms"]["cd_hash_matches"] is True

    def test_single_byte_tamper_detected_and_matches_codesign(self, tmp_path):
        import platform
        import shutil
        import subprocess

        import lief

        lief.logging.disable()

        target = tmp_path / "tampered"
        shutil.copy(REAL_SIGNED_BINARY, target)

        # codesign --verify (no --arch) checks the slice matching this host's
        # architecture, so the flipped byte must land inside THAT slice's
        # code region -- a byte at a fixed fraction of the file can land in
        # the other architecture's slice, padding, or the signature blob
        # itself and get silently ignored by both verifiers.
        want_arch = {"arm64": "ARM64", "x86_64": "X86_64"}[platform.machine()]
        fat = lief.MachO.parse(str(target))
        binary = next(b for b in fat if b.header.cpu_type.name == want_arch)
        flip_at = binary.fat_offset + 4096  # first full page past the Mach-O header

        data = bytearray(target.read_bytes())
        data[flip_at] ^= 0xFF
        target.write_bytes(data)

        codesign = subprocess.run(
            ["codesign", "--verify", "--verbose=4", str(target)],
            capture_output=True, text=True,
        )
        our_result = verify_code_signature(str(target))

        assert codesign.returncode != 0  # codesign agrees it's broken
        assert our_result["fully_verified"] is False
        assert our_result["tamper_detected"] is True
        assert our_result["slices"][want_arch.lower()]["page_hashes_valid"] is False

    def test_blob_transplant_caught_by_page_hashes_alone(self):
        """CMS + chain both pass (donor really is Apple-signed); only page
        hashes reveal the signature describes a different binary."""
        import lief

        lief.logging.disable()
        target_fat = lief.MachO.parse(REAL_SIGNED_BINARY)
        donor_fat = lief.MachO.parse(DONOR_BINARY)
        target_slice = target_fat.at(0)
        donor_slice = donor_fat.at(0)
        donor_cs = bytes(donor_slice.code_signature.content)

        with open(REAL_SIGNED_BINARY, "rb") as fh:
            result = _verify_slice(fh, target_slice.fat_offset, donor_cs, load_pinned_roots())

        assert result["page_hashes_valid"] is False
        assert result["cms"]["signature_valid"] is True  # donor's own signature IS valid
        assert result["cms"]["cd_hash_matches"] is True
        assert result["fully_verified"] is False
        assert result["tamper_detected"] is True


@pytest.mark.integration
class TestCodesignPathDistinguishesTamperFromAbsence:
    """codesign --verify failing means either "never signed" or "signed but
    broken" -- two very different things that both signature_analyzer.py
    (machopy, used by the detector pipeline) and extract_features_native.py
    (native pipeline) must not conflate, or signature_trust's tamper gate can
    never fire on the platform where codesign is authoritative.
    """

    @staticmethod
    def _make_tampered_copy(tmp_path):
        import shutil

        target = tmp_path / "tampered"
        shutil.copy(REAL_SIGNED_BINARY, target)
        data = bytearray(target.read_bytes())
        data[len(data) // 2] ^= 0xFF
        target.write_bytes(data)
        return str(target)

    def test_never_signed_reports_structural_unsigned(self, tmp_path):
        from macskillet.machopy.signature_analyzer import _analyze_with_codesign

        unsigned = tmp_path / "plain"
        unsigned.write_bytes(Path(REAL_SIGNED_BINARY).read_bytes())
        # A raw copy of a Mach-O with its signature stripped -- codesign
        # itself reports "not signed at all" for this, not "invalid".
        import subprocess
        subprocess.run(["codesign", "--remove-signature", str(unsigned)],
                       capture_output=True)

        result = _analyze_with_codesign(str(unsigned))
        assert result["signing_status"] == "unsigned"
        assert result["verification"] != "invalid"

    def test_tampered_reports_invalid_not_unsigned(self, tmp_path):
        from macskillet.machopy.signature_analyzer import _analyze_with_codesign

        result = _analyze_with_codesign(self._make_tampered_copy(tmp_path))
        assert result["verification"] == "invalid"
        assert result["signing_status"] != "unsigned"  # identity still readable

    def test_native_extractor_matches(self, tmp_path):
        from macskillet.native.extract_features_native import analyze_signature

        result = analyze_signature(self._make_tampered_copy(tmp_path))
        assert result["verification"] == "invalid"
        assert result["signing_status"] != "unsigned"
        assert "codesign --verify FAILED" in result["signing_status_detail"]

    def test_tamper_gate_fires_end_to_end_via_signature_trust(self, tmp_path):
        from macskillet.machopy.signature_analyzer import _analyze_with_codesign
        from macskillet.native.signature_trust import assess_signature_trust

        sig = _analyze_with_codesign(self._make_tampered_copy(tmp_path))
        result = assess_signature_trust({"signature": sig, "clickfix": {}})
        assert result["trust_level"] == "signature_invalid"
        assert result["adjustment"] == 5


class TestExpiryAndSelfSigned:
    """Certificate validity windows and self-signed detection.

    Expiry is checked against a caller-supplied reference time (in practice
    the CMS signing_time), never wall-clock "now" -- a code-signing cert
    legitimately expires years after a binary was signed.
    """

    @staticmethod
    def _cert(not_before, not_after, subject_cn="Leaf", issuer_cn=None, key=None):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = key or rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
        issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn or subject_cn)])
        return key, (
            x509.CertificateBuilder()
            .subject_name(subject).issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before).not_valid_after(not_after)
            .sign(key, hashes.SHA256())
        )

    def test_self_signed_flagged_on_leaf(self):
        _, cert = self._cert(
            __import__("datetime").datetime(2020, 1, 1),
            __import__("datetime").datetime(2040, 1, 1),
        )
        result = _verify_chain([cert], [])
        assert result["self_signed"] is True

    def test_not_self_signed_when_issuer_differs(self):
        _, leaf = self._cert(
            __import__("datetime").datetime(2020, 1, 1),
            __import__("datetime").datetime(2040, 1, 1),
            subject_cn="Leaf", issuer_cn="Someone Else",
        )
        result = _verify_chain([leaf], [])
        assert result["self_signed"] is False

    def test_no_reference_time_skips_expiry_check(self):
        import datetime as dt

        roots = load_pinned_roots()
        developer_id_ca = next(
            r for r in roots if "Developer ID Certification Authority" in r.subject.rfc4514_string()
        )
        apple_root = next(
            r for r in roots
            if r.subject.rfc4514_string() == "CN=Apple Root CA,OU=Apple Certification Authority,O=Apple Inc.,C=US"
        )
        result = _verify_chain([developer_id_ca], [apple_root], reference_time=None)
        assert result["expired"] is None
        assert result["valid"] is True  # unchecked never blocks validity

    def test_reference_time_within_window_is_valid(self):
        roots = load_pinned_roots()
        developer_id_ca = next(
            r for r in roots if "Developer ID Certification Authority" in r.subject.rfc4514_string()
        )
        apple_root = next(
            r for r in roots
            if r.subject.rfc4514_string() == "CN=Apple Root CA,OU=Apple Certification Authority,O=Apple Inc.,C=US"
        )
        midpoint = developer_id_ca.not_valid_before_utc + (
            developer_id_ca.not_valid_after_utc - developer_id_ca.not_valid_before_utc
        ) / 2
        result = _verify_chain([developer_id_ca], [apple_root], reference_time=midpoint)
        assert result["expired"] is False
        assert result["valid"] is True

    def test_reference_time_outside_window_marks_expired_and_invalid(self):
        import datetime

        roots = load_pinned_roots()
        developer_id_ca = next(
            r for r in roots if "Developer ID Certification Authority" in r.subject.rfc4514_string()
        )
        apple_root = next(
            r for r in roots
            if r.subject.rfc4514_string() == "CN=Apple Root CA,OU=Apple Certification Authority,O=Apple Inc.,C=US"
        )
        long_after = developer_id_ca.not_valid_after_utc + datetime.timedelta(days=3650)
        result = _verify_chain([developer_id_ca], [apple_root], reference_time=long_after)
        assert result["expired"] is True
        assert result["valid"] is False


class TestRevocationOptIn:
    """OCSP checking is opt-in only -- never triggered by default."""

    def test_default_never_checks_revocation(self):
        roots = load_pinned_roots()
        developer_id_ca = next(
            r for r in roots if "Developer ID Certification Authority" in r.subject.rfc4514_string()
        )
        apple_root = next(
            r for r in roots
            if r.subject.rfc4514_string() == "CN=Apple Root CA,OU=Apple Certification Authority,O=Apple Inc.,C=US"
        )
        result = _verify_chain([developer_id_ca], [apple_root])
        assert result["revocation"]["checked"] is False

    def test_check_revocation_url_absent_reports_unavailable_not_revoked(self):
        from macskillet.machopy.code_signature_verifier import check_revocation

        roots = load_pinned_roots()
        developer_id_ca = next(
            r for r in roots if "Developer ID Certification Authority" in r.subject.rfc4514_string()
        )
        apple_root = next(
            r for r in roots
            if r.subject.rfc4514_string() == "CN=Apple Root CA,OU=Apple Certification Authority,O=Apple Inc.,C=US"
        )
        # Root-adjacent intermediates typically carry no OCSP AIA extension.
        result = check_revocation(developer_id_ca, apple_root)
        assert result["status"] == "unavailable"
        assert result["checked"] is False


@pytest.mark.integration
class TestRevocationLive:
    """Live OCSP round-trip against Apple's real responder."""

    def test_real_developer_id_leaf_is_not_revoked(self):
        """Uses Slack.app if present -- a real Developer ID signed binary."""
        slack = Path("/Applications/Slack.app/Contents/MacOS/Slack")
        if not slack.exists():
            pytest.skip("Slack.app not installed on this machine")

        result = verify_code_signature(str(slack), check_revocation=True)
        checked_any = False
        for s in result["slices"].values():
            chain = s.get("chain") or {}
            for detail in chain.get("revocation", {}).get("details", []):
                if detail["checked"]:
                    checked_any = True
                    assert detail["status"] == "good"
        if not checked_any:
            pytest.skip("could not reach Apple's OCSP responder from this environment")


class TestCertInfoFeaturesAdapter:
    """The classical-ML feature vector now delegates to verify_code_signature."""

    def test_signed_binary_produces_expected_vector(self):
        pytest.importorskip("numpy")
        from macskillet.machopy.static_feat_extractor import CertInfoFeatures

        vector = CertInfoFeatures().extract_features(REAL_SIGNED_BINARY)
        names = CertInfoFeatures.FEATURE_NAMES
        values = dict(zip(names, vector))
        assert values["cert_present"] == 1
        assert values["cert_validated"] == 1
        assert values["cert_self_signed"] == 0

    def test_certificates_extractor_module_is_gone(self):
        with pytest.raises(ModuleNotFoundError):
            import macskillet.machopy.certificates_extractor  # noqa: F401
