"""
signature_analyzer.py — code signature and Gatekeeper analysis.

Two paths behind one schema:

``codesign``/``spctl`` (macOS)
    Cryptographically verifies the signature, resolves the certificate chain
    against the system trust store, and asks Gatekeeper for an actual
    admission decision. Also reports notarization, which has no offline
    equivalent — it's a server-side ticket check.

:mod:`macskillet.machopy.code_signature_verifier` (any OS)
    Independently cryptographically verifies the signature offline: recomputes
    every page hash, verifies the CMS signature, and checks the certificate
    chain against Apple roots pinned in ``machopy/certs/``. This is not a
    lesser fallback — it catches a class of forgery ``codesign`` and a naive
    "does the blob contain this substring" read both handle differently: a
    signature blob copied whole from a legitimately-signed binary onto
    malware (only recomputing page hashes against *this* file's actual bytes
    catches that; the CMS signature and cert chain are internally consistent
    either way — see that module's docstring for the full four-link
    breakdown).

The distinction that remains is reported in ``verification``:

``"cryptographic"``
    Fully verified — either by codesign or by recomputing everything offline.
``"invalid"``
    A cryptographic check was attempted and failed: a broken page hash, a CMS
    signature that doesn't verify, or a chain that doesn't reach a pinned
    root. This is *evidence*, not silence — treat it as more alarming than
    "structural", not as a synonym for it.
``"structural"``
    No verification was possible (missing dependency, no code signature to
    check, or nothing suspicious found but nothing confirmed either).

Downstream trust logic must not treat these as equivalent. This is also why
``select_backend`` never silently downgrades an explicit backend choice.
"""

from __future__ import annotations

import plistlib
import re
import shutil
import subprocess

__all__ = ["analyze_signature", "codesign_available"]

#: Signing-status vocabulary, shared by both paths.
UNSIGNED = "unsigned"
AD_HOC = "ad_hoc"
APPLE_SIGNED = "apple_signed"
DEVELOPER_ID = "developer_id"
OTHER_SIGNED = "other_signed"

#: verification levels
CRYPTOGRAPHIC = "cryptographic"
INVALID = "invalid"
STRUCTURAL = "structural"


def _empty_result() -> dict:
    return {
        "signed": False,
        "signing_status": UNSIGNED,
        "notarized": False,
        "team_id": None,
        "bundle_id_match": None,
        "codesign_verify_output": "",
        "spctl_output": "",
        "entitlements_xml": "",
        "entitlements": {},
        "codesign_display": "",
        "verification": STRUCTURAL,
        "analyzer": None,
    }


def _run(cmd: list, timeout: int = 30) -> tuple[str, str, int]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT", -1
    except FileNotFoundError:
        return "", f"TOOL_NOT_FOUND: {cmd[0]}", -1


def codesign_available() -> bool:
    """True if the macOS signing toolchain is present on this host."""
    return shutil.which("codesign") is not None


# ---------------------------------------------------------------------------
# macOS path — cryptographic verification
# ---------------------------------------------------------------------------

def _analyze_with_codesign(path: str) -> dict:
    result = _empty_result()
    result["analyzer"] = "codesign"
    result["verification"] = CRYPTOGRAPHIC

    _, stderr, rc = _run(["codesign", "--verify", "--verbose=4", path])
    result["codesign_verify_output"] = stderr
    result["signed"] = rc == 0

    # `--verify` failing means one of two very different things: no
    # signature at all ("code object is not signed at all"), or a signature
    # that WAS present and no longer matches the binary's actual bytes
    # (blob transplant, post-sign tampering) -- active tamper evidence, not
    # absence of information. codesign can still read the certificate chain
    # via `-d` even when `--verify` rejects it, so identity below is parsed
    # normally in the tampered case rather than forced to "unsigned".
    tampered_signature = (not result["signed"]) and "not signed at all" not in stderr

    stdout, stderr, _ = _run(["codesign", "-d", "--verbose=4", path])
    display_out = stdout + stderr
    result["codesign_display"] = display_out

    has_readable_identity = result["signed"] or tampered_signature
    if not has_readable_identity:
        result["signing_status"] = UNSIGNED
    elif "ad hoc" in display_out.lower():
        result["signing_status"] = AD_HOC
    elif "Apple Root CA" in display_out and "Developer ID Application" not in display_out:
        result["signing_status"] = APPLE_SIGNED
    elif "Developer ID Application" in display_out:
        result["signing_status"] = DEVELOPER_ID
    else:
        result["signing_status"] = OTHER_SIGNED

    if tampered_signature:
        result["verification"] = INVALID

    team_match = re.search(r"TeamIdentifier=(\S+)", display_out)
    if team_match and team_match.group(1) != "not":
        result["team_id"] = team_match.group(1)

    ent_stdout, _, _ = _run(["codesign", "-d", "--entitlements", ":-", path])
    result["entitlements_xml"] = ent_stdout
    result["entitlements"] = _parse_entitlements_xml(ent_stdout)

    spctl_out, spctl_err, _ = _run(["spctl", "--assess", "--verbose", path])
    result["spctl_output"] = (spctl_out + spctl_err).strip()
    if "notarized" in result["spctl_output"].lower():
        result["notarized"] = True

    return result


# ---------------------------------------------------------------------------
# Portable path — structural parsing
# ---------------------------------------------------------------------------

def _parse_entitlements_xml(xml: str) -> dict:
    """Parse an entitlements plist blob, tolerating codesign's leading junk."""
    if not xml:
        return {}
    start = xml.find("<?xml")
    if start == -1:
        start = xml.find("<plist")
    if start == -1:
        return {}
    try:
        data = plistlib.loads(xml[start:].encode("utf-8", errors="ignore"))
    except (plistlib.InvalidFileException, ValueError, UnicodeDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _analyze_with_lief(path: str) -> dict:
    """Independently verify the embedded code signature offline.

    Delegates the actual cryptography to
    :func:`macskillet.machopy.code_signature_verifier.verify_code_signature`,
    which recomputes page hashes, verifies the CMS signature, and checks the
    certificate chain against pinned Apple roots — see that module for what
    each check catches. This function's job is just translating that result
    into the schema shared with the codesign path.
    """
    result = _empty_result()
    result["analyzer"] = "lief"

    try:
        import lief
    except ImportError:
        result["codesign_verify_output"] = "LIEF not installed and codesign unavailable"
        return result

    lief.logging.disable()
    try:
        fat = lief.MachO.parse(path)
    except Exception as exc:  # LIEF raises a variety of parse errors
        result["codesign_verify_output"] = f"LIEF parse failed: {exc}"
        return result
    if fat is None:
        result["codesign_verify_output"] = f"LIEF could not parse: {path}"
        return result

    has_signature = any(
        getattr(binary, "has_code_signature", False) and binary.code_signature is not None
        for binary in fat
    )
    result["signed"] = has_signature
    if not has_signature:
        result["signing_status"] = UNSIGNED
        return result

    # Entitlements come from the embedded 0xFADE7171 blob — pure Python, no OS help.
    try:
        from macskillet.machopy.entitlements_extractor import EntitlementsExtractor

        extractor = EntitlementsExtractor(verbose=False, use_all_entitlements=True)
        keys = extractor.get_entitlements_sample(path) or []
        result["entitlements"] = {key: True for key in keys}
    except Exception as exc:
        result["codesign_verify_output"] = f"entitlement parse failed: {exc}"

    from macskillet.machopy.code_signature_verifier import verify_code_signature

    verification = verify_code_signature(path)
    _apply_verification_result(result, verification)

    # Notarization is a server-side Gatekeeper ticket check. There is no
    # offline answer, so this stays False rather than guessing — a wrong
    # True would grant trust that was never earned.
    result["spctl_output"] = "unavailable off-macOS (notarization requires Gatekeeper)"
    return result


def _apply_verification_result(result: dict, verification: dict) -> None:
    """Fill in signing_status/team_id/verification from a verifier result."""
    signed_slices = [s for s in verification.get("slices", {}).values() if s.get("signed")]
    primary = signed_slices[0] if signed_slices else None
    cms = (primary or {}).get("cms") or {}
    cd = (primary or {}).get("code_directory") or {}

    result["team_id"] = cms.get("signer_team_id") or cd.get("team_id")

    common_name = cms.get("signer_common_name") or ""
    if not cms.get("present"):
        result["signing_status"] = AD_HOC
        result["codesign_display"] = "no CMS certificate chain in signature blob (ad-hoc)"
    else:
        result["codesign_display"] = f"Authority={cms.get('signer_subject')}"
        if common_name.startswith("Developer ID Application"):
            result["signing_status"] = DEVELOPER_ID
        elif "Apple" in common_name or (result["team_id"] is None and common_name):
            result["signing_status"] = APPLE_SIGNED
        else:
            result["signing_status"] = OTHER_SIGNED

    if verification["fully_verified"]:
        result["verification"] = CRYPTOGRAPHIC
    elif verification["tamper_detected"]:
        result["verification"] = INVALID
        errors = [e for s in signed_slices for e in s.get("errors", [])]
        result["codesign_verify_output"] = "; ".join(errors) or "signature verification failed"
    else:
        result["verification"] = STRUCTURAL
        notes = [n for s in signed_slices for n in s.get("notes", [])]
        if notes:
            result["codesign_verify_output"] = "; ".join(notes)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_signature(path: str, prefer_codesign: bool = True) -> dict:
    """Return structured signature info for ``path``.

    Uses ``codesign``/``spctl`` when available (authoritative), otherwise falls
    back to structural parsing. Check the ``verification`` field before acting
    on ``signing_status``.
    """
    if prefer_codesign and codesign_available():
        return _analyze_with_codesign(path)
    return _analyze_with_lief(path)
