#!/usr/bin/env python3
"""
signature_trust.py — Deterministic signing-trust assessment for macOS samples.

Implements the "notarized != safe" finding from the 2026 macOS vendor-blog
literature synthesis (SentinelOne, Moonlock, Jamf, Objective-See):

  Multiple 2025-2026 infostealers (MacSync, Odyssey, BlueNoroff Hidden Risk)
  ship a *validly Developer-ID-signed and notarized* app that is clean at
  Gatekeeper scan time, then strips quarantine / fetches a second stage /
  runs a shell shortly after launch. Certificates are revoked only after the
  fact. Treating "signed + notarized" as trustworthy is therefore unsafe.

This helper assigns the normal signing trust credit (negative = more trusted),
but REVOKES that credit and applies a penalty when a signed/notarized sample
also exhibits run-only/compiled AppleScript or a suspicious-string category
match — behavioral-suspicion evidence that the sample does something a
legitimately signed app shouldn't, regardless of its signing claim.

It runs AFTER obfuscation detection so it can read top-level
features["applescript_analysis"]["runonly_applescript"], and after binary/string
analysis so it can read the suspicious-string category matches at top-level
features["strings_of_interest"] — the same field shape on both pipelines. There
is no dedicated ClickFix-delivery detector (ClickFix
itself is a social-engineering technique — a fake support/CAPTCHA page tricking a user
into pasting and running a command — that happens before a sample is even dropped, not
something static analysis of the binary observes directly); this gate is sourced from
those two already-computed detectors instead.
Weights are provisional and intended for recalibration against a labeled set.

## Trust requires verification

A second, independent gate: trust credit is only ever granted when the
signature was *cryptographically verified*. ``features["signature"]`` carries a
``verification`` field with three levels (shared vocabulary with
``macskillet.machopy.signature_analyzer`` — keep the string values in sync):

``"cryptographic"``
    Fully verified: either codesign/spctl validated against the system trust
    store, or (off macOS) ``machopy.code_signature_verifier`` independently
    recomputed the page hashes, verified the CMS signature, and checked the
    certificate chain against pinned Apple roots. Both mean the same thing —
    this is not a lesser verification, see that module's docstring for the
    four-link breakdown of what it actually proves.

``"invalid"``
    A cryptographic check was *attempted and failed* — a broken page hash
    (signature copied from a different binary), a CMS signature that doesn't
    verify, or a chain that doesn't reach a pinned root. This is evidence of
    tampering, not absence of information, and is treated worse than an
    ordinary unsigned binary: something went to the trouble of *looking*
    signed and failed the check, which unsigned malware doesn't bother with.

``"unverified"``
    No cryptographic determination was reached — several distinct causes, not
    one: no signature present at all; a signature present but with nothing
    cryptographic to check (ad-hoc, no CMS blob); a missing dependency; no
    pinned roots to anchor the chain; or (historically, before the offline
    verifier existed) identity merely read from certificate ASCII without
    validation. A binary can simply *contain* the bytes "Apple Root CA" or a
    Developer ID common name and be reported as signed by them under this
    level, so it earns no credit regardless of which cause produced it.

Granting negative (trusting) credit on an unverified claim is forgeable with a
string literal — that is the whole reason this gate exists. Under
``unverified``, trust credit is clamped to zero: penalties still apply, since
the *absence* of a signature blob is reliably observable without a trust
store, while unverified presence proves nothing.

A missing ``verification`` field is treated as unverified. That direction costs
a benign sample a small trust credit; the other direction hands trust to
whatever asserts it.
"""

from typing import Any

# Normal signing trust credit (negative = trust, positive = risk).
# Mirrors docs/references-native/risk-signals.md. Provisional.
_BASE_CREDIT = {
    "apple_signed": -2,
    "developer_id": -1,   # only when also notarized; see _base_credit_for()
    "other_signed": 2,
    "ad_hoc": 3,
    "unsigned": 4,
}

# Behavioral suspicious-string categories (from common.strings) that indicate
# the signed trust should not be honored. Deliberately narrow, matching the
# scope of the prior ClickFix-era {"delivery", "script_editor", "exfil"} set:
# harvest/anti-analysis/persistence-flavored categories (tcc_abuse,
# dev_secret_harvest, shell_config_persistence, browser_data, crypto_wallet,
# keychain_access, anti_vm, cloud_hosting_abuse) stay informational only and
# do not revoke trust on their own.
_SUSPICIOUS_CATEGORIES = {
    "gatekeeper_bypass",
    "automation",
    "download_execute",
    "cloud_c2_exfil",
    "malware_family_marker",
}

# Penalty applied when a signed/notarized sample behaves maliciously.
_OVERRIDE_PENALTY = 3

# Penalty for a signature that was cryptographically checked and found
# broken. Worse than "unsigned" (+4): unsigned malware didn't bother trying
# to look trustworthy, this did and got caught — that is deliberate deception,
# not merely an absence of signing effort.
_TAMPER_PENALTY = 5

# Verification levels — see this module's docstring. Must match the string
# values produced by macskillet.machopy.signature_analyzer.
VERIFIED = "cryptographic"
INVALID = "invalid"


def _is_verified(sig: dict) -> bool:
    """True only if the signature was cryptographically verified.

    Fails closed: anything other than an explicit "cryptographic" — including
    a missing field — counts as unverified.
    """
    return sig.get("verification") == VERIFIED


def _is_tamper_detected(sig: dict) -> bool:
    """True if a cryptographic check was attempted and found the signature broken."""
    return sig.get("verification") == INVALID


def _base_credit_for(signing_status: str, notarized: bool) -> int:
    """Normal trust credit before verification and behavioral overrides."""
    if signing_status == "developer_id":
        # Developer ID earns a trust credit only if also notarized.
        return -1 if notarized else 0
    return _BASE_CREDIT.get(signing_status, 0)


def _findings_are_suspicious(findings: list) -> bool:
    return any(f.get("category") in _SUSPICIOUS_CATEGORIES for f in findings)


def _has_suspicious_behavior(features: dict) -> bool:
    """True if obfuscation, suspicious-string, or deep-scan analysis found
    run-only AppleScript or a suspicious-string category match — in the main
    binary or in any embedded item a --deep scan inspected.

    Checks top-level features["applescript_analysis"]["runonly_applescript"],
    the same path on both pipelines (the applescript_analysis wrapper key is
    deliberately named differently from its own inner runonly_applescript
    boolean, so the two can't be confused or truth-tested interchangeably).
    Also checks the suspicious-string findings at the top-level
    features["strings_of_interest"] (both pipelines populate this same
    field from the same category taxonomy, so this half works identically on
    either pipeline), and every features["deep_scan"]["scanned"] entry (an
    embedded AppleScript file or Mach-O binary a --deep scan inspected) for
    the same two signals. A malicious payload stashed outside the main
    executable must not be invisible to this gate merely because it isn't
    the main binary.
    """
    if (features.get("applescript_analysis") or {}).get("runonly_applescript"):
        return True

    findings = features.get("strings_of_interest") or []
    if _findings_are_suspicious(findings):
        return True

    deep_scan = features.get("deep_scan") or {}
    for entry in deep_scan.get("scanned", []):
        analysis = entry.get("analysis") or {}
        if (analysis.get("applescript_analysis") or {}).get("runonly_applescript"):
            return True
        if _findings_are_suspicious(analysis.get("strings_of_interest") or []):
            return True

    return False


def assess_signature_trust(features: dict) -> dict:
    sig = features.get("signature") or {}

    signing_status = sig.get("signing_status", "unsigned")
    verified = _is_verified(sig)
    tamper_detected = _is_tamper_detected(sig)
    verification = sig.get("verification") or "unknown"

    # Notarization is a Gatekeeper ticket check with no offline answer, so a
    # claim of it under an unverified signature is not evidence. Kept only
    # for labelling; the credit gate below is what actually withholds trust.
    claimed_notarized = bool(sig.get("notarized"))
    notarized = claimed_notarized and verified

    # Start from what the signature *claims*, then let the verification gate
    # decide whether that claim is worth anything. Computing the credit from
    # the already-downgraded notarization would zero it first and hide the
    # withholding, so an unverified apple_signed would look merely uncredited
    # rather than explicitly distrusted.
    claimed_credit = _base_credit_for(signing_status, claimed_notarized)
    base_credit = claimed_credit

    reasons = []
    override_applied = False
    credit_withheld = False

    # Gate 0: a signature that was cryptographically checked and found broken
    # is not "we don't know" — it's evidence someone tried to forge trust and
    # failed (a page hash that doesn't match this binary, a CMS signature
    # that doesn't verify, a chain that doesn't reach a pinned root). This
    # fires independently of behavioral-suspicion corroboration and short-circuits the
    # rest of the assessment — nothing below this outweighs caught tampering.
    if tamper_detected:
        credit_withheld = True
        base_credit = 0
        adjustment = _TAMPER_PENALTY
        trust_level = "signature_invalid"
        reasons.append(
            f"{signing_status} claimed but the signature failed cryptographic "
            f"verification — treated as tamper evidence, penalty {adjustment:+d} applied "
            f"(worse than unsigned: this tried to look trustworthy and failed the check)"
        )
        if _has_suspicious_behavior(features):
            reasons.append("also exhibits run-only AppleScript or suspicious-string evidence")
        return {
            "trust_level": trust_level,
            "base_credit": base_credit,
            "claimed_credit": claimed_credit,
            "adjustment": adjustment,
            "override_applied": False,
            "verification": verification,
            "verified": verified,
            "tamper_detected": True,
            "credit_withheld": credit_withheld,
            "reasons": reasons,
            "summary": reasons[0],
        }

    # Gate 1: unverified signatures never earn trust, but still incur penalties.
    if base_credit < 0 and not verified:
        credit_withheld = True
        base_credit = 0
        reasons.append(
            f"{signing_status} claimed but verification is '{verification}' — "
            f"signing identity was parsed, not validated; trust credit "
            f"{claimed_credit:+d} withheld"
        )

    earns_credit = base_credit < 0
    suspicious = _has_suspicious_behavior(features)

    # Gate 2: a sample that presents as signed but has run-only AppleScript or
    # a suspicious-string category match gets a penalty. This fires whether
    # the signature was verified or merely claimed — the MacSync / Odyssey
    # pattern is exactly "looks signed, acts malicious", and a forged claim is
    # not less alarming than a real certificate.
    if suspicious and (earns_credit or credit_withheld):
        override_applied = True
        adjustment = _OVERRIDE_PENALTY
        trust_level = "suspicious_signed"
        label = "notarized" if notarized else signing_status
        reasons.append(
            f"{label} sample exhibits run-only AppleScript or suspicious-string "
            f"evidence — signing trust credit revoked (was {claimed_credit:+d}), "
            f"penalty {adjustment:+d} applied"
        )
    else:
        adjustment = base_credit
        if earns_credit:
            trust_level = "trusted"
            reasons.append(f"{signing_status} (notarized={notarized}) — trust credit {adjustment:+d}")
        elif credit_withheld:
            trust_level = "unverified_signature"
        else:
            trust_level = "untrusted"
            reasons.append(f"{signing_status} — no trust credit, adjustment {adjustment:+d}")

    return {
        "trust_level": trust_level,
        "base_credit": base_credit,
        "claimed_credit": claimed_credit,
        "adjustment": adjustment,
        "override_applied": override_applied,
        "verification": verification,
        "verified": verified,
        "tamper_detected": False,
        "credit_withheld": credit_withheld,
        "reasons": reasons,
        "summary": reasons[0] if reasons else "",
    }
