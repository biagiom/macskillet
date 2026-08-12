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
also exhibits ClickFix-style delivery, script-editor, or exfiltration behavior.

It runs AFTER detect_clickfix() so it can read features["clickfix"].
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

``"structural"``
    No verification was possible — dependency missing, no signature present,
    or (historically, before the offline verifier existed) identity merely
    read from certificate ASCII without validation. A binary can simply
    *contain* the bytes "Apple Root CA" or a Developer ID common name and be
    reported as signed by them under this level, so it earns no credit.

Granting negative (trusting) credit on an unverified claim is forgeable with a
string literal — that is the whole reason this gate exists. Under
``structural``, trust credit is clamped to zero: penalties still apply, since
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

# Behavioral categories (from clickfix detector) that indicate the signed
# trust should not be honored.
_SUSPICIOUS_CATEGORIES = {"delivery", "script_editor", "exfil"}

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


def _has_suspicious_behavior(clickfix: dict) -> bool:
    if clickfix.get("clickfix_suspected"):
        return True
    for ind in clickfix.get("matched_indicators", []):
        if ind.get("category") in _SUSPICIOUS_CATEGORIES:
            return True
    return False


def assess_signature_trust(features: dict) -> dict:
    sig = features.get("signature") or {}
    clickfix = features.get("clickfix") or {}

    signing_status = sig.get("signing_status", "unsigned")
    verified = _is_verified(sig)
    tamper_detected = _is_tamper_detected(sig)
    verification = sig.get("verification") or "unknown"

    # Notarization is a Gatekeeper ticket check with no offline answer, so a
    # claim of it under structural parsing is not evidence. Kept only for
    # labelling; the credit gate below is what actually withholds trust.
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
    # fires independently of ClickFix corroboration and short-circuits the
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
        if _has_suspicious_behavior(clickfix):
            reasons.append("also exhibits ClickFix-style delivery/exfil behavior")
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
    suspicious = _has_suspicious_behavior(clickfix)

    # Gate 2: a sample that presents as signed and behaves like ClickFix gets a
    # penalty. This fires whether the signature was verified or merely claimed —
    # the MacSync / Odyssey pattern is exactly "looks signed, acts malicious",
    # and a forged claim is not less alarming than a real certificate.
    if suspicious and (earns_credit or credit_withheld):
        override_applied = True
        adjustment = _OVERRIDE_PENALTY
        trust_level = "suspicious_signed"
        label = "notarized" if notarized else signing_status
        reasons.append(
            f"{label} sample exhibits ClickFix-style delivery/exfil behavior — "
            f"signing trust credit revoked (was {claimed_credit:+d}), "
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
