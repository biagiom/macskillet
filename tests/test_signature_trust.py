"""
test_signature_trust.py — Unit tests for signature_trust.py

Risk-signal helper implementing the "notarized != safe" finding from the
2026 vendor-blog literature synthesis: a Developer-ID-signed / notarized app
that ALSO exhibits ClickFix-style delivery/exfil behavior must NOT receive the
normal signing trust credit — the credit is revoked and a penalty applied.

Run from repo root:
    PYTHONPATH=src/native python3 -m pytest tests/test_signature_trust.py -v
"""

import sys
import os


from macskillet.native.signature_trust import assess_signature_trust


def make_features(signing_status="unsigned", notarized=False, clickfix=None,
                  verification="cryptographic"):
    """Build a minimal features dict for signature-trust testing.

    Defaults to ``verification="cryptographic"`` to match what the native
    (codesign-backed) extractor produces. Pass ``"structural"`` to model the
    cross-platform pipeline, or ``None`` to model a features blob predating
    the field.
    """
    signature = {
        "signed": signing_status not in ("unsigned",),
        "signing_status": signing_status,
        "notarized": notarized,
    }
    if verification is not None:
        signature["verification"] = verification
    return {
        "signature": signature,
        "clickfix": clickfix or {
            "clickfix_suspected": False,
            "matched_indicators": [],
        },
    }


CLICKFIX_HIT = {
    "clickfix_suspected": True,
    "matched_indicators": [
        {"indicator": "do shell script", "category": "script_editor",
         "risk": "HIGH", "detail": ""},
    ],
}


class TestTrustCreditRevocation:

    def test_notarized_but_clickfix_revokes_trust_credit(self):
        """Developer-ID + notarized app showing ClickFix behavior loses its
        trust credit and gets a positive penalty instead."""
        features = make_features(
            signing_status="developer_id",
            notarized=True,
            clickfix={
                "clickfix_suspected": True,
                "matched_indicators": [
                    {"indicator": "do shell script", "category": "script_editor",
                     "risk": "HIGH", "detail": ""},
                ],
            },
        )
        result = assess_signature_trust(features)
        assert result["override_applied"] is True
        assert result["trust_level"] == "suspicious_signed"
        assert result["adjustment"] > 0

    def test_notarized_clean_app_keeps_trust_credit(self):
        """BENIGN REGRESSION GUARD: a notarized app with no suspicious behavior
        must keep its negative trust credit and NOT be penalized."""
        features = make_features(signing_status="developer_id", notarized=True)
        result = assess_signature_trust(features)
        assert result["override_applied"] is False
        assert result["trust_level"] == "trusted"
        assert result["adjustment"] < 0

    def test_apple_signed_clean_is_trusted(self):
        features = make_features(signing_status="apple_signed", notarized=True)
        result = assess_signature_trust(features)
        assert result["override_applied"] is False
        assert result["adjustment"] == -2


class TestSigningTierMapping:

    def test_unsigned_gets_positive_adjustment(self):
        features = make_features(signing_status="unsigned")
        result = assess_signature_trust(features)
        assert result["adjustment"] == 4
        assert result["trust_level"] == "untrusted"

    def test_ad_hoc_gets_positive_adjustment(self):
        features = make_features(signing_status="ad_hoc")
        result = assess_signature_trust(features)
        assert result["adjustment"] == 3

    def test_developer_id_without_notarization_earns_no_credit(self):
        """Developer ID signing alone (not notarized) is not a trust signal."""
        features = make_features(signing_status="developer_id", notarized=False)
        result = assess_signature_trust(features)
        assert result["adjustment"] == 0
        assert result["override_applied"] is False

    def test_unsigned_with_clickfix_not_overridden_just_untrusted(self):
        """No trust credit to revoke -> no override, stays its base risk."""
        features = make_features(
            signing_status="unsigned",
            clickfix={"clickfix_suspected": True,
                      "matched_indicators": [
                          {"indicator": "base64 -d", "category": "delivery",
                           "risk": "HIGH", "detail": ""}]},
        )
        result = assess_signature_trust(features)
        assert result["override_applied"] is False
        assert result["adjustment"] == 4


class TestOutputContract:

    def test_always_has_required_fields(self):
        result = assess_signature_trust(make_features())
        for field in ["trust_level", "base_credit", "adjustment",
                      "override_applied", "reasons", "summary"]:
            assert field in result

    def test_handles_missing_signature_block(self):
        result = assess_signature_trust({})
        assert result["override_applied"] is False
        assert isinstance(result["adjustment"], int)


class TestVerificationGate:
    """Trust credit requires a cryptographically verified signature.

    Under structural parsing the signing identity is read as ASCII from the
    certificate chain, so a binary that merely *contains* "Apple Root CA" or a
    Developer ID common name reports as signed by them. Granting negative
    credit on that is forgeable with a string literal.
    """

    def test_structural_apple_signed_gets_no_trust_credit(self):
        features = make_features(signing_status="apple_signed", notarized=True,
                                 verification="structural")
        result = assess_signature_trust(features)
        assert result["adjustment"] == 0
        assert result["credit_withheld"] is True
        assert result["claimed_credit"] == -2
        assert result["trust_level"] == "unverified_signature"

    def test_structural_developer_id_gets_no_trust_credit(self):
        features = make_features(signing_status="developer_id", notarized=True,
                                 verification="structural")
        result = assess_signature_trust(features)
        assert result["adjustment"] == 0
        assert result["verified"] is False

    def test_missing_verification_field_fails_closed(self):
        """A features blob predating the field must not earn trust by default."""
        features = make_features(signing_status="apple_signed", verification=None)
        result = assess_signature_trust(features)
        assert result["adjustment"] == 0
        assert result["credit_withheld"] is True
        assert result["verification"] == "unknown"

    def test_penalties_still_apply_without_verification(self):
        """Absence of a signature is observable without a trust store."""
        for status, expected in (("unsigned", 4), ("ad_hoc", 3), ("other_signed", 2)):
            result = assess_signature_trust(
                make_features(signing_status=status, verification="structural")
            )
            assert result["adjustment"] == expected, status
            assert result["credit_withheld"] is False

    def test_structural_signed_with_clickfix_still_penalized(self):
        """Claiming a signature while behaving like ClickFix is not less alarming."""
        features = make_features(signing_status="developer_id", notarized=True,
                                 verification="structural", clickfix=CLICKFIX_HIT)
        result = assess_signature_trust(features)
        assert result["override_applied"] is True
        assert result["trust_level"] == "suspicious_signed"
        assert result["adjustment"] > 0

    def test_verified_path_is_unchanged(self):
        """Regression guard: the codesign-backed path keeps its old behaviour."""
        result = assess_signature_trust(
            make_features(signing_status="apple_signed", notarized=True)
        )
        assert result["adjustment"] == -2
        assert result["verified"] is True
        assert result["credit_withheld"] is False
        assert result["trust_level"] == "trusted"

    def test_notarized_claim_ignored_without_verification(self):
        """Notarization is a Gatekeeper ticket check with no offline answer."""
        features = make_features(signing_status="developer_id", notarized=True,
                                 verification="structural")
        result = assess_signature_trust(features)
        assert "notarized=True" not in result["summary"]

    def test_reason_names_the_verification_level(self):
        features = make_features(signing_status="apple_signed", verification="structural")
        result = assess_signature_trust(features)
        assert "structural" in result["summary"]
        assert "withheld" in result["summary"]


class TestTamperDetectedGate:
    """A signature that was cryptographically checked and found broken.

    This is what code_signature_verifier reports when page hashes don't
    match the binary's actual bytes (blob transplant), the CMS signature
    doesn't verify, or the certificate chain doesn't reach a pinned root.
    It is evidence, not silence -- distinct from "structural" (never checked)
    and worse than "unsigned" (didn't even try to look trustworthy).
    """

    def test_invalid_verification_gets_tamper_penalty(self):
        features = make_features(signing_status="apple_signed", notarized=True,
                                 verification="invalid")
        result = assess_signature_trust(features)
        assert result["adjustment"] == 5
        assert result["tamper_detected"] is True
        assert result["trust_level"] == "signature_invalid"
        assert result["credit_withheld"] is True

    def test_tamper_penalty_worse_than_unsigned(self):
        tampered = assess_signature_trust(
            make_features(signing_status="apple_signed", verification="invalid")
        )
        unsigned = assess_signature_trust(
            make_features(signing_status="unsigned", verification="structural")
        )
        assert tampered["adjustment"] > unsigned["adjustment"]

    def test_tamper_gate_fires_regardless_of_clickfix(self):
        """Tampering is independently alarming -- no ClickFix corroboration needed."""
        clean = assess_signature_trust(
            make_features(signing_status="developer_id", notarized=True, verification="invalid")
        )
        with_clickfix = assess_signature_trust(
            make_features(signing_status="developer_id", notarized=True,
                         verification="invalid", clickfix=CLICKFIX_HIT)
        )
        assert clean["adjustment"] == with_clickfix["adjustment"] == 5
        assert "also exhibits ClickFix" in with_clickfix["summary"] or any(
            "ClickFix" in r for r in with_clickfix["reasons"]
        )

    def test_tamper_gate_takes_precedence_over_credit(self):
        """Even a claimed apple_signed (normally -2) gets the tamper penalty, not 0."""
        result = assess_signature_trust(
            make_features(signing_status="apple_signed", notarized=True, verification="invalid")
        )
        assert result["claimed_credit"] == -2
        assert result["base_credit"] == 0
        assert result["adjustment"] == 5

    def test_verified_field_false_when_tampered(self):
        result = assess_signature_trust(
            make_features(signing_status="apple_signed", verification="invalid")
        )
        assert result["verified"] is False
