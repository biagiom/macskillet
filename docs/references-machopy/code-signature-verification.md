# Offline Code-Signature Verification

`src/macskillet/machopy/code_signature_verifier.py` lets the `portable` backend verify an
Apple code signature without macOS — not by reading certificate text, but by independently
re-deriving the same cryptographic proof `codesign --verify` produces.

## The four links

`codesign --verify` proves a signature is valid by checking four separate links. Each one
blocks a distinct forgery.

| # | Link | What it proves | What forging it requires |
|---|------|-----------------|---------------------------|
| 1 | Page hashes | SHA-256 of every page of the actual binary matches the CodeDirectory's hash slots | Rewriting every page hash for the attacker's own binary |
| 2 | CodeDirectory → CMS binding | The CMS `message_digest` attribute matches *this* CodeDirectory, not a swapped one | Forging the CMS signature over a different digest |
| 3 | CMS signature | A private key really signed that digest | Holding the leaf certificate's private key |
| 4 | Certificate chain | The signing key traces to a pinned Apple root | Holding a key that traces to Apple's actual root, or forging a certificate whose signature verifies under Apple's real root public key |

**Why link 1 exists on its own:** copy a real app's whole `LC_CODE_SIGNATURE` onto malware
(a *blob transplant*). Links 2–4 all pass — the CodeDirectory, CMS signature, and
certificate chain are internally consistent, they just describe someone else's binary.
Only recomputing page hashes against *this* binary's actual bytes reveals the mismatch.

**Why link 4 checks a pinned key, not a pinned name:** a self-signed certificate can
simply be *named* "Apple Root CA". Link 4 verifies the terminal certificate's signature
against the public key in a certificate this project ships
(`src/macskillet/machopy/certs/`, sourced from apple.com/certificateauthority), never
against whatever key the binary's own signature blob happens to provide. A same-named
forgery fails here regardless of what it claims, because its self-signature verifies
under the attacker's key, not Apple's.

## A fifth, optional link: the RFC 3161 timestamp token

Links 1–4 establish that a real private key signed this exact binary — but the expiry check
(below) trusts the CMS `signing_time` attribute, which is self-declared by the signer, using
the *same* key as everything else. A signer who still holds the private key for a certificate
that has since expired or been revoked can forge `signing_time` to a date inside the
certificate's original validity window while actually signing today, and links 1–4 would still
all pass.

When `codesign --timestamp` was used to sign, the CMS carries a `signature_time_stamp_token`
unsigned attribute — an RFC 3161 timestamp token, itself a nested CMS `SignedData` wrapping a
`TSTInfo`. This module independently verifies it:
1. `TSTInfo.messageImprint` must match a hash of the *outer CMS signature bytes themselves* —
   confirmed empirically against a real `--timestamp`-signed binary. This is what makes the
   token unforgeable-by-substitution: forging `signing_time` changes `signed_attrs`, which
   forces a brand-new signature value, invalidating any previously-issued token's imprint match.
2. the token's own CMS signature is verified under its signer certificate;
3. the token's certificate chain must resolve to a pinned root — empirically, Apple's timestamp
   authority chain (`Timestamp Signer RNO1` → `Apple Timestamp Certification Authority`) already
   terminates at the same pinned `Apple Root CA` used for links 1–4, so no additional certificate
   needed sourcing or pinning.

A **present** token that fails any of these three checks is tamper evidence (folded into the
same `tamper_detected`/`"invalid"` outcome as a broken link 1–4). A token's **absence** is not
evidence of anything — many legitimate signatures (ad-hoc, older tooling, `codesign` without
`--timestamp`) never carry one, and the expiry check falls back to the self-declared
`signing_time` exactly as before. This is an inherent limit, not an oversight: nothing but a
trusted third-party countersignature can catch a forged `signing_time`, so unstamped signatures
remain as exposed to this specific lie as they were before this link existed.

## `verification` levels

Every signature result (`features["signature"]["verification"]`) carries one of three values:

- **`cryptographic`** — fully verified, either by `codesign`/`spctl` on macOS or by this
  module off macOS. Equivalent outcomes, not a lesser fallback.
- **`invalid`** — a cryptographic check was attempted and failed: a broken page hash, a
  CMS signature that doesn't verify, or a chain that doesn't reach a pinned root. This is
  *evidence of tampering*, not absence of information — `signature_trust.py` weights it
  worse than an unsigned binary, since something tried to look trustworthy and got caught.
- **`unverified`** — no cryptographic determination was reached. Several independent causes
  fall under this one value, all treated identically by trust logic: no signature present at
  all; a signature present with nothing cryptographic to check (ad-hoc, no CMS blob); a
  missing dependency (`asn1crypto` not installed, or off the LIEF path entirely); or no pinned
  root certificates available to anchor the chain. None of these is evidence of tampering —
  trust logic must not treat `unverified` as equivalent to `cryptographic`, but must also not
  treat it as equivalent to `invalid`.

## What is deliberately not verified

Bundle resources (`_CodeResources`, hash slot -3) and `Info.plist` (slot -1) are reported
as present but not verified — that requires interpreting Apple's resource-rules plist
grammar, a project on its own, and `codesign` already does it natively on the platform
where that matters most.

## Expiry and revocation

Certificate expiry is checked against a signing-time reference, never against wall-clock
"now" — a code-signing certificate legitimately expires years after a binary was signed, and
checking against the current time would flag every untouched old app as expired. That
reference is, in priority order: a verified RFC 3161 timestamp token's `genTime` (see above),
when present and valid; otherwise the self-declared CMS `signing_time`. When neither is
available, the expiry check is skipped (`expired: None`) rather than guessed.

Revocation (OCSP) requires network access, which this module never initiates unless
explicitly asked: pass `check_revocation=True` to `verify_code_signature()`. This is the
only place in the entire codebase that touches the network. It is deliberately excluded
from `fully_verified` — the four links above establish a fact about the past (this
signature is real and covers this exact binary); revocation is a fact about now, and
conflating the two would make `fully_verified` flap on network availability. A revoked
certificate is reported separately, under each slice's `chain.revocation`.
