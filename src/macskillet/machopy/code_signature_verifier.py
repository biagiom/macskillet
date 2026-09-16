"""
code_signature_verifier.py — offline Apple code-signature verification.

``codesign --verify`` proves a signature is valid by checking four separate
links. Each one blocks a distinct forgery:

    link 1   page hashes        SHA-256 of every 4KB page of the binary,
                                 stored in the CodeDirectory's hash slots
    link 2   CodeDirectory hash  SHA-256 of the CodeDirectory blob itself,
                                 carried in the CMS message_digest attribute
    link 3   CMS signature       proves a private key signed that digest
    link 4   certificate chain   proves that key traces to a pinned Apple root

``signature_analyzer._read_signing_identity`` (the module this replaces as
the trust source) only ever reached link 4, and reached it by regexing ASCII
out of the certificate chain rather than verifying anything — a binary that
merely *contains* the bytes "Developer ID Application: X (TEAMID1234)" was
reported as signed by X. This module implements all four links so trust
credit can be granted without macOS.

What breaks each link, and what this module catches:

    link 1   blob transplant — copy a real app's whole LC_CODE_SIGNATURE
             onto malware. Links 2-4 all pass (the CD, the CMS signature and
             the certs are internally consistent, just describe someone
             else's binary). Only recomputing page hashes against *this*
             binary's actual bytes reveals the CodeDirectory belongs to a
             different file.
    link 2   swap the CodeDirectory for one with different flags/identifier
             after signing, without redoing the CMS signature.
    link 3   forge a CMS blob without holding the leaf certificate's key.
    link 4   embed a self-signed certificate merely *named* "Apple Root
             CA" — the terminal certificate's signature is verified against
             the actual public key in a pinned root file, not against
             whatever key the blob happens to carry, so a same-named forgery
             fails signature verification regardless of what it claims.

## What is deliberately NOT verified

Bundle resources (``_CodeResources``, hash slot -3) and ``Info.plist``
(slot -1) are reported as present but not verified. Doing so requires
interpreting Apple's resource-rules plist grammar (include/exclude globs,
per-file omissions) — a project on its own, and macOS's own ``codesign``
already does it natively, so the native pipeline does not need this module
to reach full verification.

Certificate expiry is checked against the CMS ``signing_time`` attribute when
present, never against wall-clock "now" — a code-signing cert legitimately
expires years after a binary was signed, and checking against the current
time would flag every untouched old app as expired. When ``signing_time``
isn't available the expiry check is skipped (reported as ``None``) rather
than guessed.

Revocation (OCSP) requires network access, which this module **never
initiates unless explicitly asked**: pass ``check_revocation=True`` to
:func:`verify_code_signature`. It is not part of ``fully_verified`` — the
four links above establish "this signature is real and covers this exact
binary", which is a fact about the past; revocation is a fact about now, and
conflating the two would make ``fully_verified`` flap on network
availability. A revoked certificate is reported in ``chain.revocation``
regardless of how the other four links came out.

## Result levels

``fully_verified=True``
    All four links check out for at least one signed architecture slice, and
    none failed. Equivalent to ``codesign --verify`` (minus revocation).

``fully_verified=False`` with ``tamper_detected=True``
    A cryptographic check was attempted and failed — a broken page hash, a
    CMS signature that doesn't verify, or a chain that doesn't reach a
    pinned root. This is *evidence*, not silence: report it as more
    alarming than an ordinary unsigned binary, not merely "unknown".

``fully_verified=False`` with ``tamper_detected=False``
    No signature was present to check, or every slice was unsigned.
"""

from __future__ import annotations

import hashlib
import os
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

__all__ = ["verify_code_signature", "load_pinned_roots", "check_revocation", "CERTS_DIR"]

# ---------------------------------------------------------------------------
# Apple code-signing constants (bsd/sys/codesign.h, cs_blobs.h)
# ---------------------------------------------------------------------------

CSMAGIC_CODEDIRECTORY = 0xFADE0C02
CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0  # SuperBlob wrapping everything below
CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xFADE7171
CSMAGIC_EMBEDDED_DER_ENTITLEMENTS = 0xFADE7172
CSMAGIC_BLOBWRAPPER = 0xFADE0B01  # wraps the CMS SignedData

CSSLOT_CODEDIRECTORY = 0
CSSLOT_INFOSLOT = 1
CSSLOT_REQUIREMENTS = 2
CSSLOT_RESOURCEDIR = 3
CSSLOT_APPLICATION = 4
CSSLOT_ENTITLEMENTS = 5
CSSLOT_REP_SPECIFIC = 6
CSSLOT_ENTITLEMENTS_DER = 7
CSSLOT_SIGNATURESLOT = 0x10000

#: Index types that hold a CodeDirectory. 0 is primary; 0x1000+ are
#: alternates carrying the same content hashed with a different algorithm
#: (modern macOS signs with both SHA-1 and SHA-256 for compatibility).
_CODE_DIRECTORY_SLOT_TYPES = {0, 0x1000, 0x1001, 0x1002, 0x1003, 0x1004}

#: hashType -> (hashlib name, digest bytes actually stored in the slot).
#: Type 3 truncates a SHA-256 digest to the first 20 bytes.
_HASH_TYPES = {
    1: ("sha1", 20),
    2: ("sha256", 32),
    3: ("sha256", 20),
    4: ("sha384", 48),
}

#: Streamed read size for page hashing. Never materializes the whole file.
_READ_CHUNK = 1 << 20

CERTS_DIR = Path(__file__).parent / "certs"


# ---------------------------------------------------------------------------
# Pinned roots
# ---------------------------------------------------------------------------

def load_pinned_roots(certs_dir: Path = CERTS_DIR):
    """Load every ``*.cer`` in ``certs_dir`` as a parsed X.509 certificate.

    These are Apple's public root and intermediate certificates, fetched
    from https://www.apple.com/certificateauthority/ — the same source
    browsers and ``codesign`` itself ultimately trust. Being public is the
    point: pinning does not require secrecy, only that *this* copy cannot be
    substituted by whatever the binary being analyzed provides.
    """
    from cryptography import x509

    roots = []
    if not certs_dir.is_dir():
        return roots
    for cer_path in sorted(certs_dir.glob("*.cer")):
        try:
            roots.append(x509.load_der_x509_certificate(cer_path.read_bytes()))
        except ValueError:
            continue
    return roots


# ---------------------------------------------------------------------------
# SuperBlob / CodeDirectory parsing
# ---------------------------------------------------------------------------

@dataclass
class CodeDirectory:
    offset: int          # offset of this CD within the code-signature blob
    length: int
    version: int
    flags: int
    hash_offset: int
    ident_offset: int
    n_special_slots: int
    n_code_slots: int
    code_limit: int
    hash_size: int
    hash_type: int
    platform: int
    page_size: int       # already resolved to bytes (0 => whole codeLimit)
    team_id: str | None
    identifier: str
    raw: bytes            # the CD blob's own bytes, for hashing (link 2)


def _read_cstr(data: bytes, offset: int) -> str:
    end = data.find(b"\x00", offset)
    if end == -1:
        end = len(data)
    return data[offset:end].decode("utf-8", errors="replace")


def _parse_code_directory(cs: bytes, offset: int) -> CodeDirectory | None:
    if offset + 44 > len(cs):
        return None
    magic, length, version = struct.unpack(">III", cs[offset:offset + 12])
    if magic != CSMAGIC_CODEDIRECTORY:
        return None
    (flags, hash_offset, ident_offset, n_special_slots,
     n_code_slots, code_limit) = struct.unpack(">IIIIII", cs[offset + 12:offset + 36])
    hash_size, hash_type, platform, page_size_log = cs[offset + 36:offset + 40]

    team_id = None
    if version >= 0x20200 and offset + 48 <= len(cs):
        (team_offset,) = struct.unpack(">I", cs[offset + 44:offset + 48])
        if team_offset:
            team_id = _read_cstr(cs, offset + team_offset) or None

    if version >= 0x20300 and offset + 60 <= len(cs):
        (code_limit_64,) = struct.unpack(">Q", cs[offset + 52:offset + 60])
        if code_limit_64:
            code_limit = code_limit_64

    page_size = (1 << page_size_log) if page_size_log else code_limit

    return CodeDirectory(
        offset=offset, length=length, version=version, flags=flags,
        hash_offset=offset + hash_offset, ident_offset=offset + ident_offset,
        n_special_slots=n_special_slots, n_code_slots=n_code_slots,
        code_limit=code_limit, hash_size=hash_size, hash_type=hash_type,
        platform=platform, page_size=page_size, team_id=team_id,
        identifier=_read_cstr(cs, offset + ident_offset),
        raw=cs[offset:offset + length],
    )


def _parse_superblob(cs: bytes) -> dict[int, int] | None:
    """Return ``{index_type: offset}`` for a SuperBlob, or ``None`` if malformed."""
    if len(cs) < 12:
        return None
    magic, _length, count = struct.unpack(">III", cs[0:12])
    if magic != CSMAGIC_EMBEDDED_SIGNATURE:
        return None
    entries = {}
    pos = 12
    for _ in range(count):
        if pos + 8 > len(cs):
            break
        index_type, index_offset = struct.unpack(">II", cs[pos:pos + 8])
        entries[index_type] = index_offset
        pos += 8
    return entries


def _blob_at(cs: bytes, offset: int) -> bytes:
    """A generic (magic, length, ...) blob's full bytes, header included.

    Special-slot hashes cover the whole blob — magic and length included,
    not just the payload — confirmed against a real signed binary.
    """
    if offset + 8 > len(cs):
        return b""
    _magic, length = struct.unpack(">II", cs[offset:offset + 8])
    return cs[offset:offset + length]


# ---------------------------------------------------------------------------
# Link 1: page hashes
# ---------------------------------------------------------------------------

def _hash_slot(cd: CodeDirectory, slot_index: int) -> bytes:
    """slot_index >= 0 for code slots, negative for special slots."""
    off = cd.hash_offset + slot_index * cd.hash_size
    return cd.raw[off - cd.offset:off - cd.offset + cd.hash_size] if 0 <= off - cd.offset else b""


def _hash_bytes(cd: CodeDirectory, data: bytes) -> bytes:
    algo_name, digest_len = _HASH_TYPES.get(cd.hash_type, ("sha256", 32))
    digest = hashlib.new(algo_name, data).digest()
    return digest[:digest_len]


def _verify_page_hashes(fh: BinaryIO, slice_offset: int, cd: CodeDirectory) -> tuple[bool, str | None]:
    """Recompute every code-slot hash by reading the binary's actual bytes.

    Streams the file in page-sized reads rather than loading it whole, so
    this stays bounded on large samples.
    """
    if cd.hash_type not in _HASH_TYPES:
        return False, f"unsupported hashType {cd.hash_type}"

    for i in range(cd.n_code_slots):
        start = slice_offset + i * cd.page_size
        end = min(slice_offset + (i + 1) * cd.page_size, slice_offset + cd.code_limit)
        if end <= start:
            break
        fh.seek(start)
        page = fh.read(end - start)
        computed = _hash_bytes(cd, page)
        stored = _hash_slot(cd, i)
        if computed != stored:
            return False, f"code slot {i} hash mismatch — binary content does not match signature"
    return True, None


def _verify_special_slot(cd: CodeDirectory, slot_number: int, blob: bytes) -> bool | None:
    """True/False if the slot is populated and checkable, None if absent."""
    if slot_number > cd.n_special_slots or not blob:
        return None
    computed = _hash_bytes(cd, blob)
    stored = _hash_slot(cd, -slot_number)
    return computed == stored


# ---------------------------------------------------------------------------
# Links 2 & 3: CodeDirectory hash -> CMS signature
# ---------------------------------------------------------------------------

def _verify_cms(cs: bytes, sig_offset: int, code_directories: list[CodeDirectory],
                pinned_roots: list) -> dict:
    result = {
        "present": False, "signature_valid": False, "cd_hash_matches": False,
        "signing_time": None, "signer_subject": None,
        "signer_common_name": None, "signer_team_id": None,
        "certificates": [],
        # RFC 3161 timestamp-token verification, when present — see
        # _verify_timestamp_token for why a verified token's genTime is
        # preferred over the self-declared signing_time above.
        "timestamp": {"present": False, "valid": False, "gen_time": None, "errors": []},
        # Verification could not be attempted (missing dependency, etc.) —
        # never evidence of tampering.
        "environment_errors": [],
        # A check was attempted and failed — this IS evidence.
        "errors": [],
    }
    blob = _blob_at(cs, sig_offset)
    if len(blob) <= 8:
        return result
    result["present"] = True
    cms_der = blob[8:]

    try:
        from asn1crypto.cms import CMSAttributes, ContentInfo
    except ImportError:
        result["environment_errors"].append(
            "asn1crypto not installed — cannot parse the CMS signature blob"
        )
        return result

    try:
        content_info = ContentInfo.load(cms_der)
        signed_data = content_info["content"]
        certs_asn1 = [c.chosen for c in signed_data["certificates"]]
        signer_infos = signed_data["signer_infos"]
    except Exception as exc:
        # A present-but-unparseable CMS blob on a binary that claims to be
        # signed is itself suspicious — unlike a missing dependency, this is
        # a property of the sample, not the environment.
        result["errors"].append(f"CMS parse failed: {exc}")
        return result
    if not signer_infos or not certs_asn1:
        result["errors"].append("CMS has no signer or no certificates")
        return result

    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes

    certs = [x509.load_der_x509_certificate(c.dump()) for c in certs_asn1]
    result["certificates"] = certs

    si = signer_infos[0]
    digest_algo_name = si["digest_algorithm"]["algorithm"].native
    hash_algo = {
        "sha1": hashes.SHA1(), "sha256": hashes.SHA256(),
        "sha384": hashes.SHA384(), "sha512": hashes.SHA512(),
    }.get(digest_algo_name)
    if hash_algo is None:
        result["errors"].append(f"unsupported CMS digest algorithm {digest_algo_name}")
        return result

    signed_attrs = si["signed_attrs"]
    message_digest = None
    for attr in signed_attrs:
        if attr["type"].native == "message_digest":
            message_digest = attr["values"].native[0]
        elif attr["type"].native == "signing_time":
            result["signing_time"] = attr["values"].native[0]

    # link 2: does the attested digest match a CodeDirectory we actually have?
    if message_digest is not None:
        result["cd_hash_matches"] = any(
            hashlib.new(digest_algo_name, cd.raw).digest() == message_digest
            for cd in code_directories
        )

    # Signed attributes are DER-tagged [0] IMPLICIT in the CMS structure but
    # must be re-encoded as an explicit SET OF for the signature to verify —
    # RFC 5652 §5.4. asn1crypto's CMSAttributes forces that re-encoding.
    attrs_out = CMSAttributes()
    for attr in signed_attrs:
        attrs_out.append(attr)
    signed_attrs_der = attrs_out.dump()

    signer_cert = _find_signer_cert(si, certs, certs_asn1)
    if signer_cert is None:
        result["errors"].append("could not identify signer certificate")
        return result
    result["signer_subject"] = signer_cert.subject.rfc4514_string()
    result["signer_common_name"], result["signer_team_id"] = _cert_identity(signer_cert)

    # CMS certificate order is not guaranteed to be leaf-first (confirmed:
    # Apple's own blobs sometimes list an intermediate before the leaf).
    # _verify_chain builds its chain starting from certs[0], and self-signed
    # / revocation checks operate on that same assumption -- so the identified
    # signer must be moved to the front, or both silently operate on the
    # wrong certificate (chain validity itself still comes out correct either
    # way, since it just walks issuer links, but the *leaf* would never be
    # the one actually checked).
    result["certificates"] = [signer_cert] + [c for c in certs if c is not signer_cert]

    signature = si["signature"].native
    try:
        _verify_signature(signer_cert.public_key(), signature, signed_attrs_der, hash_algo)
        result["signature_valid"] = True
    except InvalidSignature:
        result["errors"].append("CMS signature does not verify under signer certificate")
    except Exception as exc:
        result["errors"].append(f"CMS signature verification error: {exc}")

    result["timestamp"] = _verify_timestamp_token(si, signature, pinned_roots)
    if result["timestamp"]["present"] and not result["timestamp"]["valid"]:
        # A present-but-broken token doesn't vouch for this signature — real
        # evidence, not an absence. Folded into the same `errors` list the
        # outer CMS checks use so the existing tamper-detection branch in
        # _verify_slice (`if cms["errors"]: tamper_detected = True`) already
        # covers it without a second flagging path.
        result["errors"].extend(
            f"timestamp token: {e}" for e in result["timestamp"]["errors"]
        )

    return result


def _select_reference_time(cms: dict):
    """Pick the expiry-check reference time from a ``_verify_cms`` result.

    A verified timestamp token's ``genTime`` is a trusted third-party
    attestation, immune to a forged self-declared ``signing_time`` — prefer
    it whenever the token verified. A present-but-invalid token already sets
    ``tamper_detected`` via ``cms["errors"]``, so falling back to
    ``signing_time`` here in that case is harmless — the tamper flag is what
    actually matters for that outcome, not which time this function returns.
    """
    timestamp = cms["timestamp"]
    return timestamp["gen_time"] if timestamp["valid"] else cms.get("signing_time")


def _verify_timestamp_token(si, outer_signature: bytes, pinned_roots: list) -> dict:
    """Verify an RFC 3161 timestamp token attached to ``si``, if any.

    A verified token's ``genTime`` is a trusted third-party attestation of
    when this exact signature was made, immune to a self-declared signing_time
    lie: ``messageImprint`` binds to the *outer signature bytes themselves*,
    so forging signing_time changes signed_attrs, which forces a new
    signature value that no previously-issued token can match. See
    specs/macskillet-signature-verification's timestamp-token requirement.

    Returns ``{"present", "valid", "gen_time", "errors"}``. ``present=False``
    (no errors) means the signer simply didn't request a timestamp — common
    and not itself evidence of anything.
    """
    result = {"present": False, "valid": False, "gen_time": None, "errors": []}

    unsigned_attrs = si["unsigned_attrs"]
    if not unsigned_attrs.native:
        return result

    token_der = None
    for attr in unsigned_attrs:
        if attr["type"].native == "signature_time_stamp_token":
            token_der = attr["values"][0].dump()
            break
    if token_der is None:
        return result

    result["present"] = True

    try:
        from asn1crypto import tsp
        from asn1crypto.cms import CMSAttributes, ContentInfo
    except ImportError:
        result["errors"].append("asn1crypto not installed — cannot parse timestamp token")
        return result

    try:
        token_ci = ContentInfo.load(token_der)
        token_sd = token_ci["content"]
        econtent = token_sd["encap_content_info"]
        tst_info = tsp.TSTInfo.load(econtent["content"].parsed.dump())
        token_signer_infos = token_sd["signer_infos"]
        token_certs_asn1 = [c.chosen for c in token_sd["certificates"]]
    except Exception as exc:
        result["errors"].append(f"timestamp token parse failed: {exc}")
        return result

    if not token_signer_infos or not token_certs_asn1:
        result["errors"].append("timestamp token has no signer or no certificates")
        return result

    # Does the token's messageImprint actually cover *this* signature?
    mi = tst_info["message_imprint"]
    hash_algo_name = mi["hash_algorithm"]["algorithm"].native
    if hash_algo_name not in hashlib.algorithms_available:
        result["errors"].append(f"unsupported timestamp hash algorithm {hash_algo_name}")
        return result
    computed_imprint = hashlib.new(hash_algo_name, outer_signature).digest()
    if computed_imprint != mi["hashed_message"].native:
        result["errors"].append(
            "messageImprint does not match the outer signature — token does not "
            "vouch for this signature"
        )
        return result

    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes

    token_certs = [x509.load_der_x509_certificate(c.dump()) for c in token_certs_asn1]

    tsi = token_signer_infos[0]
    digest_algo_name = tsi["digest_algorithm"]["algorithm"].native
    hash_algo = {
        "sha1": hashes.SHA1(), "sha256": hashes.SHA256(),
        "sha384": hashes.SHA384(), "sha512": hashes.SHA512(),
    }.get(digest_algo_name)
    if hash_algo is None:
        result["errors"].append(f"unsupported timestamp CMS digest algorithm {digest_algo_name}")
        return result

    signed_attrs = tsi["signed_attrs"]
    tst_message_digest = None
    for attr in signed_attrs:
        if attr["type"].native == "message_digest":
            tst_message_digest = attr["values"].native[0]
    if tst_message_digest is None:
        result["errors"].append("timestamp token CMS has no message_digest attribute")
        return result

    encap_content_bytes = econtent["content"].parsed.dump()
    if hashlib.new(digest_algo_name, encap_content_bytes).digest() != tst_message_digest:
        result["errors"].append("timestamp token's message_digest does not match its TSTInfo content")
        return result

    # Same RFC 5652 §5.4 explicit re-encoding _verify_cms already relies on.
    attrs_out = CMSAttributes()
    for attr in signed_attrs:
        attrs_out.append(attr)
    signed_attrs_der = attrs_out.dump()

    signer_cert = _find_signer_cert(tsi, token_certs, token_certs_asn1)
    if signer_cert is None:
        result["errors"].append("could not identify timestamp token's signer certificate")
        return result

    tst_signature = tsi["signature"].native
    try:
        _verify_signature(signer_cert.public_key(), tst_signature, signed_attrs_der, hash_algo)
    except InvalidSignature:
        result["errors"].append("timestamp token's CMS signature does not verify")
        return result
    except Exception as exc:
        result["errors"].append(f"timestamp token signature verification error: {exc}")
        return result

    ordered_certs = [signer_cert] + [c for c in token_certs if c is not signer_cert]
    # No reference_time: this module deliberately doesn't check the TSA
    # certificate's own expiry window (see design.md's non-goals) — only that
    # it chains to a pinned root.
    chain = _verify_chain(ordered_certs, pinned_roots)
    if not chain["valid"]:
        detail = "; ".join(chain["errors"]) or "chain did not resolve to a pinned root"
        result["errors"].append(f"certificate chain invalid: {detail}")
        return result

    result["valid"] = True
    result["gen_time"] = tst_info["gen_time"].native
    return result


def _cert_identity(cert) -> tuple[str | None, str | None]:
    """(common_name, team_id) read from the certificate's own attributes.

    Structured field access rather than regexing a formatted display string —
    an Organization name containing a comma would break rfc4514 parsing by
    regex; ``get_attributes_for_oid`` doesn't care.
    """
    from cryptography.x509.oid import NameOID

    def _attr(oid):
        vals = cert.subject.get_attributes_for_oid(oid)
        return vals[0].value if vals else None

    common_name = _attr(NameOID.COMMON_NAME)
    # Apple's Developer ID certs carry the 10-character team ID in the OU
    # field (confirmed empirically: OU=BQR82RBBHL on a real Slack.app cert).
    team_id = _attr(NameOID.ORGANIZATIONAL_UNIT_NAME)
    if team_id and not (len(team_id) == 10 and team_id.isalnum()):
        team_id = None
    return common_name, team_id


def _find_signer_cert(si, certs, certs_asn1):
    try:
        sid = si["sid"].chosen
        target_serial = sid["serial_number"].native
        for cert, cert_asn1 in zip(certs, certs_asn1):
            if cert_asn1.serial_number == target_serial:
                return cert
    except Exception:
        pass
    return certs[0] if certs else None


def _verify_signature(pubkey, signature: bytes, data: bytes, hash_algo) -> None:
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

    if isinstance(pubkey, rsa.RSAPublicKey):
        pubkey.verify(signature, data, padding.PKCS1v15(), hash_algo)
    elif isinstance(pubkey, ec.EllipticCurvePublicKey):
        pubkey.verify(signature, data, ec.ECDSA(hash_algo))
    else:
        raise ValueError(f"unsupported public key type: {type(pubkey)}")


# ---------------------------------------------------------------------------
# Link 4: certificate chain to a pinned root
# ---------------------------------------------------------------------------

def _verify_chain(certs: list, pinned_roots: list, reference_time=None,
                  check_revocation: bool = False) -> dict:
    """Walk from the leaf up through certs supplied in the CMS blob, then
    require the top of that chain to be signed by a *pinned* root's real key.

    The chain-building step trusts nothing — it just follows issuer/subject
    name links among the certificates the blob provided, which could all be
    attacker-controlled. Trust only enters at the final step, where the top
    certificate's signature is checked against a root loaded from a local
    file this module shipped with, never against a key found in the binary
    being analyzed. A same-named forged root fails right here: its
    self-signature verifies under its own (attacker) key, not under the
    pinned key, and we never test the former.

    ``reference_time`` gates the validity-window check — pass the CMS
    signing time, never wall-clock "now" (see module docstring). ``None``
    skips the check entirely rather than assuming the current time.

    ``check_revocation`` triggers a live OCSP lookup — the only place in this
    module that touches the network, and only when the caller asks for it.
    """
    result = {
        "valid": False, "matched_root": None, "chain": [],
        "self_signed": False, "expired": None,
        "revocation": {"checked": False, "revoked": False, "details": []},
        "environment_errors": [], "errors": [],
    }
    if not certs:
        return result

    result["self_signed"] = certs[0].issuer == certs[0].subject

    if not pinned_roots:
        result["environment_errors"].append(
            "no pinned root certificates loaded — see CERTS_DIR"
        )
        return result

    chain = [certs[0]]
    seen = {id(certs[0])}
    current = certs[0]
    while True:
        nxt = next((c for c in certs if c.subject == current.issuer and id(c) not in seen), None)
        if nxt is None:
            break
        chain.append(nxt)
        seen.add(id(nxt))
        current = nxt

    result["chain"] = [c.subject.rfc4514_string() for c in chain]

    # Verify every link built purely from blob-supplied certs (still
    # untrusted at this point, but internal inconsistency is worth reporting).
    for subject, issuer in zip(chain, chain[1:]):
        try:
            _verify_signature(issuer.public_key(), subject.signature,
                              subject.tbs_certificate_bytes, subject.signature_hash_algorithm)
        except Exception as exc:
            result["errors"].append(f"broken intra-chain link at {subject.subject.rfc4514_string()}: {exc}")
            return result

    if reference_time is not None:
        expired = [c for c in chain
                  if not (c.not_valid_before_utc <= reference_time <= c.not_valid_after_utc)]
        result["expired"] = bool(expired)
        if expired:
            result["errors"].append(
                f"certificate not valid at signing time: {expired[0].subject.rfc4514_string()}"
            )

    top = chain[-1]
    matched_root = None
    for root in pinned_roots:
        if top.issuer != root.subject:
            continue
        try:
            _verify_signature(root.public_key(), top.signature,
                              top.tbs_certificate_bytes, top.signature_hash_algorithm)
        except Exception:
            continue
        matched_root = root
        break

    if matched_root is None:
        result["errors"].append(
            f"chain does not reach a pinned root — top certificate is "
            f"{top.subject.rfc4514_string()!r}, issued by {top.issuer.rfc4514_string()!r}"
        )
        return result

    result["matched_root"] = matched_root.subject.rfc4514_string()
    # `expired` is None (unchecked) or False here for `valid` to reach True —
    # an unchecked expiry never blocks validity, only a *confirmed* one does.
    result["valid"] = not result["expired"]

    if check_revocation:
        result["revocation"] = _check_chain_revocation(chain)

    return result


# ---------------------------------------------------------------------------
# Revocation (OCSP) — network access, opt-in only
# ---------------------------------------------------------------------------

def _ocsp_responder_url(cert) -> str | None:
    from cryptography import x509

    try:
        aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
    except x509.ExtensionNotFound:
        return None
    for desc in aia.value:
        if desc.access_method == x509.AuthorityInformationAccessOID.OCSP:
            return desc.access_location.value
    return None


def check_revocation(cert, issuer_cert, timeout: int = 10) -> dict:
    """Query ``cert``'s OCSP responder, using ``issuer_cert`` to build the request.

    Never called by :func:`verify_code_signature` unless ``check_revocation=True``
    is passed explicitly — this is the only network access anywhere in this
    module. A network failure or missing responder URL is reported as
    ``status="unavailable"``, distinct from ``"good"``/``"revoked"``: an
    offline analysis sandbox legitimately can't reach the network, and that
    is not evidence either way about the certificate.
    """
    result = {
        "checked": False, "status": "unavailable", "responder_url": None,
        "revocation_time": None, "revocation_reason": None, "error": None,
    }

    url = _ocsp_responder_url(cert)
    result["responder_url"] = url
    if not url:
        result["error"] = "certificate has no OCSP responder URL"
        return result

    import urllib.error
    import urllib.request

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509 import ocsp

    try:
        request_der = (
            ocsp.OCSPRequestBuilder()
            .add_certificate(cert, issuer_cert, hashes.SHA1())
            .build()
            .public_bytes(Encoding.DER)
        )
    except Exception as exc:
        result["error"] = f"failed to build OCSP request: {exc}"
        return result

    try:
        http_request = urllib.request.Request(
            url, data=request_der, method="POST",
            headers={"Content-Type": "application/ocsp-request"},
        )
        with urllib.request.urlopen(http_request, timeout=timeout) as response:
            response_der = response.read()
    except (urllib.error.URLError, OSError, ValueError) as exc:
        result["error"] = f"OCSP request failed: {exc}"
        return result

    try:
        ocsp_response = ocsp.load_der_ocsp_response(response_der)
    except Exception as exc:
        result["error"] = f"could not parse OCSP response: {exc}"
        return result

    if ocsp_response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        result["error"] = f"OCSP responder returned {ocsp_response.response_status}"
        return result

    result["checked"] = True
    status = ocsp_response.certificate_status
    if status == ocsp.OCSPCertStatus.GOOD:
        result["status"] = "good"
    elif status == ocsp.OCSPCertStatus.REVOKED:
        result["status"] = "revoked"
        result["revocation_time"] = ocsp_response.revocation_time_utc
        reason = ocsp_response.revocation_reason
        result["revocation_reason"] = reason.value if reason else None
    else:
        result["status"] = "unknown"

    return result


def _check_chain_revocation(chain: list) -> dict:
    """OCSP-check every (cert, issuer) pair in an already-built chain."""
    details = []
    any_checked = False
    any_revoked = False
    for cert, issuer in zip(chain, chain[1:]):
        r = check_revocation(cert, issuer)
        details.append({"subject": cert.subject.rfc4514_string(), **r})
        any_checked = any_checked or r["checked"]
        any_revoked = any_revoked or r["status"] == "revoked"
    return {"checked": any_checked, "revoked": any_revoked, "details": details}


# ---------------------------------------------------------------------------
# Per-slice and public entry points
# ---------------------------------------------------------------------------

def _verify_slice(fh: BinaryIO, slice_offset: int, cs: bytes, pinned_roots: list,
                  check_revocation: bool = False) -> dict:
    result = {
        "signed": False, "code_directory": None,
        "page_hashes_valid": None, "entitlements_hash_valid": None,
        "info_plist_hash_present": False, "resource_dir_present": False,
        "cms": None, "chain": None,
        "fully_verified": False, "tamper_detected": False,
        "notes": [], "errors": [],
    }
    entries = _parse_superblob(cs)
    if entries is None:
        return result
    result["signed"] = True

    cd_by_offset = {}
    for kind, off in entries.items():
        if kind not in _CODE_DIRECTORY_SLOT_TYPES:
            continue
        cd = _parse_code_directory(cs, off)
        if cd is not None:
            cd_by_offset[off] = cd
    code_directories = list(cd_by_offset.values())
    if not code_directories:
        result["errors"].append("no parseable CodeDirectory found")
        result["tamper_detected"] = True
        return result

    primary_off = entries.get(CSSLOT_CODEDIRECTORY)
    primary_cd = cd_by_offset.get(primary_off, code_directories[0])
    result["code_directory"] = {
        "identifier": primary_cd.identifier,
        "team_id": primary_cd.team_id,
        "version": hex(primary_cd.version),
        "n_code_slots": primary_cd.n_code_slots,
        "n_special_slots": primary_cd.n_special_slots,
        "hash_type": primary_cd.hash_type,
        "page_size": primary_cd.page_size,
        "code_limit": primary_cd.code_limit,
    }

    # Link 1: recompute every CodeDirectory's page hashes against real bytes.
    all_pages_ok = True
    for cd in code_directories:
        ok, err = _verify_page_hashes(fh, slice_offset, cd)
        if not ok:
            all_pages_ok = False
            result["errors"].append(err)
    result["page_hashes_valid"] = all_pages_ok
    if not all_pages_ok:
        result["tamper_detected"] = True

    # Bonus: entitlements slot, when present, binds the entitlements the
    # agent reads to the exact bytes the signature covers.
    ent_off = entries.get(CSSLOT_ENTITLEMENTS)
    if ent_off is not None:
        ent_blob = _blob_at(cs, ent_off)
        result["entitlements_hash_valid"] = _verify_special_slot(primary_cd, CSSLOT_ENTITLEMENTS, ent_blob)
        if result["entitlements_hash_valid"] is False:
            result["tamper_detected"] = True
            result["errors"].append("entitlements blob does not match its signed hash")

    result["info_plist_hash_present"] = CSSLOT_INFOSLOT in entries
    result["resource_dir_present"] = CSSLOT_RESOURCEDIR in entries
    if result["info_plist_hash_present"] or result["resource_dir_present"]:
        result["notes"].append(
            "Info.plist / bundle resources (_CodeResources) are present in "
            "the signature but not verified — that requires interpreting "
            "Apple's resource-rules grammar, out of scope for this module."
        )

    # Links 2 & 3.
    sig_off = entries.get(CSSLOT_SIGNATURESLOT)
    if sig_off is None:
        result["notes"].append("ad-hoc signature: no CMS blob present")
        return result
    cms = _verify_cms(cs, sig_off, code_directories, pinned_roots)
    result["cms"] = {k: v for k, v in cms.items() if k != "certificates"}
    if cms["environment_errors"]:
        result["notes"].extend(cms["environment_errors"])
    if cms["errors"]:
        # A check was attempted and failed — real evidence, not an
        # environment limitation. Distinguished from environment_errors so a
        # missing dependency can never masquerade as tamper evidence. This
        # also covers a present-but-broken timestamp token (folded into
        # cms["errors"] by _verify_cms) — no separate tamper-flagging path.
        result["tamper_detected"] = True

    reference_time = _select_reference_time(cms)

    # Link 4.
    if cms["certificates"]:
        chain = _verify_chain(cms["certificates"], pinned_roots,
                              reference_time=reference_time,
                              check_revocation=check_revocation)
        result["chain"] = chain
        if chain["environment_errors"]:
            result["notes"].extend(chain["environment_errors"])
        if not chain["valid"] and chain["errors"]:
            result["tamper_detected"] = True

    result["fully_verified"] = bool(
        result["page_hashes_valid"]
        and cms["signature_valid"]
        and cms["cd_hash_matches"]
        and result["chain"] and result["chain"]["valid"]
    )
    return result


def verify_code_signature(binary_path: str, pinned_roots: list | None = None,
                          check_revocation: bool = False) -> dict:
    """Verify every architecture slice of ``binary_path`` against pinned Apple roots.

    Returns::

        {
          "fully_verified": bool,     # True only if every signed slice fully verified
          "tamper_detected": bool,    # a check ran and failed, on any slice
          "slices": {"x86_64": {...}, "arm64": {...}},
          "errors": [...],
        }

    ``fully_verified`` requires at least one signed slice and zero failures
    across all of them — a universal binary where one architecture's
    signature is broken does not get credit for the architecture that
    happens to be intact. It does not depend on ``check_revocation`` — see
    the module docstring for why revocation is reported separately, under
    each slice's ``chain.revocation``.

    ``check_revocation=True`` performs a live OCSP lookup per signed slice.
    This is the only network access anywhere in this module and never
    happens unless explicitly requested.
    """
    import lief

    lief.logging.disable()
    result = {"fully_verified": False, "tamper_detected": False, "slices": {}, "errors": []}

    if pinned_roots is None:
        pinned_roots = load_pinned_roots()

    try:
        fat = lief.MachO.parse(binary_path)
    except Exception as exc:
        result["errors"].append(f"LIEF parse failed: {exc}")
        return result
    if fat is None:
        result["errors"].append(f"LIEF could not parse: {binary_path}")
        return result

    signed_count = 0
    all_ok = True
    try:
        with open(binary_path, "rb") as fh:
            for binary in fat:
                if not getattr(binary, "has_code_signature", False) or binary.code_signature is None:
                    continue
                arch = _arch_name(binary)
                slice_offset = getattr(binary, "fat_offset", 0)
                cs = bytes(binary.code_signature.content)
                slice_result = _verify_slice(fh, slice_offset, cs, pinned_roots,
                                             check_revocation=check_revocation)
                result["slices"][arch] = slice_result
                if slice_result["signed"]:
                    signed_count += 1
                    all_ok = all_ok and slice_result["fully_verified"]
                if slice_result["tamper_detected"]:
                    result["tamper_detected"] = True
    except OSError as exc:
        result["errors"].append(f"cannot read {binary_path}: {exc}")
        return result

    result["fully_verified"] = signed_count > 0 and all_ok
    return result


def _arch_name(binary) -> str:
    try:
        return binary.header.cpu_type.name.lower()
    except Exception:
        return "unknown"
