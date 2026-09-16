"""
strings.py — single source of truth for suspicious-string detection.

Before this module the project carried two divergent copies of
``SUSPICIOUS_PATTERNS`` (one in the native extractor, one in machopy's
``string_extractor``). They drifted, and the machopy copy produced 99% false
positives on signed Apple binaries. Everything now goes through here:

  * :func:`iter_strings`      — streaming printable-string extraction
  * :func:`scan`              — pattern matching -> ranked, deduplicated findings
  * :func:`extract_strings_of_interest` — path in, findings out (the common case)
  * :func:`count_categories`  — numeric counts for ML feature vectors

The native and machopy pipelines call the same functions, so a pattern fix
lands in both at once.

Risk weights map to the categories documented in
``docs/references-native/risk-signals.md``. Do not hardcode risk anywhere else.
"""

from __future__ import annotations

import base64
import binascii
import math
import re
from dataclasses import dataclass, field

__all__ = [
    "Risk",
    "StringPattern",
    "SUSPICIOUS_PATTERNS",
    "is_base64",
    "iter_strings",
    "read_strings",
    "scan",
    "extract_strings_of_interest",
    "count_categories",
    "DEFAULT_MAX_RESULTS",
    "MIN_STRING_LEN",
]

# ---------------------------------------------------------------------------
# Tunables
# ---------------------------------------------------------------------------

#: Minimum run of printable bytes to be considered a "string" (matches `strings -n 6`).
MIN_STRING_LEN = 6

#: Findings returned by default. Results are risk-ranked *before* truncation,
#: so the cap keeps the most severe hits rather than whichever came first.
DEFAULT_MAX_RESULTS = 100

#: Read granularity for :func:`read_strings`. The previous implementation did
#: ``f.read()`` on the whole binary, which OOMs on large samples.
_CHUNK_SIZE = 1 << 20  # 1 MiB

#: Printable ASCII range, used for the streaming scanner.
_PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{%d,}" % MIN_STRING_LEN)

#: Longest string we keep verbatim in a finding.
_MAX_VALUE_LEN = 250


# ---------------------------------------------------------------------------
# Risk levels
# ---------------------------------------------------------------------------

class Risk:
    """Ordered risk levels. Higher ``rank`` wins when a string matches several patterns."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    _ORDER = {LOW: 0, MEDIUM: 1, HIGH: 2}

    @classmethod
    def rank(cls, level: str) -> int:
        return cls._ORDER.get(level, 0)


# ---------------------------------------------------------------------------
# Pattern table
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class StringPattern:
    """One suspicious-string rule.

    ``regex`` is matched case-sensitively unless ``ignore_case`` is set. Case
    sensitivity is per-pattern on purpose: applying ``re.IGNORECASE`` globally
    is what made ``chmod`` match ``SwitchMode`` in the old implementation.
    """

    category: str
    pattern: str
    risk: str
    description: str
    ignore_case: bool = False
    #: Optional extra predicate applied to the matched text. Used to reject
    #: structurally-invalid matches (e.g. base64-shaped strings that aren't).
    validator: object = field(default=None, compare=False)

    def compile(self) -> re.Pattern:
        return re.compile(self.pattern, re.IGNORECASE if self.ignore_case else 0)


#: Shortest base64 blob worth reporting. Real encoded payloads and keys are
#: long; shorter matches are overwhelmingly identifiers.
_MIN_BASE64_LEN = 32

#: Minimum Shannon entropy (bits/char) for a base64 candidate. Measured over
#: the 64-symbol alphabet: base64 of random bytes lands at 5.1 (48 B) to 5.7
#: (96 B); Swift mangled symbols top out around 4.7. 4.8 splits them.
_MIN_BASE64_ENTROPY = 4.8

#: Compiler-mangled symbol shapes. These dominate the printable strings of any
#: Swift or C++ Mach-O and are the single largest source of base64 false
#: positives — e.g. "s10AppIntents0A4EnumP8RawValueSY" is a Swift symbol, not
#: an encoded payload. Cheaper and more reliable than tuning entropy alone.
_MANGLED_SYMBOL_RE = re.compile(
    r"^(?:"
    r"_?\$?[sS]\d{1,3}[A-Z]"        # Swift: $s10Foundation..., s10AppIntents...
    r"|_?Z[NLT]?\d"                   # C++ Itanium: _ZN9..., _ZL..., ZT...
    r"|OBJC_(?:IVAR|CLASS|METACLASS|PROTOCOL)_"
    r"|T0"                            # Swift thunk
    r")"
)


def _shannon_entropy(value: str) -> float:
    """Shannon entropy in bits per character."""
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    total = len(value)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def _try_b64decode(value: str) -> bytes | None:
    """Strict base64 decode, or ``None`` if it doesn't round-trip.

    Shared by :func:`is_base64` (validation) and :func:`_classify_base64_payload`
    (content classification), so there's one decode implementation rather than
    two call sites each doing their own try/except around ``base64.b64decode``.
    """
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None
    return decoded or None


def is_base64(value: str) -> bool:
    """True if ``value`` is plausibly an encoded payload, not merely base64-shaped.

    The old pattern ``[A-Za-z0-9+/]{40,}={0,2}`` flagged every long alphanumeric
    run: framework paths, hex digests, Swift mangled symbols. On Calculator.app
    that was 3644 of 3670 findings. Three filters remove that class of match:

    1. Length — encoded payloads are long; short matches are identifiers.
    2. Valid decode — must round-trip through strict base64.
    3. Not a mangled symbol — Swift/C++ manglings are base64-shaped by accident.
    4. Entropy — ``observationRegistrar`` decodes fine but is English, not data.
    """
    if len(value) < _MIN_BASE64_LEN or len(value) % 4:
        return False
    if _MANGLED_SYMBOL_RE.match(value):
        return False
    if _try_b64decode(value) is None:
        return False
    return _shannon_entropy(value) >= _MIN_BASE64_ENTROPY


#: Compression magic numbers that signal a nested encoding layer (the
#: "Matryoshka" pattern — base64-then-compress — documented in prior ClickFix
#: research as a common obfuscation chain).
_COMPRESSION_MAGIC = (
    (b"\x1f\x8b", "gzip"),
    (b"PK\x03\x04", "zip"),
    (b"\x28\xb5\x2f\xfd", "zstd"),
)


def _classify_base64_payload(decoded: bytes) -> tuple[str, str, str] | None:
    """Classify already-decoded base64 content into a more specific category
    than the generic ``possible_base64``, when a stronger sub-signal is present.

    Checked in priority order (bytecode, then compressed, then shebang, then a
    recursive suspicious-string scan of the decoded text) — not because of an
    observed conflict (a still-compressed blob's shebang is buried inside the
    compressed stream and invisible in the raw decoded prefix, so these checks
    are naturally mutually exclusive already), but because each earlier check
    is stronger/cheaper evidence than the next. The recursive scan only runs
    on validly UTF-8-decoded text and is itself one level deep (it disables
    further base64 classification via ``scan(..., _classify_base64=False)``),
    so a base64-shaped substring inside the decoded text is not itself decoded.

    Returns ``(category, risk, description)`` or ``None`` if nothing stronger
    than the generic ``possible_base64`` classification applies.
    """
    if len(decoded) >= 4 and decoded[2:4] == b"\r\n":
        # Structural, version-agnostic CPython bytecode magic-number shape
        # (2-byte version-specific prefix + the fixed \r\n suffix that's held
        # across CPython versions for the modern magic-number format) — not
        # an exact per-version magic-number table, to avoid the table going
        # stale as new Python versions ship.
        return (
            "encoded_python_bytecode",
            "HIGH",
            "Decoded base64 content has the structural shape of compiled "
            "CPython bytecode (.pyc magic number).",
        )
    for magic, name in _COMPRESSION_MAGIC:
        if decoded.startswith(magic):
            return (
                "encoded_compressed_payload",
                "MEDIUM",
                f"Decoded base64 content is {name}-compressed — a nested "
                "encoding layer (\"Matryoshka\" pattern).",
            )
    if decoded.startswith(b"#!"):
        return (
            "encoded_script",
            "MEDIUM",
            "Decoded base64 content begins with a shebang — an encoded script.",
        )
    try:
        text = decoded.decode("utf-8")
    except UnicodeDecodeError:
        return None
    matches = scan([text], max_results=1, _classify_base64=False)
    if matches:
        m = matches[0]
        return (m["category"], m["risk"], m["description"] + " (found in decoded base64 content)")
    return None


#: The canonical rule set. Replaces the two prior copies.
SUSPICIOUS_PATTERNS: list[StringPattern] = [
    # -- Network / C2 ------------------------------------------------------
    StringPattern(
        "url",
        r"https?://[a-zA-Z0-9._~:/?#\[\]@!$&'()*+,;=%-]{8,}",
        Risk.MEDIUM,
        "Embedded HTTP(S) URL — candidate C2 or payload host.",
    ),
    StringPattern(
        "ip_address",
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        Risk.MEDIUM,
        "Hardcoded IPv4 literal — bypasses DNS-based blocking.",
    ),
    StringPattern(
        "onion_address",
        r"\b[a-z2-7]{16,56}\.onion\b",
        Risk.HIGH,
        "Tor hidden-service address.",
    ),
    # -- Execution ---------------------------------------------------------
    StringPattern(
        "download_execute",
        r"\b(?:curl|wget)\b[^\n|]{0,200}\|\s*(?:/bin/)?(?:ba|z|d)?sh\b",
        Risk.HIGH,
        "Download-and-pipe-to-shell — the ClickFix delivery primitive.",
    ),
    StringPattern(
        "shell_invocation",
        r"\b(?:/bin/)?(?:ba|z)?sh\s+-c\b",
        Risk.HIGH,
        "Explicit shell command invocation.",
    ),
    StringPattern(
        "permission_change",
        r"\bchmod\s+(?:[0-7]{3,4}|[ugoa]*[+-][rwxst]+)\b",
        Risk.HIGH,
        "Runtime permission change — typically making a dropped payload executable.",
    ),
    StringPattern(
        "ownership_change",
        r"\bchown\s+[a-zA-Z0-9_.:-]+\b",
        Risk.MEDIUM,
        "Runtime ownership change.",
    ),
    StringPattern(
        "automation",
        r"\bosascript\b|\bAppleScript\b|\bdo\s+shell\s+script\b",
        Risk.HIGH,
        "AppleScript automation — used for TCC prompts and privilege escalation.",
        ignore_case=True,
    ),
    # -- Persistence -------------------------------------------------------
    StringPattern(
        "persistence",
        r"\bLaunch(?:Agents|Daemons)\b|\bcom\.apple\.launchd\b|\blaunchctl\s+(?:load|bootstrap)\b",
        Risk.HIGH,
        "launchd persistence artifact.",
    ),
    StringPattern(
        "login_item",
        r"\bSMLoginItemSetEnabled\b|\bLSSharedFileList\b",
        Risk.MEDIUM,
        "Login-item persistence API.",
    ),
    # -- Staging paths -----------------------------------------------------
    StringPattern(
        "tmp_path",
        r"/tmp/[^\s\"']{3,}",
        Risk.HIGH,
        "World-writable staging path.",
    ),
    StringPattern(
        "temp_path",
        r"/var/folders/[^\s\"']{5,}",
        Risk.MEDIUM,
        "Per-user temporary directory.",
    ),
    # -- Credential theft --------------------------------------------------
    StringPattern(
        "keychain_access",
        r"\bSecKeychain(?:FindGenericPassword|FindInternetPassword|CopyDefault)\b"
        r"|/Library/Keychains/",
        Risk.HIGH,
        "Keychain credential access.",
    ),
    StringPattern(
        "browser_data",
        r"(?:Login Data|Cookies\.binarycookies|key4\.db|logins\.json|Local Extension Settings)",
        Risk.HIGH,
        "Browser credential/cookie store — infostealer collection target.",
    ),
    StringPattern(
        "crypto_wallet",
        r"(?:Exodus|Electrum|MetaMask|Coinomi|Atomic Wallet|wallet\.dat)",
        Risk.HIGH,
        "Cryptocurrency wallet artifact — infostealer collection target.",
        ignore_case=True,
    ),
    # -- Injection / tampering --------------------------------------------
    StringPattern(
        "injection",
        r"\bmethod_setImplementation\b|\bclass_replaceMethod\b|\b_dyld_insert_libraries\b"
        r"|\bDYLD_INSERT_LIBRARIES\b|\btask_for_pid\b",
        Risk.HIGH,
        "Code-injection or method-swizzling primitive.",
    ),
    StringPattern(
        "gatekeeper_bypass",
        r"\bxattr\s+-[a-z]*d[a-z]*\b|\bcom\.apple\.quarantine\b|\bspctl\s+--master-disable\b",
        Risk.HIGH,
        "Quarantine/Gatekeeper tampering.",
    ),
    # -- Anti-analysis -----------------------------------------------------
    # NOTE: the token "sandbox" is deliberately absent. It matched
    # com.apple.security.app-sandbox in every sandboxed benign app.
    StringPattern(
        "anti_vm",
        r"\b(?:VMware|VirtualBox|VBOX|Parallels|QEMU|hypervisor)\b",
        Risk.MEDIUM,
        "Virtualization artifact lookup — possible sandbox evasion.",
        ignore_case=True,
    ),
    StringPattern(
        "anti_debug",
        r"\bPT_DENY_ATTACH\b|\bsysctl\b[^\n]{0,40}\bP_TRACED\b",
        Risk.HIGH,
        "Anti-debugging check.",
    ),
    # -- Malware family markers ---------------------------------------------
    StringPattern(
        "malware_family_marker",
        r"\bosalogging\b|\breceiveex\.php\b|\bopenex\.php\b|\bjoinsystem\b"
        r"|\benablesocks5\b|\.mainhelper\b|\bOdyssey\b",
        Risk.HIGH,
        "AMOS/Odyssey Stealer family marker — staging path, C2 endpoint, or botnet command.",
    ),
    # -- TCC abuse -----------------------------------------------------------
    StringPattern(
        "tcc_abuse",
        r"\bTCC\.db\b|\btccutil\s+reset\b",
        Risk.HIGH,
        "Direct TCC database access or TCC reset — privacy-protected data theft or "
        "re-prompting for permissions.",
    ),
    # -- Developer-secret harvesting ------------------------------------------
    StringPattern(
        "dev_secret_harvest",
        r"\.npmrc\b|\.docker/config\.json\b|\.config/gcloud\b|terraform\.tfstate\b",
        Risk.HIGH,
        "Developer credential file targeting — npm/Docker/GCP secret theft, or a Terraform "
        "state file that may contain plaintext cloud secrets.",
    ),
    # -- Legitimate-cloud C2 / exfil ------------------------------------------
    StringPattern(
        "cloud_c2_exfil",
        r"api\.telegram\.org|dropboxapi\.com",
        Risk.HIGH,
        "Legitimate-cloud API used as exfiltration/C2 channel (Telegram bot / Dropbox).",
    ),
    StringPattern(
        "cloud_hosting_abuse",
        r"\.vercel\.app|\.pages\.dev",
        Risk.MEDIUM,
        "Legitimate-cloud static hosting used as C2/payload host (Vercel/Cloudflare Pages) — "
        "these domains are also common in benign apps, so this is weaker signal than "
        "cloud_c2_exfil and does not by itself corroborate signed-sample trust revocation.",
    ),
    # -- Shell-config persistence ---------------------------------------------
    StringPattern(
        "shell_config_persistence",
        r"\.zshenv\b|\.zshrc\b|\.bash_profile\b",
        Risk.MEDIUM,
        "Shell-config persistence via ~/.zshenv, ~/.zshrc, or ~/.bash_profile — also written "
        "by many legitimate installers (Homebrew, nvm, pyenv), so kept at MEDIUM.",
    ),
    # -- Encoding ----------------------------------------------------------
    # The lookaround boundaries force the match to be a *whole* token. Without
    # them the scanner happily carved "observationRegistrar" out of the Swift
    # symbol "_$observationRegistrar" and called it base64.
    StringPattern(
        "possible_base64",
        # r"(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{4})",
        r"(?<![A-Za-z0-9+/=])"
        r"(?:[A-Za-z0-9+/]{4})+(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"
        r"(?![A-Za-z0-9+/=])",
        Risk.LOW,
        "Validated base64 blob — possible encoded payload or configuration.",
        validator=is_base64,
    ),
]

#: Compiled once at import; pattern objects are frozen so this stays valid.
_COMPILED: list[tuple[StringPattern, re.Pattern]] = [
    (p, p.compile()) for p in SUSPICIOUS_PATTERNS
]

#: Categories that feed the filesystem-path count in ML feature vectors.
_FS_PATH_RE = re.compile(r"(?:/[^/\s\"']+)+/?")
_NETWORK_CATEGORIES = frozenset({"url", "ip_address", "onion_address"})


# ---------------------------------------------------------------------------
# String extraction
# ---------------------------------------------------------------------------

def iter_strings(data: bytes, min_len: int = MIN_STRING_LEN):
    """Yield printable ASCII runs of at least ``min_len`` characters from ``data``."""
    pattern = _PRINTABLE_RE if min_len == MIN_STRING_LEN else re.compile(
        rb"[\x20-\x7e]{%d,}" % min_len
    )
    for match in pattern.finditer(data):
        yield match.group().decode("ascii", errors="ignore")


def read_strings(path: str, min_len: int = MIN_STRING_LEN):
    """Stream printable strings from a file without loading it entirely.

    Chunks overlap by ``min_len - 1`` bytes so a string straddling a chunk
    boundary is still found exactly once (duplicates are removed downstream).
    """
    overlap = max(min_len - 1, 0)
    try:
        with open(path, "rb") as fh:
            carry = b""
            while True:
                chunk = fh.read(_CHUNK_SIZE)
                if not chunk:
                    break
                buf = carry + chunk
                yield from iter_strings(buf, min_len)
                carry = buf[-overlap:] if overlap else b""
    except OSError as exc:
        raise OSError(f"cannot read {path}: {exc}") from exc


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

def _match_categories(text: str) -> list[tuple[StringPattern, str]]:
    """Return every (pattern, matched_text) hit for ``text``."""
    hits = []
    for spec, regex in _COMPILED:
        match = regex.search(text)
        if not match:
            continue
        matched = match.group()
        if spec.validator is not None and not spec.validator(matched):
            continue
        hits.append((spec, matched))
    return hits


def scan(strings, max_results: int = DEFAULT_MAX_RESULTS, _classify_base64: bool = True) -> list[dict]:
    """Match ``strings`` against the pattern table and return ranked findings.

    Behaviour that differs from the code this replaces:

    * **Highest risk wins.** A string is scored by its most severe matching
      pattern, not by whichever pattern happened to sit first in the list.
      ``curl https://x/y | bash`` is now HIGH ``download_execute``, not MEDIUM
      ``url``.
    * **Deduplicated.** Identical strings collapse to one finding carrying an
      occurrence count.
    * **Ranked before truncation.** ``max_results`` keeps the most severe
      findings; the old cap kept whatever appeared first in the file.
    """
    findings: dict[str, dict] = {}

    for text in strings:
        text = text.strip()
        if not text:
            continue
        hits = _match_categories(text)
        if not hits:
            continue

        best = max(hits, key=lambda h: Risk.rank(h[0].risk))
        value = text[:_MAX_VALUE_LEN]
        existing = findings.get(value)
        if existing is not None:
            existing["occurrences"] += 1
            continue

        category, risk, description = best[0].category, best[0].risk, best[0].description
        if category == "possible_base64" and _classify_base64:
            decoded = _try_b64decode(best[1])
            if decoded is not None:
                classified = _classify_base64_payload(decoded)
                if classified is not None:
                    category, risk, description = classified

        findings[value] = {
            "value": value,
            "category": category,
            "risk": risk,
            "description": description,
            "matched": best[1][:_MAX_VALUE_LEN],
            "all_categories": sorted({spec.category for spec, _ in hits}),
            "occurrences": 1,
        }

    ranked = sorted(
        findings.values(),
        key=lambda f: (-Risk.rank(f["risk"]), -f["occurrences"], f["value"]),
    )
    return ranked[:max_results] if max_results else ranked


def extract_strings_of_interest(
    binary_path: str,
    max_results: int = DEFAULT_MAX_RESULTS,
    min_len: int = MIN_STRING_LEN,
) -> list[dict]:
    """Extract printable strings from ``binary_path`` and return ranked findings.

    Never raises: on read failure it returns an empty list. Callers that need
    to distinguish "clean" from "unreadable" should use :func:`read_strings`
    directly. Errors are *not* mixed into the findings list — the old version
    appended ``{"error": ...}`` entries that lacked ``category``/``risk`` keys
    and blew up consumers.
    """
    try:
        return scan(read_strings(binary_path, min_len), max_results=max_results)
    except OSError:
        return []


# ---------------------------------------------------------------------------
# Numeric counts (ML feature vectors)
# ---------------------------------------------------------------------------

def count_categories(strings) -> dict[str, int]:
    """Count distinct suspicious strings per category, plus filesystem paths.

    Consumed by ``machopy.static_feat_extractor.StringFeatures`` so the ML
    feature vector and the agent findings are derived from one pattern table.
    """
    seen: dict[str, set] = {}
    fs_paths: set = set()

    for text in strings:
        text = text.strip()
        if not text:
            continue
        for path_match in _FS_PATH_RE.finditer(text):
            fs_paths.add(path_match.group())
        for spec, matched in _match_categories(text):
            seen.setdefault(spec.category, set()).add(matched)

    counts = {category: len(values) for category, values in seen.items()}
    counts["filesystem_path"] = len(fs_paths)
    counts["network"] = sum(
        len(seen.get(category, ())) for category in _NETWORK_CATEGORIES
    )
    return counts
