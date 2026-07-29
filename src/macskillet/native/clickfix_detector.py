#!/usr/bin/env python3
"""
clickfix_detector.py — Static ClickFix indicator detection for macOS binaries.

ClickFix on macOS has two primary delivery chains as of 2026:

  Chain A — Terminal (classic):
    Fake webpage → user pastes "base64 -d | bash" → shell downloads + exec
    Drops binary to /tmp/ (helper, update, cleaner3, etc.)
    Calls xattr -c to strip quarantine, chmod +x, then runs

  Chain B — Script Editor (newer, evades macOS 26.4 Terminal protection):
    Fake webpage → applescript:// URL → Script Editor opens pre-filled
    AppleScript runs do shell script with obfuscated curl | zsh
    Same /tmp/ drop + xattr -c + exec pattern

  Common payload families: AMOS/Atomic Stealer, Odyssey Stealer, MacSync,
  Shub Stealer, Macsync, Lumma Stealer (macOS port)

This module checks for static indicators present in the *dropped binary*
(the Mach-O that ends up in /tmp/ after ClickFix delivers it).
It also checks for ClickFix-style dropper scripts embedded in bundles.
"""

import re
from typing import Any


# ---------------------------------------------------------------------------
# ClickFix indicator database
# ---------------------------------------------------------------------------

# Strings that appear in ClickFix-delivered payloads (AMOS, Odyssey, etc.)
# These are in the dropped Mach-O or embedded scripts, not the webpage
CLICKFIX_STRING_INDICATORS = [

    # ── Delivery mechanism remnants ──────────────────────────────────────
    ("base64 -d", "delivery", "HIGH",
     "base64 decode pipeline — core ClickFix delivery primitive"),
    ("base64 -D", "delivery", "HIGH",
     "macOS base64 decode (capital D flag) — ClickFix delivery"),
    ("| bash", "delivery", "HIGH",
     "pipe to bash — fileless execution pattern"),
    ("| zsh", "delivery", "HIGH",
     "pipe to zsh — ClickFix execution variant"),
    ("| osascript", "delivery", "HIGH",
     "pipe to osascript — in-memory AppleScript delivery"),
    ("curl -k", "delivery", "HIGH",
     "curl with TLS verification disabled — ClickFix C2 comms"),
    ("curl -kSsfL", "delivery", "HIGH",
     "curl silent+follow-redirects — ClickFix stage-2 download"),
    ("xattr -c", "delivery", "HIGH",
     "strip ALL extended attributes — removes quarantine to bypass Gatekeeper"),
    ("xattr -d com.apple.quarantine", "delivery", "HIGH",
     "explicit quarantine removal — Gatekeeper bypass"),
    ("gunzip", "delivery", "MEDIUM",
     "gzip decompression — ClickFix Matryoshka nested payload"),
    ("bunzip2", "delivery", "MEDIUM",
     "bzip2 decompression — ClickFix payload variant"),
    ("eval \"$", "delivery", "HIGH",
     "eval of variable — in-memory execution without disk write"),

    # ── Common drop paths ────────────────────────────────────────────────
    ("/tmp/helper", "drop_path", "HIGH",
     "Canonical AMOS/ClickFix drop path — seen in multiple campaigns"),
    ("/tmp/update", "drop_path", "HIGH",
     "ClickFix drop path variant"),
    ("/tmp/cleaner", "drop_path", "HIGH",
     "ClickFix fake cleaner drop path (cleaner3/update variants)"),
    ("/tmp/installer", "drop_path", "MEDIUM",
     "Generic installer drop to /tmp/ — suspicious"),
    ("/tmp/osalogging", "drop_path", "HIGH",
     "Odyssey Stealer staging archive path"),
    ("/tmp/out.zip", "drop_path", "HIGH",
     "AppleScript stealer exfil archive — Odyssey/generic"),
    ("/private/var/tmp/", "drop_path", "MEDIUM",
     "Alternative temp staging path used in some campaigns"),

    # ── Exfiltration patterns ─────────────────────────────────────────────
    ("/upload.php", "exfil", "HIGH",
     "C2 upload endpoint — seen in AMOS, MacSync, Odyssey"),
    ("/gate", "exfil", "HIGH",
     "Matryoshka ClickFix C2 gate endpoint"),
    ("/receiveex.php", "exfil", "HIGH",
     "AMOS exfil endpoint"),
    ("/openex.php", "exfil", "HIGH",
     "AMOS exfil endpoint variant"),
    ("/api/v1/bot/", "exfil", "HIGH",
     "AMOS botnet C2 API endpoint"),
    ("curl -X POST", "exfil", "MEDIUM",
     "POST exfiltration via curl"),
    ("-F \"file=@", "exfil", "HIGH",
     "curl multipart file upload — data exfiltration"),

    # ── Data harvesting targets (seen in AMOS, Odyssey, MacSync) ─────────
    ("keychain.db", "harvest", "HIGH",
     "Direct keychain database access — credential theft"),
    ("login.keychain", "harvest", "HIGH",
     "Login keychain targeting"),
    ("Local State", "harvest", "HIGH",
     "Chrome/Brave credential store — browser data theft"),
    ("Cookies", "harvest", "MEDIUM",
     "Browser cookie harvesting"),
    ("cookies.sqlite", "harvest", "HIGH",
     "Firefox cookie store"),
    ("key4.db", "harvest", "HIGH",
     "Firefox password database"),
    ("logins.json", "harvest", "HIGH",
     "Firefox login data"),
    ("wallet.dat", "harvest", "HIGH",
     "Bitcoin/crypto wallet file"),
    ("seed.seco", "harvest", "HIGH",
     "Exodus wallet seed file"),
    ("Electrum/wallets", "harvest", "HIGH",
     "Electrum wallet targeting"),
    (".ssh/id_rsa", "harvest", "HIGH",
     "SSH private key theft"),
    ("aws/credentials", "harvest", "HIGH",
     "AWS credential harvesting"),
    (".kube/config", "harvest", "HIGH",
     "Kubernetes config theft"),
    ("iCloud", "harvest", "MEDIUM",
     "iCloud data targeting"),

    # ── Anti-analysis / environment checks (in AMOS) ──────────────────────
    ("SPHardwareDataType", "anti_analysis", "MEDIUM",
     "Hardware info query — VM/sandbox detection (AMOS pattern)"),
    ("SPMemoryDataType", "anti_analysis", "MEDIUM",
     "Memory info query — VM detection (AMOS anti-analysis)"),
    ("system_profiler", "anti_analysis", "MEDIUM",
     "System profiler — environment fingerprinting"),
    ("VMware", "anti_analysis", "MEDIUM",
     "VMware detection string"),
    ("VirtualBox", "anti_analysis", "MEDIUM",
     "VirtualBox detection"),

    # ── Persistence (seen in AMOS v2+ botnet variant) ──────────────────────
    (".mainhelper", "persistence", "HIGH",
     "AMOS persistence script name"),
    ("com.apple.launchd", "persistence", "MEDIUM",
     "LaunchAgent/Daemon plist naming pattern"),
    ("joinsystem", "persistence", "HIGH",
     "AMOS botnet join endpoint"),
    ("enablesocks5", "persistence", "HIGH",
     "AMOS botnet SOCKS5 proxy command"),

    # ── Script Editor / applescript:// vector (Chain B) ───────────────────
    ("do shell script", "script_editor", "HIGH",
     "AppleScript shell execution — Script Editor delivery vector"),
    ("applescript://", "script_editor", "HIGH",
     "applescript:// URL scheme — ClickFix Script Editor vector"),
    ("osascript -e", "script_editor", "HIGH",
     "Inline osascript execution"),

    # ── 2026 enrichment: decode-chain primitives ─────────────────────────
    ("openssl enc -d", "delivery", "HIGH",
     "OpenSSL decrypt of staged payload — ClickFix obfuscation chain"),
    ("xxd -p -r", "delivery", "HIGH",
     "hex decode pipeline (xxd -p -r) — ClickFix payload deobfuscation"),

    # ── 2026 enrichment: developer / cloud secret targets ────────────────
    (".npmrc", "harvest", "HIGH",
     "npm auth token theft — developer credential harvesting"),
    (".docker/config.json", "harvest", "HIGH",
     "Docker registry credential theft"),
    ("terraform.tfstate", "harvest", "MEDIUM",
     "Terraform state file — may contain plaintext cloud secrets"),
    (".config/gcloud", "harvest", "HIGH",
     "GCP credential harvesting (gcloud config dir)"),

    # ── 2026 enrichment: legitimate-cloud C2 / exfil ─────────────────────
    ("api.telegram.org", "exfil", "HIGH",
     "Telegram bot API — exfiltration channel"),
    ("dropboxapi.com", "exfil", "HIGH",
     "Dropbox API (api./content.) — exfiltration / payload hosting"),
    (".vercel.app", "exfil", "MEDIUM",
     "Vercel-hosted C2/payload — legitimate-cloud abuse"),
    (".pages.dev", "exfil", "MEDIUM",
     "Cloudflare Pages-hosted C2/payload — legitimate-cloud abuse"),

    # ── 2026 enrichment: crypto-wallet trojanizing ───────────────────────
    ("Ledger Live", "harvest", "HIGH",
     "Ledger Live wallet app — app.asar replacement / trojanizing target"),

    # ── 2026 enrichment: shell-config persistence (alert-evasive) ─────────
    (".zshenv", "persistence", "HIGH",
     "~/.zshenv persistence — evades macOS 13+ background-item notification"),
    (".zshrc", "persistence", "MEDIUM",
     "shell-config persistence via ~/.zshrc"),
    (".bash_profile", "persistence", "MEDIUM",
     "shell-config persistence via ~/.bash_profile"),

    # ── 2026 enrichment: TCC abuse ────────────────────────────────────────
    ("tccutil reset", "anti_analysis", "HIGH",
     "tccutil reset — clears TCC to re-prompt for privacy permissions"),
    ("TCC.db", "harvest", "HIGH",
     "direct TCC database access — privacy-protected data theft"),

    # ── 2026 enrichment: anti-analysis fingerprint + masquerade ──────────
    ("hw.optional.arm.FEAT_", "anti_analysis", "MEDIUM",
     "Apple Silicon feature-flag fingerprinting — anti-analysis / targeting"),
    ("exec -a", "anti_analysis", "HIGH",
     "exec -a process-name masquerade (e.g. mdworker_local / distnoted)"),
    ("ioreg", "anti_analysis", "MEDIUM",
     "ioreg hardware/serial query — VM/sandbox detection"),
]

# Binary signatures for known packers/droppers
BINARY_SIGNATURES = [
    # UPX packer (common for AMOS and other macOS malware)
    (b"UPX!", "packer", "HIGH", "UPX packer signature detected"),
    (b"MPRESS", "packer", "HIGH", "MPRESS packer signature"),
    # AMOS-specific markers from research
    (b"osalogging", "amos", "HIGH", "AMOS staging directory marker"),
    (b"receiveex.php", "amos", "HIGH", "AMOS C2 endpoint"),
    (b"openex.php", "amos", "HIGH", "AMOS exfil endpoint"),
    # Odyssey Stealer
    (b"odyssey", "odyssey", "HIGH", "Odyssey Stealer marker"),
]

# Known ClickFix-related filename patterns (dropped binary names)
CLICKFIX_FILENAMES = {
    "helper": "HIGH",
    "update": "MEDIUM",
    "cleaner": "HIGH",
    "installer": "MEDIUM",
    "fix": "MEDIUM",
    "repair": "MEDIUM",
    "optimizer": "MEDIUM",
    "speedup": "MEDIUM",
}


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

def detect_clickfix(features: dict) -> dict:
    """
    Run ClickFix indicator detection against extracted features.
    Returns a structured result with matched indicators and a verdict.
    """
    result = {
        "clickfix_suspected": False,
        "confidence": "NONE",
        "delivery_chain": None,
        "matched_indicators": [],
        "score": 0,
        "filename_suspicious": False,
        "binary_signatures": [],
        "summary": "",
    }

    # ── Filename check ────────────────────────────────────────────────────
    sample_name = features.get("sample", {}).get("name", "").lower()
    for fname, risk in CLICKFIX_FILENAMES.items():
        if sample_name == fname or sample_name.startswith(fname):
            result["filename_suspicious"] = True
            result["matched_indicators"].append({
                "indicator": f"filename={sample_name}",
                "category": "drop_path",
                "risk": risk,
                "detail": f"Filename matches ClickFix-dropped binary pattern: '{fname}'",
            })
            result["score"] += 4 if risk == "HIGH" else 2

    # ── Drop path check (was file found in /tmp/ or /private/var/tmp/) ───
    sample_path = features.get("sample", {}).get("path", "")
    if sample_path.startswith("/tmp/") or sample_path.startswith("/private/tmp/"):
        result["matched_indicators"].append({
            "indicator": "path=/tmp/",
            "category": "drop_path",
            "risk": "HIGH",
            "detail": "Binary located in /tmp/ — canonical ClickFix drop location",
        })
        result["score"] += 5

    # ── String indicator scan ─────────────────────────────────────────────
    strings_of_interest = features.get("binary", {}).get("strings_of_interest", []) \
        if features.get("binary") else []
    string_values = [s.get("value", "") for s in strings_of_interest if isinstance(s, dict)]

    # Also check embedded scripts in bundle
    bundle = features.get("bundle") or {}
    embedded_scripts = bundle.get("embedded_scripts", [])

    all_text = "\n".join(string_values)

    for pattern, category, risk, detail in CLICKFIX_STRING_INDICATORS:
        if pattern.lower() in all_text.lower():
            result["matched_indicators"].append({
                "indicator": pattern,
                "category": category,
                "risk": risk,
                "detail": detail,
            })
            score_map = {"HIGH": 3, "MEDIUM": 1}
            result["score"] += score_map.get(risk, 1)

    # ── Binary signature scan ─────────────────────────────────────────────
    binary_path = None
    if features.get("sample", {}).get("type") == "macho_binary":
        binary_path = features.get("sample", {}).get("path")
    elif features.get("bundle"):
        main_exec = bundle.get("main_executable")
        app_path = features.get("sample", {}).get("path", "")
        if main_exec:
            binary_path = f"{app_path}/Contents/MacOS/{main_exec}"

    if binary_path:
        try:
            with open(binary_path, "rb") as f:
                binary_data = f.read(65536)  # first 64KB sufficient for signatures
            for sig, category, risk, detail in BINARY_SIGNATURES:
                if sig in binary_data:
                    result["binary_signatures"].append({
                        "signature": sig.decode("utf-8", errors="replace"),
                        "category": category,
                        "risk": risk,
                        "detail": detail,
                    })
                    result["score"] += 5 if risk == "HIGH" else 2
        except Exception:
            pass

    # ── xattr quarantine bypass check ─────────────────────────────────────
    pf = features.get("preflight") or {}
    if not pf.get("has_quarantine") and features.get("sample", {}).get("type") == "macho_binary":
        # Bare binary with no quarantine — likely downloaded and quarantine stripped
        if sample_path.startswith("/tmp/") or sample_path.startswith("/private/tmp/"):
            result["matched_indicators"].append({
                "indicator": "no_quarantine+tmp_path",
                "category": "delivery",
                "risk": "HIGH",
                "detail": "Binary in /tmp/ with no quarantine xattr — xattr -c was run (ClickFix pattern)",
            })
            result["score"] += 6

    # ── Delivery chain inference ──────────────────────────────────────────
    all_categories = {ind["category"] for ind in result["matched_indicators"]}

    has_script_editor = "script_editor" in all_categories
    has_delivery = "delivery" in all_categories
    has_harvest = "harvest" in all_categories
    has_exfil = "exfil" in all_categories

    if has_script_editor:
        result["delivery_chain"] = "chain_b_script_editor"
    elif has_delivery:
        result["delivery_chain"] = "chain_a_terminal"

    # ── Final verdict ──────────────────────────────────────────────────────
    if result["score"] >= 12:
        result["clickfix_suspected"] = True
        result["confidence"] = "HIGH"
    elif result["score"] >= 6:
        result["clickfix_suspected"] = True
        result["confidence"] = "MEDIUM"
    elif result["score"] >= 3:
        result["clickfix_suspected"] = True
        result["confidence"] = "LOW"

    # ── Summary ────────────────────────────────────────────────────────────
    n = len(result["matched_indicators"])
    if result["clickfix_suspected"]:
        chain_str = {
            "chain_a_terminal": "Terminal-based (base64|bash)",
            "chain_b_script_editor": "Script Editor (applescript:// URL)",
        }.get(result["delivery_chain"], "unknown delivery chain")
        families = []
        if any("amos" in i["indicator"].lower() or "osalogging" in i["indicator"]
               for i in result["matched_indicators"] + result["binary_signatures"]):
            families.append("AMOS/Atomic Stealer")
        if any("odyssey" in i["indicator"].lower() for i in result["matched_indicators"]):
            families.append("Odyssey Stealer")
        family_str = f" (possible family: {', '.join(families)})" if families else ""
        result["summary"] = (
            f"ClickFix-delivered payload suspected ({result['confidence']} confidence). "
            f"Delivery: {chain_str}. {n} indicator(s) matched{family_str}."
        )
    else:
        result["summary"] = f"No ClickFix indicators detected ({n} checks run)."

    return result
