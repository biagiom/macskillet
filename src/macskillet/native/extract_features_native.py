#!/usr/bin/env python3
"""
extract_features_native.py — macOS App Static Feature Extractor (Native Edition)

Uses ONLY tools that ship with macOS:
  codesign, spctl, otool, nm, lipo, strings, xattr, mdls, plutil, file, find, python3

No external dependencies. Runs on any macOS 12+ system.

Usage:
    python3 extract_features_native.py -f /path/to/App.app
    python3 extract_features_native.py -f /path/to/binary
    python3 extract_features_native.py --dir /path/to/samples/ -o results.jsonl
"""

import argparse
import hashlib
import json
import os
import plistlib
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from macskillet.native.utils import _entropy


# ---------------------------------------------------------------------------
# Subprocess helper
# ---------------------------------------------------------------------------

def run(cmd: list, timeout: int = 30, input_data: bytes = None) -> tuple[str, str, int]:
    try:
        r = subprocess.run(
            cmd, capture_output=True, timeout=timeout,
            input=input_data
        )
        return r.stdout.decode("utf-8", errors="replace"), \
               r.stderr.decode("utf-8", errors="replace"), \
               r.returncode
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT", -1
    except FileNotFoundError:
        return "", f"NOT_FOUND: {cmd[0]}", -1


def run_text(cmd: list, timeout: int = 30) -> str:
    out, _, _ = run(cmd, timeout)
    return out


# ---------------------------------------------------------------------------
# File identification
# ---------------------------------------------------------------------------

MACHO_MAGIC = {
    b"\xca\xfe\xba\xbe",  # FAT
    b"\xfe\xed\xfa\xce",  # MH_MAGIC 32-bit
    b"\xce\xfa\xed\xfe",  # MH_CIGAM 32-bit LE
    b"\xfe\xed\xfa\xcf",  # MH_MAGIC_64
    b"\xcf\xfa\xed\xfe",  # MH_CIGAM_64 LE
}

def is_macho(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(4) in MACHO_MAGIC
    except Exception:
        return False

def is_fat(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\xca\xfe\xba\xbe"
    except Exception:
        return False

def sha256(path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    except Exception:
        return ""
    return h.hexdigest()

def md5(path: str) -> str:
    h = hashlib.md5()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    except Exception:
        return ""
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Phase 1: Pre-flight (xattr, mdls, file)
# ---------------------------------------------------------------------------

def analyze_preflight(path: str) -> dict:
    result = {
        "file_type": run_text(["file", path]).strip(),
        "quarantine_xattr": None,
        "has_quarantine": False,
        "quarantine_bypassed": False,
        "download_origin_urls": [],
        "downloaded_date": None,
        "all_xattrs": [],
        "spotlight_metadata": {},
    }

    # xattr -l
    xattr_out, _, _ = run(["xattr", "-l", path])
    result["all_xattrs"] = [line.strip() for line in xattr_out.splitlines() if line.strip()]

    # Quarantine specifically
    qout, _, qrc = run(["xattr", "-p", "com.apple.quarantine", path])
    if qrc == 0 and qout.strip():
        result["has_quarantine"] = True
        result["quarantine_xattr"] = qout.strip()
        # Parse flags (first field before ;)
        parts = qout.strip().split(";")
        if parts:
            try:
                flags = int(parts[0], 16)
                result["quarantine_bypassed"] = flags == 0
            except ValueError:
                pass
    else:
        # No quarantine = arrived without Gatekeeper trigger
        result["quarantine_bypassed"] = True

    # Download origin — xattr -px outputs hex-encoded binary plist; decode via plutil
    hex_out, _, hex_rc = run(["xattr", "-px", "com.apple.metadata:kMDItemWhereFroms", path])
    if hex_rc == 0 and hex_out.strip():
        try:
            raw_bytes = bytes.fromhex(hex_out.replace("\n", "").replace(" ", ""))
            json_out, _, plutil_rc = run(
                ["plutil", "-convert", "json", "-o", "-", "-"],
                input_data=raw_bytes,
            )
            if plutil_rc == 0:
                urls = json.loads(json_out)
                if isinstance(urls, list):
                    # keep only http/https; plists sometimes include ftp: or file: referrer entries
                    result["download_origin_urls"] = [
                        u for u in urls if isinstance(u, str) and u.startswith("http")
                    ]
        except Exception:
            pass

    # mdls for structured metadata
    mdls_fields = [
        "kMDItemWhereFroms", "kMDItemDownloadedDate",
        "kMDItemFSCreationDate", "kMDItemFSContentChangeDate",
        "kMDItemContentType",
    ]
    for field in mdls_fields:
        out, _, rc = run(["mdls", "-raw", "-name", field, path])
        if rc == 0 and out.strip() and out.strip() != "(null)":
            result["spotlight_metadata"][field] = out.strip()
            if field == "kMDItemDownloadedDate":
                result["downloaded_date"] = out.strip()

    return result


# ---------------------------------------------------------------------------
# Phase 2: Bundle Inventory
# ---------------------------------------------------------------------------

def analyze_bundle(app_path: str) -> dict:
    result = {
        "bundle_id": None,
        "bundle_version": None,
        "main_executable": None,
        "lsui_element": False,
        "ls_background_only": False,
        "has_launch_agent": False,
        "has_launch_daemon": False,
        "has_login_items": False,
        "embedded_scripts": [],
        "all_binaries": [],
        "hidden_files": [],
        "info_plist_keys": {},
        "info_plist_raw": {},
        "all_plists": [],
    }

    plist_path = os.path.join(app_path, "Contents", "Info.plist")
    if os.path.exists(plist_path):
        out, _, rc = run(["plutil", "-convert", "json", "-o", "-", plist_path])
        if rc == 0:
            try:
                plist = json.loads(out)
                result["info_plist_raw"] = plist
                result["bundle_id"] = plist.get("CFBundleIdentifier")
                result["bundle_version"] = (
                    plist.get("CFBundleShortVersionString") or plist.get("CFBundleVersion")
                )
                result["main_executable"] = plist.get("CFBundleExecutable")
                result["lsui_element"] = bool(plist.get("LSUIElement", False))
                result["ls_background_only"] = bool(plist.get("LSBackgroundOnly", False))
                interesting = {
                    k: v for k, v in plist.items()
                    if any(p in k for p in [
                        "NSApple", "com.apple.security", "Privacy",
                        "Usage", "NSPrincipal", "SMPrivilege"
                    ])
                }
                result["info_plist_keys"] = interesting
            except Exception:
                pass

    # File traversal
    find_out, _, _ = run(["find", app_path, "-type", "f"], timeout=15)
    for fp in find_out.splitlines():
        fp = fp.strip()
        if not fp:
            continue
        if is_macho(fp):
            result["all_binaries"].append(fp)
        ext = os.path.splitext(fp)[1].lower()
        if ext in (".sh", ".py", ".rb", ".pl", ".js", ".bash"):
            result["embedded_scripts"].append(fp)
        if os.path.basename(fp).startswith("."):
            result["hidden_files"].append(fp)

    # Persistence
    for dirpath, label in [
        ("Contents/Library/LaunchAgents", "launch_agent"),
        ("Contents/Library/LaunchDaemons", "launch_daemon"),
        ("Contents/Library/LoginItems", "login_items"),
    ]:
        full = os.path.join(app_path, dirpath)
        if os.path.isdir(full):
            result[f"has_{label}"] = True

    # All plists
    find_plist, _, _ = run(["find", app_path, "-name", "*.plist"], timeout=10)
    result["all_plists"] = [p.strip() for p in find_plist.splitlines() if p.strip()]

    return result


# ---------------------------------------------------------------------------
# Phase 3: Signature & Trust
# ---------------------------------------------------------------------------

def analyze_signature(path: str) -> dict:
    result = {
        "signed": False,
        "signing_status": "unsigned",
        "signing_status_detail": "",
        "notarized": False,
        "stapled": False,
        "hardened_runtime": False,
        "team_id": None,
        "bundle_id_from_sig": None,
        "identifier": None,
        "authority_chain": [],
        "flags_raw": "",
        "gatekeeper_verdict": "",
        # codesign validates the CodeDirectory hashes and resolves the chain
        # against the system trust store, so results from this path are
        # cryptographically verified. The cross-platform pipeline reports
        # "structural" instead. signature_trust.py only grants trust credit on
        # "cryptographic" — see that module for why.
        "verification": "cryptographic",
        "gatekeeper_source": "",
        "entitlements": {},
        "entitlements_raw": "",
        "codesign_verify_output": "",
        "codesign_display_output": "",
    }

    # Verify
    _, verify_stderr, verify_rc = run(["codesign", "--verify", "--verbose=4", path])
    result["codesign_verify_output"] = verify_stderr
    result["signed"] = verify_rc == 0

    # codesign --verify failing means one of two very different things, and
    # conflating them throws away the more alarming signal: a binary with
    # NO signature at all ("code object is not signed at all") versus one
    # that WAS signed and whose signature no longer matches the binary's
    # actual bytes (blob transplant, post-sign tampering). The latter is
    # active tamper evidence -- codesign can still read the certificate
    # chain via `-d` even though `--verify` rejected it, so identity below
    # is still parsed normally rather than forced to "unsigned".
    tampered_signature = (not result["signed"]) and "not signed at all" not in verify_stderr

    # Display
    _, display_stderr, _ = run(["codesign", "-d", "--verbose=4", path])
    result["codesign_display_output"] = display_stderr

    display = display_stderr

    # Parse identifier
    id_match = re.search(r"^Identifier=(.+)$", display, re.MULTILINE)
    if id_match:
        result["identifier"] = id_match.group(1).strip()

    # Parse TeamIdentifier
    team_match = re.search(r"TeamIdentifier=(\S+)", display)
    if team_match:
        result["team_id"] = team_match.group(1)
        if result["team_id"] == "not set":
            result["team_id"] = None

    # Parse authority chain
    result["authority_chain"] = re.findall(r"^Authority=(.+)$", display, re.MULTILINE)

    # Parse flags
    flags_match = re.search(r"flags=(\S+)", display)
    if flags_match:
        result["flags_raw"] = flags_match.group(1)
        result["hardened_runtime"] = "runtime" in flags_match.group(1)

    # Determine signing status. A tampered signature still has a readable
    # identity (see above), so it is classified the same way a valid one
    # would be -- only the `verification` field below marks it as broken.
    has_readable_identity = result["signed"] or tampered_signature
    if not has_readable_identity:
        result["signing_status"] = "unsigned"
    elif "ad hoc" in display.lower():
        result["signing_status"] = "ad_hoc"
        result["signing_status_detail"] = "Ad-hoc signed — no developer identity"
    elif "Apple Root CA" in display and "Developer ID" not in display:
        result["signing_status"] = "apple_signed"
        result["signing_status_detail"] = "Signed by Apple directly"
    elif "Developer ID Application" in display:
        result["signing_status"] = "developer_id"
        result["signing_status_detail"] = "Developer ID signed"
    else:
        result["signing_status"] = "other_signed"

    if tampered_signature:
        result["verification"] = "invalid"
        result["signing_status_detail"] = (
            (result["signing_status_detail"] + "; " if result["signing_status_detail"] else "")
            + f"codesign --verify FAILED: {verify_stderr.strip()[:200]}"
        )

    # Gatekeeper
    spctl_out, spctl_err, _ = run(["spctl", "--assess", "--verbose=4", "--type", "exec", path])
    spctl_combined = (spctl_out + spctl_err).strip()
    result["gatekeeper_verdict"] = spctl_combined
    if "accepted" in spctl_combined:
        source_match = re.search(r"source=(.+?)(?:\n|$)", spctl_combined)
        if source_match:
            result["gatekeeper_source"] = source_match.group(1).strip()
        if "Notarized" in spctl_combined:
            result["notarized"] = True
    
    # Staple check
    staple_out, staple_err, staple_rc = run(["xcrun", "stapler", "validate", path])
    staple_combined = (staple_out + staple_err).strip()
    result["stapled"] = "worked" in staple_combined.lower()

    # Entitlements
    ent_out, _, _ = run(["codesign", "-d", "--entitlements", ":-", path])
    result["entitlements_raw"] = ent_out
    if ent_out.strip():
        try:
            plist = plistlib.loads(ent_out.encode() if isinstance(ent_out, str) else ent_out)
            result["entitlements"] = dict(plist)
        except Exception:
            # Try parsing as XML
            try:
                result["entitlements"] = {"_raw": ent_out[:500]}
            except Exception:
                pass

    return result


# ---------------------------------------------------------------------------
# Phase 4: Binary Analysis
# ---------------------------------------------------------------------------

def analyze_binary(binary_path: str) -> dict:
    result = {
        "architectures": [],
        "is_fat": False,
        "filetype": None,
        "flags": [],
        "dylib_dependencies": [],
        "rpath_entries": [],
        "load_commands": [],
        "symbols_imported": [],
        "symbols_exported": [],
        "high_risk_symbols": [],
        "objc_classes": [],
        "objc_methods": [],
        "segments": [],
        "has_encryption": False,
        "encryption_cryptid": None,
        "entry_point": None,
        "strings_of_interest": [],
        "otool_header_raw": "",
    }

    # Architecture
    lipo_out, _, lipo_rc = run(["lipo", "-info", binary_path])
    if lipo_rc == 0:
        if "Architectures in the fat file" in lipo_out:
            result["is_fat"] = True
            arch_match = re.search(r"are: (.+)$", lipo_out)
            if arch_match:
                result["architectures"] = arch_match.group(1).strip().split()
        else:
            arch_match = re.search(r"is architecture: (.+)$", lipo_out)
            if arch_match:
                result["architectures"] = [arch_match.group(1).strip()]

    # Header
    otool_h, _, _ = run(["otool", "-h", binary_path])
    result["otool_header_raw"] = otool_h
    ft_match = re.search(r"EXECUTE|DYLIB|BUNDLE|OBJECT|CORE", otool_h)
    if ft_match:
        result["filetype"] = ft_match.group(0)

    # Load commands + dylibs
    otool_l, _, _ = run(["otool", "-l", binary_path], timeout=30)
    
    # Dylib dependencies
    otool_L, _, _ = run(["otool", "-L", binary_path])
    for line in otool_L.splitlines()[1:]:  # skip first line (binary name)
        line = line.strip()
        if line and "(" in line:
            dylib_path = line.split("(")[0].strip()
            result["dylib_dependencies"].append(dylib_path)

    # Load command names
    result["load_commands"] = list(set(re.findall(r"^\s+(LC_\w+)", otool_l, re.MULTILINE)))

    # Rpath entries
    result["rpath_entries"] = re.findall(r"LC_RPATH.*?\n.*?path\s+(.+?)\s+\(", otool_l, re.DOTALL)

    # Encryption
    enc_match = re.search(r"cryptid\s+(\d+)", otool_l)
    if enc_match:
        cryptid = int(enc_match.group(1))
        result["encryption_cryptid"] = cryptid
        result["has_encryption"] = cryptid != 0

    # Entry point
    ep_match = re.search(r"LC_MAIN.*?entryoff\s+(\d+)", otool_l, re.DOTALL)
    if ep_match:
        result["entry_point"] = int(ep_match.group(1))

    # Segment entropy
    result["segments"] = _calculate_segment_entropy(binary_path, otool_l)

    # Symbols
    nm_out, _, nm_rc = run(["nm", "-u", binary_path], timeout=30)
    if nm_rc == 0:
        result["symbols_imported"] = [
            s.strip().split()[-1] for s in nm_out.splitlines() if s.strip()
        ]

    nm_g_out, _, nm_g_rc = run(["nm", "-g", "-U", binary_path], timeout=30)
    if nm_g_rc == 0:
        result["symbols_exported"] = [
            s.strip().split()[-1] for s in nm_g_out.splitlines() if s.strip()
        ]

    # High-risk symbols
    HIGH_RISK_PATTERNS = [
        "mach_vm_allocate", "mach_vm_write", "mach_vm_protect",
        "thread_create_running", "task_for_pid", "processor_set_tasks",
        "_ptrace", "dlopen", "dlsym", "_system", "_popen",
        "_fork", "_execve", "posix_spawn",
        "SecKeychainFind", "SecKeychainSearch", "SecKeychainItemCopy",
        "CCCrypt", "CCKeyDerivation",
        "NSClassFromString", "NSSelectorFromString",
    ]
    for sym in result["symbols_imported"]:
        clean = sym.lstrip("_")
        for pattern in HIGH_RISK_PATTERNS:
            if pattern.lstrip("_").lower() in clean.lower():
                result["high_risk_symbols"].append(sym)
                break

    # ObjC class names
    objc_class_out, _, _ = run(
        ["otool", "-s", "__DATA", "__objc_classname", binary_path]
    )
    # Also try __DATA_CONST
    objc_class_out2, _, _ = run(
        ["otool", "-s", "__DATA_CONST", "__objc_classname", binary_path]
    )
    class_strings = _extract_strings_from_section(objc_class_out + objc_class_out2)
    result["objc_classes"] = [s for s in class_strings if s and len(s) > 2]

    # ObjC method names
    objc_meth_out, _, _ = run(
        ["otool", "-s", "__TEXT", "__objc_methnames", binary_path]
    )
    method_strings = _extract_strings_from_section(objc_meth_out)
    result["objc_methods"] = [s for s in method_strings if s and len(s) > 3][:200]

    # Strings of interest
    result["strings_of_interest"] = _extract_suspicious_strings(binary_path)

    return result


def _calculate_segment_entropy(binary_path: str, otool_l_output: str) -> list:
    """Calculate entropy for each Mach-O segment using otool -l output + python3."""
    segments = []
    current_seg = None
    fileoff = None
    filesize = None

    try:
        with open(binary_path, "rb") as f:
            binary_data = f.read()
    except Exception:
        return []

    for line in otool_l_output.splitlines():
        line = line.strip()
        if "segname" in line:
            # Save previous segment
            if current_seg and fileoff is not None and filesize and filesize > 0:
                chunk = binary_data[fileoff:fileoff + filesize]
                ent = _entropy(chunk)
                segments.append({
                    "name": current_seg,
                    "fileoff": fileoff,
                    "filesize": filesize,
                    "entropy": round(ent, 4),
                    "high_entropy": ent > 7.0,
                })
            current_seg = line.split()[-1]
            fileoff = filesize = None
        elif "fileoff" in line and current_seg and "sectname" not in line:
            try:
                fileoff = int(line.split()[-1])
            except ValueError:
                pass
        elif "filesize" in line and current_seg and "sectname" not in line:
            try:
                filesize = int(line.split()[-1])
            except ValueError:
                pass

    # Last segment
    if current_seg and fileoff is not None and filesize and filesize > 0:
        chunk = binary_data[fileoff:fileoff + filesize]
        ent = _entropy(chunk)
        segments.append({
            "name": current_seg,
            "fileoff": fileoff,
            "filesize": filesize,
            "entropy": round(ent, 4),
            "high_entropy": ent > 7.0,
        })

    return segments


def _extract_strings_from_section(otool_section_output: str) -> list:
    """Parse hex+ascii from otool section output and extract strings."""
    strings_found = []
    # otool section output has lines like: "00001234  61 62 63 00  abc."
    # We just grab the ASCII part after the hex
    current = []
    for line in otool_section_output.splitlines():
        # Lines with hex content
        parts = line.strip().split("\t")
        if len(parts) >= 2:
            ascii_part = parts[-1]
            for ch in ascii_part:
                if ch.isprintable() and ch != ".":
                    current.append(ch)
                else:
                    if len(current) >= 3:
                        strings_found.append("".join(current))
                    current = []
    if current and len(current) >= 3:
        strings_found.append("".join(current))
    
    # Fallback: just run strings on the raw output
    if not strings_found:
        raw = otool_section_output.encode("utf-8", errors="replace")
        strings_found = [
            s for s in re.findall(r"[\x20-\x7e]{4,}", otool_section_output)
            if not all(c in "0123456789abcdef \t" for c in s.lower())
        ]
    
    return strings_found


SUSPICIOUS_PATTERNS = [
    (r"https?://[a-zA-Z0-9._/-]{8,}", "url"),
    (r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "ip_address"),
    (r"/tmp/[^\s\"']{3,}", "tmp_path"),
    (r"/var/folders/[^\s\"']{5,}", "temp_path"),
    (r"LaunchAgents|LaunchDaemons", "persistence"),
    (r"osascript|applescript", "automation"),
    (r"(chmod|chown)\s+[0-9+]", "permission_change"),
    (r"(curl|wget)\s+.*\|\s*(ba)?sh", "download_execute"),
    (r"VMware|VirtualBox|Parallels|VBOX", "anti_vm"),
    (r"inject|hooklib|swizzle|method_setImplementation", "injection"),
    (r"[A-Za-z0-9+/]{40,}={0,2}", "possible_base64"),
    (r"(keychain|SecKeychainFind)", "keychain_access"),
]

def _extract_suspicious_strings(binary_path: str) -> list:
    results = []
    strings_out, _, _ = run(["strings", "-n", "6", binary_path], timeout=30)
    # Also get UTF-16 strings
    strings_utf16, _, _ = run(["strings", "-encoding", "l", "-n", "6", binary_path], timeout=30)
    all_strings = strings_out + "\n" + strings_utf16

    for line in all_strings.splitlines():
        line = line.strip()
        if not line:
            continue
        for pattern, category in SUSPICIOUS_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                risk = "HIGH" if category in ("persistence", "download_execute", "tmp_path", "injection") else "MEDIUM"
                results.append({"value": line[:250], "category": category, "risk": risk})
                break

    return results[:100]  # cap to avoid huge outputs


# ---------------------------------------------------------------------------
# Main extraction pipeline
# ---------------------------------------------------------------------------

def extract(path: str) -> dict:
    path = os.path.abspath(path)

    features = {
        "sample": {
            "name": os.path.basename(path),
            "path": path,
            "type": None,
            "sha256": None,
            "md5": None,
            "filesize_bytes": None,
            "extraction_tool": "native-macos",
        },
        "preflight": None,
        "bundle": None,
        "signature": None,
        "binary": None,
        "clickfix": None,
        "obfuscation": None,
        "errors": [],
    }

    # Import detectors (lazy import — don't fail if files missing)
    try:
        from macskillet.native.clickfix_detector import detect_clickfix
        _has_clickfix = True
    except ImportError:
        _has_clickfix = False
    try:
        from macskillet.native.obfuscation_detector import detect_obfuscation
        _has_obfuscation = True
    except ImportError:
        _has_obfuscation = False
    try:
        from macskillet.common.signature_trust import assess_signature_trust
        _has_signature_trust = True
    except ImportError:
        _has_signature_trust = False

    if path.endswith(".app") and os.path.isdir(path):
        features["sample"]["type"] = "app_bundle"
        features["sample"]["sha256"] = "N/A (bundle)"
        features["sample"]["md5"] = "N/A (bundle)"

        features["preflight"] = analyze_preflight(path)
        bundle_info = analyze_bundle(path)
        features["bundle"] = bundle_info
        features["signature"] = analyze_signature(path)

        # Find main binary
        main_exec = bundle_info.get("main_executable")
        main_binary = os.path.join(path, "Contents", "MacOS", main_exec or "")
        if not os.path.exists(main_binary):
            binaries = bundle_info.get("all_binaries", [])
            main_binary = binaries[0] if binaries else None

        if main_binary and os.path.exists(main_binary):
            features["sample"]["sha256"] = sha256(main_binary)
            features["sample"]["md5"] = md5(main_binary)
            features["sample"]["filesize_bytes"] = os.path.getsize(main_binary)
            features["binary"] = analyze_binary(main_binary)
        else:
            features["errors"].append("Could not locate main executable")

    elif os.path.isfile(path) and is_macho(path):
        features["sample"]["type"] = "macho_binary"
        features["sample"]["sha256"] = sha256(path)
        features["sample"]["md5"] = md5(path)
        features["sample"]["filesize_bytes"] = os.path.getsize(path)
        features["preflight"] = analyze_preflight(path)
        features["signature"] = analyze_signature(path)
        features["binary"] = analyze_binary(path)

    else:
        features["errors"].append(f"Not a .app bundle or Mach-O binary: {path}")

    # Run optional detectors if available
    if _has_clickfix:
        try:
            features["clickfix"] = detect_clickfix(features)
        except Exception as e:
            features["errors"].append(f"ClickFix detection error: {e}")
    if _has_obfuscation:
        try:
            features["obfuscation"] = detect_obfuscation(features)
        except Exception as e:
            features["errors"].append(f"Obfuscation detection error: {e}")
    # Signature-trust must run AFTER clickfix: it reads features["clickfix"]
    # to revoke the signing trust credit for signed-but-malicious samples.
    if _has_signature_trust:
        try:
            features["signature_trust"] = assess_signature_trust(features)
        except Exception as e:
            features["errors"].append(f"Signature-trust assessment error: {e}")

    return features


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Extract static features from macOS app using native tools only"
    )
    parser.add_argument("-f", "--file", help="Path to .app or binary")
    parser.add_argument("--dir", help="Directory of samples (bulk)")
    parser.add_argument("-o", "--output", help="Output file")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    if args.file:
        result = extract(args.file)
        output = json.dumps(result, indent=2 if args.pretty else None, default=str)
        if args.output:
            with open(args.output, "w") as f:
                f.write(output)
        else:
            print(output)

    elif args.dir:
        samples = []
        for root, dirs, files in os.walk(args.dir):
            for name in files:
                fp = os.path.join(root, name)
                if is_macho(fp):
                    samples.append(fp)
            for d in list(dirs):
                if d.endswith(".app"):
                    samples.append(os.path.join(root, d))
                    dirs.remove(d)

        out = open(args.output, "w") if args.output else sys.stdout
        for s in samples:
            r = extract(s)
            out.write(json.dumps(r, default=str) + "\n")
            sys.stderr.write(f"[+] {s}\n")
        if args.output:
            out.close()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
