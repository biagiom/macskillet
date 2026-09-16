#!/usr/bin/env python3
"""
packer_signatures.py — Packer/compiler-runtime byte-signature detection.

Pure byte-matching against a binary's raw bytes — no macOS dependency, no
Mach-O parsing. Shared by both pipelines' main-binary analysis and by
``--deep``'s embedded Mach-O item analysis on both backends, so a
PyInstaller/Nuitka-compiled helper binary bundled inside an otherwise-clean
wrapper app is detected the same way the main executable would be.
"""

from __future__ import annotations

PACKER_SIGNATURES = [
    # UPX — most common macOS packer
    (b"UPX!", "UPX", "HIGH",
     "UPX packer magic bytes — binary is compressed and self-unpacking"),
    (b"UPX0", "UPX", "HIGH",
     "UPX section name (UPX0) — confirms UPX packing"),
    (b"UPX1", "UPX", "HIGH",
     "UPX section name (UPX1)"),
    # MPRESS
    (b"MPRESS1", "MPRESS", "HIGH",
     "MPRESS packer section name"),
    (b"MPRESS2", "MPRESS", "HIGH",
     "MPRESS packer section name"),
    # Generic packed section markers
    (b".upxsig", "UPX", "HIGH",
     "UPX signature section"),
    # Themida/VMProtect (rare on macOS but seen in some samples)
    (b"VMProtect", "VMProtect", "HIGH",
     "VMProtect obfuscator marker"),
    # Golang runtime (not a packer but large binary, distinct markers)
    (b"Go build ID:", "Go", "LOW",
     "Go runtime — large binary expected, not malicious by itself"),
    (b"runtime.main", "Go", "LOW",
     "Go runtime marker"),
    # Rust runtime
    (b"__rustc", "Rust", "LOW",
     "Rust compiler marker — statically linked runtime"),
    # Nim
    (b"NimMain", "Nim", "MEDIUM",
     "Nim language runtime — sometimes used in macOS malware (Sliver, etc.)"),
    (b"nimGC", "Nim", "MEDIUM",
     "Nim GC marker"),
    # PyInstaller / py2app wrapped Python
    (b"PKG_BASE", "PyInstaller", "MEDIUM",
     "PyInstaller embedded package marker"),
    (b"pyi-", "PyInstaller", "MEDIUM",
     "PyInstaller marker prefix"),
    (b"py2app", "py2app", "LOW",
     "py2app wrapper — Python app bundle"),
    # Nuitka — compiled Python, documented current macOS threat (Infiniti
    # Stealer, March 2026: ClickFix-delivered, Nuitka-compiled Python 3.11).
    (b"\x4b\x41\x59\x28\xb5\x2f\xfd", "Nuitka", "HIGH",
     "Nuitka onefile archive marker (\"KAY(\" header + Zstandard magic) — "
     "compiled Python payload"),
    (b"__compiled__", "Nuitka", "MEDIUM",
     "Nuitka '__compiled__' module attribute — standalone build marker"),
    # LLVM Obfuscator / Hikari / o-llvm
    (b"__cstring\x00", "LLVM", "LOW",
     "Standard LLVM section (normal, but check with entropy)"),
    # Custom/unknown — high-entropy section with no readable strings
    # (handled via entropy analysis, not byte signatures)
]


def detect_packer_signatures(binary_path: str) -> list:
    """Scan binary bytes for known packer signatures."""
    matches = []
    try:
        with open(binary_path, "rb") as f:
            data = f.read()
        for sig, packer, risk, detail in PACKER_SIGNATURES:
            if sig in data:
                matches.append({
                    "packer": packer,
                    "signature": sig.decode("utf-8", errors="replace"),
                    "risk": risk,
                    "detail": detail,
                })
    except Exception:
        pass
    return matches
