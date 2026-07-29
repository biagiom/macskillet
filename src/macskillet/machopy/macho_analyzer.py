"""
macho_analyzer.py — LIEF-based Mach-O static analysis.

Direct binary parsing via LIEF.
Produces an arch-keyed dict consumed by the agent tool layer (src/detector/tools.py).
"""

import collections
import hashlib
import math

import lief

lief.logging.disable()


# ---------------------------------------------------------------------------
# File-level helpers
# ---------------------------------------------------------------------------

def is_macho(path: str) -> bool:
    """Return True if file starts with a recognized Mach-O magic number."""
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
        return magic in (
            b"\xca\xfe\xba\xbe",  # FAT
            b"\xfe\xed\xfa\xce",  # MH_MAGIC
            b"\xce\xfa\xed\xfe",  # MH_CIGAM
            b"\xfe\xed\xfa\xcf",  # MH_MAGIC_64
            b"\xcf\xfa\xed\xfe",  # MH_CIGAM_64
        )
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
# LIEF helpers
# ---------------------------------------------------------------------------

def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = collections.Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _arch_name(binary: lief.MachO.Binary) -> str:
    try:
        return binary.header.cpu_type.name.lower()
    except Exception:
        return "unknown"


def _get_imports(binary: lief.MachO.Binary) -> dict:
    """Group imported symbols by library name using dyld binding info."""
    imports: dict[str, list[str]] = {}

    if binary.has_dyld_info:
        for bi in binary.dyld_info.bindings:
            if bi.has_symbol:
                lib = bi.library.name.split("/")[-1] if bi.has_library else "unknown"
                imports.setdefault(lib, []).append(bi.symbol.name)
    else:
        # Fallback: symbols without library attribution
        for sym in binary.imported_functions:
            imports.setdefault("unknown", []).append(sym.name)

    return imports


def _get_segments(binary: lief.MachO.Binary) -> list:
    segments = []
    for seg in binary.segments:
        data = bytes(seg.content)
        segments.append({
            "segment_name": seg.name,
            "filesize": seg.file_size,
            "entropy": _entropy(data),
        })
    return segments


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_macho(binary_path: str) -> dict:
    """
    Parse a Mach-O binary (or FAT universal) with LIEF.

    Returns an arch-keyed dict whose structure matches what src/detector/tools.py
    expects.

    Schema per arch key:
        {
            "imports":   {"libname": ["sym", ...]},
            "segments":  [{"segment_name": str, "filesize": int, "entropy": float}],
            "dylibs":    ["/path/to/lib.dylib", ...],
            "signature": {"entitlements_info": {"entitlements": {}}},
        }
    """
    try:
        fat = lief.MachO.parse(binary_path)
    except Exception as e:
        return {"error": str(e)}

    if fat is None:
        return {"error": f"LIEF could not parse: {binary_path}"}

    result = {}
    for binary in fat:
        arch = _arch_name(binary)
        result[arch] = {
            "imports": _get_imports(binary),
            "segments": _get_segments(binary),
            "dylibs": [lib.name for lib in binary.libraries],
            "signature": {"entitlements_info": {"entitlements": {}}},
        }
    return result
