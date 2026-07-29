"""
backends.py — pick the analysis pipeline that fits the host.

MacSkillet ships two feature-extraction pipelines behind one interface:

===============  ==========================  ==================================
Backend          Requires                    Sees
===============  ==========================  ==================================
``native``       macOS 12+, Xcode CLI tools  Everything below, plus quarantine
                                             xattrs, Gatekeeper verdict,
                                             notarization staple, download
                                             provenance, ObjC class/method
                                             names, DRM encryption state
``detector``     LIEF (any OS)               Mach-O structure, imports,
                                             segment entropy, entitlements,
                                             strings, bundle layout
===============  ==========================  ==================================

The native backend is strictly more capable *on macOS* because several signals
are held by the OS rather than the file — a stripped quarantine xattr is
invisible to any amount of byte parsing. Off macOS those signals do not exist
to be read, so the detector backend is not a degraded native backend, it is the
complete set of what is knowable from the artifact alone.

Both expose the same tool-call contract, so every agent mode in
:mod:`macskillet.native.agent_modes` runs unchanged against either.

Typical use::

    from macskillet.backends import select_backend
    backend = select_backend()          # auto
    features = backend.extract(path)
    verdict = backend.classify(path, mode="react")
"""

from __future__ import annotations

import platform
import shutil
from dataclasses import dataclass
from typing import Any, Callable

__all__ = [
    "Backend",
    "BackendUnavailable",
    "available_backends",
    "select_backend",
    "NATIVE",
    "DETECTOR",
]


class BackendUnavailable(RuntimeError):
    """Raised when a backend is requested but its prerequisites are missing."""


#: macOS CLI tools the native backend cannot work without.
_REQUIRED_NATIVE_TOOLS = ("codesign", "otool", "nm", "strings")


@dataclass(frozen=True)
class Backend:
    """One feature-extraction + tool-dispatch pipeline."""

    name: str
    description: str
    _extract: Callable[[str], dict]
    _tools: Callable[[], list]
    _dispatch: Callable[[dict, str, dict], dict]
    _check: Callable[[], str | None]

    # -- availability ------------------------------------------------------

    def unavailable_reason(self) -> str | None:
        """Human-readable reason this backend cannot run here, or ``None``."""
        return self._check()

    def is_available(self) -> bool:
        return self._check() is None

    def require(self) -> None:
        reason = self._check()
        if reason:
            raise BackendUnavailable(f"backend '{self.name}' unavailable: {reason}")

    # -- pipeline ----------------------------------------------------------

    def extract(self, path: str) -> dict:
        """Extract features for ``path``. Result carries ``sample.backend``."""
        self.require()
        features = self._extract(path)
        features.setdefault("sample", {})["backend"] = self.name
        return features

    @property
    def tools(self) -> list:
        """Anthropic-format tool schemas this backend can service."""
        self.require()
        return self._tools()

    def dispatch(self, features: dict, tool_name: str, tool_input: dict) -> dict:
        """Execute one tool call. Never raises — errors come back as ``{"error": ...}``."""
        try:
            return self._dispatch(features, tool_name, tool_input)
        except Exception as exc:  # tool implementations must not break the loop
            return {"error": f"{type(exc).__name__}: {exc}"}

    def classify(self, path: str, mode: str = "react", **kwargs: Any) -> dict:
        """Extract then classify in one call. See ``agent_modes`` for modes."""
        from macskillet.native.agent_modes import run_mode

        return run_mode(self.extract(path), mode=mode, backend=self, **kwargs)


# ---------------------------------------------------------------------------
# Availability checks
# ---------------------------------------------------------------------------

def _check_native() -> str | None:
    if platform.system() != "Darwin":
        return f"requires macOS, host is {platform.system()}"
    missing = [t for t in _REQUIRED_NATIVE_TOOLS if shutil.which(t) is None]
    if missing:
        return (
            f"missing macOS tools: {', '.join(missing)} "
            "(run `xcode-select --install`)"
        )
    return None


def _check_detector() -> str | None:
    try:
        import lief  # noqa: F401
    except ImportError:
        return "LIEF not installed (pip install 'macskillet[detector]')"
    return None


# ---------------------------------------------------------------------------
# Lazy adapters
#
# Imports are deferred so that importing this module on Linux does not drag in
# the macOS-only extractor, and importing it on a macOS box without LIEF does
# not fail either.
# ---------------------------------------------------------------------------

def _native_extract(path: str) -> dict:
    from macskillet.native.extract_features_native import extract

    return extract(path)


def _native_tools() -> list:
    from macskillet.native.tools_native import TOOLS

    return TOOLS


def _native_dispatch(features: dict, name: str, payload: dict) -> dict:
    from macskillet.native.tools_native import dispatch_tool

    return dispatch_tool(features, name, payload)


def _detector_extract(path: str) -> dict:
    from macskillet.detector.feature_extractor import extract

    return extract(path)


def _detector_tools() -> list:
    from macskillet.detector.tool_dispatcher import TOOLS

    return TOOLS


def _detector_dispatch(features: dict, name: str, payload: dict) -> dict:
    from macskillet.detector.tool_dispatcher import dispatch_tool

    return dispatch_tool(features, name, payload)


NATIVE = Backend(
    name="native",
    description="macOS built-in tooling; zero pip dependencies; sees OS-held signals",
    _extract=_native_extract,
    _tools=_native_tools,
    _dispatch=_native_dispatch,
    _check=_check_native,
)

DETECTOR = Backend(
    name="detector",
    description="LIEF-based; runs on any OS; sees everything derivable from bytes",
    _extract=_detector_extract,
    _tools=_detector_tools,
    _dispatch=_detector_dispatch,
    _check=_check_detector,
)

#: Preference order used by :func:`select_backend`.
_ORDER = (NATIVE, DETECTOR)

_BY_NAME = {b.name: b for b in _ORDER}


def available_backends() -> list[Backend]:
    """Every backend that can actually run on this host, best first."""
    return [b for b in _ORDER if b.is_available()]


def select_backend(prefer: str | None = None) -> Backend:
    """Return the backend to use.

    ``prefer`` names a backend explicitly (``"native"`` or ``"detector"``) and
    raises :class:`BackendUnavailable` if that one cannot run — an explicit
    request is never silently downgraded, because a native-vs-detector swap
    changes which signals are observable and therefore what a verdict means.

    With ``prefer=None`` the best available backend is chosen: native on a
    working macOS host, detector everywhere else.
    """
    if prefer is not None:
        backend = _BY_NAME.get(prefer)
        if backend is None:
            raise BackendUnavailable(
                f"unknown backend '{prefer}' (choose from {sorted(_BY_NAME)})"
            )
        backend.require()
        return backend

    for backend in _ORDER:
        if backend.is_available():
            return backend

    reasons = "; ".join(f"{b.name}: {b.unavailable_reason()}" for b in _ORDER)
    raise BackendUnavailable(f"no analysis backend available — {reasons}")
