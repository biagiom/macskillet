"""
MacSkillet — agentic static analysis and malware classification for macOS.

Two analysis pipelines share one tool contract, one risk vocabulary and one
output schema:

``macskillet.native``
    macOS-only. Uses nothing but tools that ship with the OS (codesign, spctl,
    otool, nm, lipo, strings, xattr, mdls, plutil). Zero pip dependencies.
    Reads quarantine xattrs, Gatekeeper verdicts, notarization staples and
    download provenance, none of which are recoverable from the file alone.

``macskillet.portable``
    Runs anywhere. Parses Mach-O with LIEF via :mod:`macskillet.machopy`.
    Loses the OS-mediated signals above, keeps everything derivable from bytes.

:func:`macskillet.backends.select_backend` picks between them automatically.
"""

__version__ = "0.1.0"

#: Default Anthropic model for every agent mode.
DEFAULT_CLAUDE_MODEL = "claude-sonnet-5"

__all__ = ["__version__", "DEFAULT_CLAUDE_MODEL"]
