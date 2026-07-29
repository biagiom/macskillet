#!/usr/bin/env python3
"""
agent_loop_foundation.py — Apple Foundation Models backend for macskillet.

Uses apple-fm-sdk (https://github.com/apple/python-apple-fm-sdk) to run
the analysis loop on-device via Apple Intelligence.

Requirements:
  - macOS 26.0+ (Tahoe) with Apple Intelligence enabled
  - Xcode 26.0+
  - uv sync --extra apple   (installs apple-fm-sdk)

Key difference from Anthropic/Ollama backends:
  The Apple FM SDK handles the tool-calling loop internally — no explicit
  ReAct turn management needed. Tools are registered at session creation;
  the native layer invokes them and continues generation automatically.
  Python just awaits the final response.
"""

import asyncio
import json
import sys
from typing import Optional

try:
    import apple_fm_sdk as fm
except ImportError:
    fm = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Generable argument schemas for parameterized tools
# (zero-arg tools use EmptyArgs)
# ---------------------------------------------------------------------------

def _define_arg_schemas():
    """Define @fm.generable arg classes. Called lazily after import check."""

    @fm.generable
    class EmptyArgs:
        pass

    @fm.generable
    class GetStringsArgs:
        pattern: str = fm.guide("Regex or substring to search for in extracted strings")

    @fm.generable
    class GetSymbolsArgs:
        filter: Optional[str] = fm.guide("Optional regex filter to narrow symbol results")

    @fm.generable
    class LookupApiRiskArgs:
        symbol: str = fm.guide("Symbol name to look up risk for, e.g. 'mach_vm_write'")

    return EmptyArgs, GetStringsArgs, GetSymbolsArgs, LookupApiRiskArgs


# ---------------------------------------------------------------------------
# Tool factory
# ---------------------------------------------------------------------------

def _make_tool(tool_name: str, tool_desc: str, arg_class, extractor, features: dict, log: list):
    """Return an fm.Tool instance that delegates to dispatch_tool()."""
    from macskillet.native.tools_native import dispatch_tool

    class _BuiltTool(fm.Tool):
        name = tool_name
        description = tool_desc

        @property
        def arguments_schema(self):
            return arg_class.generation_schema()

        async def call(self, args: fm.GeneratedContent) -> str:
            tool_input = extractor(args)
            result = dispatch_tool(features, tool_name, tool_input)
            log.append({"tool": tool_name, "input": tool_input, "result": result})
            print(f"[foundation] tool: {tool_name}", file=sys.stderr)
            return json.dumps(result, default=str)

    return _BuiltTool()


def _build_tools(features: dict, log: list) -> list:
    """Instantiate all 13 agent tools as fm.Tool objects."""
    from macskillet.native.tools_native import TOOLS

    EmptyArgs, GetStringsArgs, GetSymbolsArgs, LookupApiRiskArgs = _define_arg_schemas()

    def _empty(args):
        return {}

    def _get_filter(args):
        v = args.value(type_class=str, for_property="filter")
        return {"filter": v} if v else {}

    def _get_pattern(args):
        return {"pattern": args.value(type_class=str, for_property="pattern")}

    def _get_symbol(args):
        return {"symbol": args.value(type_class=str, for_property="symbol")}

    ARG_MAP = {
        "get_xattr":            (EmptyArgs,        _empty),
        "get_signature_info":   (EmptyArgs,        _empty),
        "get_entitlements":     (EmptyArgs,        _empty),
        "get_dylibs":           (EmptyArgs,        _empty),
        "get_load_commands":    (EmptyArgs,        _empty),
        "get_objc_info":        (EmptyArgs,        _empty),
        "get_segment_entropy":  (EmptyArgs,        _empty),
        "get_bundle_info":      (EmptyArgs,        _empty),
        "check_injection_triad":(EmptyArgs,        _empty),
        "get_lipo_info":        (EmptyArgs,        _empty),
        "get_symbols":          (GetSymbolsArgs,   _get_filter),
        "get_strings":          (GetStringsArgs,   _get_pattern),
        "lookup_api_risk":      (LookupApiRiskArgs,_get_symbol),
    }

    tools = []
    for t in TOOLS:
        name = t["name"]
        desc = t["description"]
        arg_class, extractor = ARG_MAP[name]
        tools.append(_make_tool(name, desc, arg_class, extractor, features, log))
    return tools


# ---------------------------------------------------------------------------
# Agent entry point
# ---------------------------------------------------------------------------

async def _run_async(features: dict) -> tuple:
    """Async core. Single session.respond() — SDK handles tool loop internally."""
    from macskillet.native.agent_modes import REACT_SYSTEM_PROMPT, _precomputed_signals_block
    from macskillet.native.utils import _parse_json_verdict

    fm_model = fm.SystemLanguageModel()
    is_available, reason = fm_model.is_available()
    if not is_available:
        raise RuntimeError(f"Apple Foundation Models not available: {reason}")

    tool_call_log: list = []
    tools = _build_tools(features, tool_call_log)

    session = fm.LanguageModelSession(
        instructions=REACT_SYSTEM_PROMPT,
        tools=tools,
    )

    sample = features.get("sample") or {}
    sig = features.get("signature") or {}
    pf = features.get("preflight") or {}

    initial_message = (
        f"Please analyze this macOS sample:\n\n"
        f"**Sample:** {sample.get('name', 'unknown')}\n"
        f"**Type:** {sample.get('type', 'unknown')}\n"
        f"**SHA256:** {sample.get('sha256', 'N/A')}\n"
        f"**Size:** {sample.get('filesize_bytes', 'N/A')} bytes\n\n"
        f"**Quick context:**\n"
        f"- Code signature: {sig.get('signing_status', 'unknown')}\n"
        f"- Quarantine present: {pf.get('has_quarantine', 'unknown')}\n"
        f"{_precomputed_signals_block(features)}\n"
        "Begin your analysis. Use tools to gather information, "
        "then deliver your verdict as JSON."
    )

    print(f"[foundation] Analyzing: {sample.get('name', 'unknown')}", file=sys.stderr)
    response = await session.respond(initial_message)

    verdict = _parse_json_verdict(str(response))
    return verdict, tool_call_log


def run_agent_foundation(features: dict) -> dict:
    """Synchronous entry point — called from classify_bundle_native.py."""
    if fm is None:
        raise ImportError(
            "apple-fm-sdk not installed. Run: uv sync --extra apple\n"
            "Requires macOS 26.0+ with Apple Intelligence enabled."
        )

    sample = features.get("sample", {})

    try:
        verdict, tool_call_log = asyncio.run(_run_async(features))
    except RuntimeError as e:
        return {
            "verdict": "SUSPICIOUS",
            "confidence": "LOW",
            "risk_score": 0,
            "recommendation": "INVESTIGATE",
            "summary": f"Apple Foundation Models unavailable: {e}",
            "key_indicators": [],
            "reasoning_chain": [],
            "inference_backend": "apple_foundation_models",
        }

    if verdict is None:
        verdict = {
            "verdict": "SUSPICIOUS",
            "confidence": "LOW",
            "risk_score": 0,
            "recommendation": "INVESTIGATE",
            "summary": "Foundation model agent did not produce a parseable verdict. Manual review required.",
            "key_indicators": [],
            "reasoning_chain": [],
        }

    verdict["mode"] = "react"
    verdict["sample"] = sample
    verdict["agent_tool_calls"] = tool_call_log
    verdict["inference_backend"] = "apple_foundation_models"
    return verdict
