#!/usr/bin/env python3
"""
agent_modes.py — Agentic analysis modes for macskillet.

Implements four analysis patterns for OBTS paper evaluation:
  - run_one_shot: single prompt, no tool use — fastest and cheapest
  - run_hierarchical: quick triage → full analysis if not clearly benign
  - run_react: plain ReAct loop over the full tool set — the default mode
  - run_react_thinking: ReAct loop with extended thinking between tool calls
  - _run_react_loop: shared helper used by run_hierarchical and run_react()

REACT_SYSTEM_PROMPT is the canonical prompt, used directly by run_react() above.
"""

import json
import sys

from macskillet import DEFAULT_CLAUDE_MODEL

try:
    import anthropic
except ImportError:
    anthropic = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# System prompts
# ---------------------------------------------------------------------------

ONE_SHOT_SYSTEM_PROMPT = """You are an expert macOS malware analyst. You have been given a complete
set of pre-extracted static analysis features for a macOS sample. Analyze all provided fields
and classify the sample as MALICIOUS, SUSPICIOUS, or BENIGN.

Work through these areas in order:
1. Provenance: quarantine xattr, download origin URLs
2. Signature: signing status, notarization, team ID, entitlements
3. Bundle: LSUIElement, persistence directories, embedded scripts
4. Imports: high-risk symbols, injection triad (mach_vm_allocate+mach_vm_write+thread_create_running)
5. ObjC classes/methods: behavioral intent (often unstripped)
6. Entropy: high __TEXT entropy (>7.0) = packing
7. Strings: C2 URLs, /tmp/ paths, shell commands, persistence strings
8. Pre-computed signals: obfuscation_precomputed if present

Correlate all signals. Multiple weak signals outweigh a single strong signal.

Output ONLY a JSON object (no surrounding text, no markdown fences):
{
  "verdict": "MALICIOUS | SUSPICIOUS | BENIGN",
  "confidence": "HIGH | MEDIUM | LOW",
  "risk_score": <integer 0-20>,
  "recommendation": "BLOCK | INVESTIGATE | ALLOW",
  "summary": "<2-4 sentence human-readable verdict>",
  "key_indicators": ["<signal 1>", "<signal 2>"],
  "reasoning_chain": [
    {"step": 1, "observation": "...", "inference": "...", "risk_delta": <int>}
  ]
}"""

TRIAGE_SYSTEM_PROMPT = """You are an expert macOS malware analyst performing a QUICK TRIAGE.
You have access to only three tools: get_xattr, get_signature_info, get_segment_entropy.
Use AT MOST 3 tool calls total, then provide your verdict.

Return BENIGN/HIGH only when ALL of these hold:
- Properly Developer ID-signed or Apple-signed AND notarized
- No high-entropy segments (not packed)
- Quarantine xattr present (Gatekeeper ran normally)

Return SUSPICIOUS/MEDIUM for any uncertainty — a deeper Stage 2 analysis will follow.

Output ONLY a JSON object:
{
  "verdict": "BENIGN | SUSPICIOUS",
  "confidence": "HIGH | MEDIUM | LOW",
  "risk_score": <integer 0-5>,
  "recommendation": "ALLOW | INVESTIGATE",
  "summary": "<1-2 sentences>",
  "key_indicators": ["<signal>"],
  "reasoning_chain": [{"step": 1, "observation": "...", "inference": "...", "risk_delta": 0}]
}"""

REACT_SYSTEM_PROMPT = """You are an expert macOS malware analyst. You have extracted static analysis
features from a macOS application using native macOS tools (codesign, otool, nm, lipo,
strings, xattr, mdls, spctl). Your job is to classify the sample as MALICIOUS, SUSPICIOUS,
or BENIGN with a detailed chain-of-thought explanation.

## Analysis order

Work through these areas using tools:

1. **Extended attributes & provenance** (get_xattr): Was the file quarantined? Where did it come from?
   Missing quarantine xattr = arrived without Gatekeeper (USB/script/archive).

2. **Signature & trust** (get_signature_info): Signing status, team ID, notarization.
   Unsigned, ad-hoc, or invalid = significant red flag.
   NOTARIZED != SAFE: 2025-2026 stealers ship clean-at-scan notarized apps that fetch
   the payload post-Gatekeeper. If `trust_assessment.credit_revoked` is true, the sample
   is signed/notarized BUT behaves maliciously — do not treat signing as exculpatory;
   use `trust_assessment.risk_adjustment` (positive) instead of a trust credit.

3. **Entitlements** (get_entitlements): Look for private entitlements, get-task-allow,
   disable-library-validation.

4. **Bundle structure** (get_bundle_info): LSUIElement, persistence dirs, embedded scripts,
   hidden files, interesting plist keys.

5. **Dylib dependencies** (get_dylibs): Suspicious load paths (/tmp/, relative, hook-named).
   Also check rpath entries for hijacking opportunities.

6. **Symbols** (get_symbols then check_injection_triad): High-risk API imports.
   The injection triad (mach_vm_allocate + mach_vm_write + thread_create_running) is
   the most reliable single indicator of malicious intent.

7. **ObjC classes & methods** (get_objc_info): ObjC names are often unstripped and reveal
   functionality directly. Suspicious class/method names are strong signals.

8. **Entropy** (get_segment_entropy): High __TEXT entropy (>7.0) = packing/obfuscation.

9. **Strings** (get_strings): C2 URLs, /tmp paths, persistence strings, shell commands,
   anti-VM checks. Use targeted patterns like "https?://" or "LaunchAgent".

10. **Cross-reference signals**: Correlate findings. Multiple weak signals = strong case.

## Key macOS-native insights

- **No quarantine xattr** is highly significant — it means Gatekeeper never ran.
  Malware often arrives via zip/archive which drops the quarantine flag.
- **ObjC method names** are gold — unlike stripped C symbols, ObjC selectors survive
  stripping. A method called `-[Exfiltrator uploadKeychainData:]` tells you everything.
- **spctl source** tells you the exact trust level Apple assigned.
- **Hardened Runtime absent** on a Developer ID-signed app post-2019 is suspicious.

## Output

When you have reached your verdict, output ONLY a JSON object (no surrounding text):

```json
{
  "verdict": "MALICIOUS | SUSPICIOUS | BENIGN",
  "confidence": "HIGH | MEDIUM | LOW",
  "risk_score": <integer>,
  "recommendation": "BLOCK | INVESTIGATE | ALLOW",
  "summary": "<2-4 sentence human-readable verdict>",
  "key_indicators": ["<signal 1>", "<signal 2>", ...],
  "reasoning_chain": [
    {"step": 1, "observation": "...", "inference": "...", "risk_delta": <int>},
    ...
  ]
}
```
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _precomputed_signals_block(features: dict) -> str:
    """One-paragraph summary of pre-computed obfuscation/deep-scan results.

    Included in the initial agent message so the agent can reference these
    synthesized signals during its reasoning without re-discovering them via tools.
    """
    ob = features.get("obfuscation") or {}
    lines = []

    if ob:
        packing = ob.get("packing_suspected", False)
        confidence = ob.get("confidence", "NONE")
        techniques = ", ".join(ob.get("techniques_detected", [])) or "none"
        lines.append(
            f"- Obfuscation/packing: {'SUSPECTED' if packing else 'not suspected'} "
            f"({confidence} confidence, techniques: {techniques})"
        )

    deep_scan = features.get("deep_scan") or {}
    if deep_scan.get("enabled"):
        lines.append(f"- Deep scan (--deep): {deep_scan.get('summary', '')}")

    if not lines:
        return ""
    return "\n**Pre-computed signals (available before tool calls):**\n" + "\n".join(lines) + "\n"


def _compact_features(features: dict) -> str:
    """Compact JSON summary of features for the one-shot prompt.

    Strips raw otool/codesign output and caps list lengths to keep the
    prompt under ~8k tokens for typical samples.
    """
    sample = features.get("sample") or {}
    pf = features.get("preflight") or {}
    sig = features.get("signature") or {}
    bundle = features.get("bundle") or {}
    binary = features.get("binary") or {}
    obfuscation = features.get("obfuscation") or {}
    deep_scan = features.get("deep_scan") or {}

    summary = {
        "sample": {
            "name": sample.get("name"),
            "type": sample.get("type"),
            "sha256": sample.get("sha256"),
            "filesize_bytes": sample.get("filesize_bytes"),
        },
        "provenance": {
            "has_quarantine": pf.get("has_quarantine"),
            "quarantine_bypassed": pf.get("quarantine_bypassed"),
            "download_origin_urls": pf.get("download_origin_urls", []),
        },
        "signature": {
            "signed": sig.get("signed"),
            "signing_status": sig.get("signing_status"),
            "team_id": sig.get("team_id"),
            "notarized": sig.get("notarized"),
            "hardened_runtime": sig.get("hardened_runtime"),
            "authority_chain": sig.get("authority_chain", []),
            "entitlements": sig.get("entitlements", {}),
        },
        "bundle": {
            "bundle_id": bundle.get("bundle_id"),
            "lsui_element": bundle.get("lsui_element"),
            "ls_background_only": bundle.get("ls_background_only"),
            "has_launch_agent": bundle.get("has_launch_agent"),
            "has_launch_daemon": bundle.get("has_launch_daemon"),
            "embedded_scripts": bundle.get("embedded_scripts", []),
        },
        "binary": {
            "architectures": binary.get("architectures", []),
            "has_encryption": binary.get("has_encryption"),
            "dylib_dependencies": binary.get("dylib_dependencies", [])[:20],
            "high_risk_symbols": binary.get("high_risk_symbols", []),
            "objc_classes": binary.get("objc_classes", [])[:30],
            "objc_methods": binary.get("objc_methods", [])[:50],
            "segment_entropy": [
                {
                    "name": s.get("name"),
                    "entropy": s.get("entropy"),
                    "high_entropy": s.get("status") in ("suspicious", "packed"),
                }
                for s in (obfuscation.get("entropy_analysis") or {}).get("segments", [])
            ],
            "strings_of_interest": features.get("strings_of_interest", [])[:30],
        },
        "obfuscation_precomputed": obfuscation,
        "deep_scan_precomputed": deep_scan,
    }
    return json.dumps(summary, indent=2, default=str)


def _resolve_backend(backend=None):
    """Return a backend object, defaulting to whichever fits this host."""
    if backend is not None:
        return backend
    from macskillet.backends import select_backend

    return select_backend()


def _run_react_loop(
    client,
    features: dict,
    tools: list,
    system_prompt: str,
    initial_message: str,
    model: str,
    max_turns: int,
    backend=None,
) -> tuple:
    """Shared ReAct loop. Returns (verdict_dict | None, tool_call_log).

    Drives a tool-use conversation until the model reaches end_turn (verdict ready)
    or max_turns is exhausted. Works with any subset of TOOLS.

    ``backend`` decides who services the tool calls. It defaults to the best
    backend for this host, so the loop is identical on macOS (native tooling)
    and off it (LIEF) — that symmetry is the point of the two-pipeline design.
    """
    from macskillet.common.utils import _parse_json_verdict

    backend = _resolve_backend(backend)

    messages = [{"role": "user", "content": initial_message}]
    tool_call_log = []
    last_response = None

    for turn in range(max_turns):
        response = client.messages.create(
            model=model,
            max_tokens=4096,
            system=system_prompt,
            tools=tools,
            messages=messages,
        )
        last_response = response

        tool_calls = [b for b in response.content if b.type == "tool_use"]
        print(
            f"[react-loop] Turn {turn + 1}: stop={response.stop_reason}, "
            f"tools={[t.name for t in tool_calls]}",
            file=sys.stderr,
        )

        if response.stop_reason == "end_turn":
            break

        tool_result_blocks = []
        for tc in tool_calls:
            result = backend.dispatch(features, tc.name, tc.input)
            tool_result_blocks.append({
                "type": "tool_result",
                "tool_use_id": tc.id,
                "content": json.dumps(result, default=str),
            })
            tool_call_log.append({"tool": tc.name, "input": tc.input, "result": result})

        messages.append({"role": "assistant", "content": response.content})
        messages.append({"role": "user", "content": tool_result_blocks})

    # Extract final text from the last response received
    final_text = ""
    if last_response is not None:
        for block in last_response.content:
            if hasattr(block, "text") and block.type == "text":
                final_text = block.text
                break

    return _parse_json_verdict(final_text), tool_call_log


# ---------------------------------------------------------------------------
# Mode: one_shot
# ---------------------------------------------------------------------------

def run_one_shot(features: dict, model: str = DEFAULT_CLAUDE_MODEL) -> dict:
    """Single-prompt classification — no tool use.

    Passes all pre-extracted features as a compact JSON context. Fastest and
    cheapest mode; use as ablation baseline vs iterative modes.
    """
    from macskillet.common.utils import _parse_json_verdict

    if anthropic is None:
        raise ImportError("anthropic SDK not installed. Run: uv sync --extra claude")

    client = anthropic.Anthropic()
    context = _compact_features(features)
    user_message = f"Analyze this macOS sample and provide your verdict:\n\n{context}"

    response = client.messages.create(
        model=model,
        max_tokens=4096,
        system=ONE_SHOT_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_message}],
    )

    text = response.content[0].text if response.content else ""
    verdict = _parse_json_verdict(text)
    if verdict is None:
        verdict = {
            "verdict": "SUSPICIOUS",
            "confidence": "LOW",
            "risk_score": 0,
            "recommendation": "INVESTIGATE",
            "summary": "One-shot agent did not produce a parseable verdict.",
            "key_indicators": [],
            "reasoning_chain": [],
            "raw_output": text[:500],
        }

    verdict["mode"] = "one_shot"
    verdict["sample"] = features.get("sample", {})
    verdict["inference_backend"] = "claude"
    verdict["input_tokens"] = response.usage.input_tokens
    verdict["output_tokens"] = response.usage.output_tokens
    return verdict


# ---------------------------------------------------------------------------
# Mode: hierarchical
# ---------------------------------------------------------------------------

def run_hierarchical(features: dict, model: str = DEFAULT_CLAUDE_MODEL, backend=None) -> dict:
    """Two-stage analysis: quick triage → full ReAct only if not clearly benign.

    Stage 1 uses 3 tools (get_xattr, get_signature_info, get_segment_entropy)
    with max 5 turns. Returns BENIGN/HIGH immediately if all signals are
    clean — skipping the expensive full analysis. Everything else proceeds to
    Stage 2 full ReAct loop.

    Expected cost reduction: 3-5× on benign-heavy datasets (typical real-world
    distribution is 70-85% benign).
    """
    import anthropic

    backend = _resolve_backend(backend)
    TOOLS = backend.tools
    client = anthropic.Anthropic()
    sample = features.get("sample") or {}
    sig = features.get("signature") or {}
    pf = features.get("preflight") or {}

    triage_tools = [
        t for t in TOOLS
        if t["name"] in ("get_xattr", "get_signature_info", "get_segment_entropy")
    ]
    triage_msg = (
        f"Quick triage — use get_xattr, get_signature_info, and get_segment_entropy "
        f"(3 calls max), then give your verdict.\n\n"
        f"Sample: {sample.get('name', 'unknown')}\n"
        f"Type: {sample.get('type', 'unknown')}\n"
        f"Signature hint: {sig.get('signing_status', 'unknown')}\n"
        f"Quarantine hint: {pf.get('has_quarantine', 'unknown')}"
    )

    print(f"[hierarchical] Stage 1 triage: {sample.get('name', '?')}", file=sys.stderr)
    triage_verdict, triage_tool_calls = _run_react_loop(
        client, features, triage_tools, TRIAGE_SYSTEM_PROMPT, triage_msg, model,
        max_turns=5, backend=backend
    )

    # Early exit: sample is clearly benign
    if (triage_verdict is not None
            and triage_verdict.get("verdict") == "BENIGN"
            and triage_verdict.get("confidence") == "HIGH"):
        print("[hierarchical] Early exit — BENIGN at Stage 1", file=sys.stderr)
        triage_verdict["mode"] = "hierarchical_early_exit"
        triage_verdict["sample"] = features.get("sample", {})
        triage_verdict["agent_tool_calls"] = triage_tool_calls
        triage_verdict["inference_backend"] = "claude"
        triage_verdict["extraction_backend"] = backend.name
        return triage_verdict

    # Stage 2: full analysis
    print("[hierarchical] Stage 2 full analysis", file=sys.stderr)
    triage_summary = (
        f"{triage_verdict.get('verdict', 'N/A')} — {triage_verdict.get('summary', '')}"
        if triage_verdict else "N/A"
    )
    full_msg = (
        f"Analyze this macOS sample:\n\n"
        f"**Sample:** {sample.get('name', 'unknown')}\n"
        f"**Type:** {sample.get('type', 'unknown')}\n"
        f"**SHA256:** {sample.get('sha256', 'N/A')}\n"
        f"**Triage result:** {triage_summary}\n"
        f"{_precomputed_signals_block(features)}\n"
        "Begin full analysis. Use tools to gather detailed information, "
        "then provide your verdict as JSON."
    )

    full_verdict, full_tool_calls = _run_react_loop(
        client, features, TOOLS, REACT_SYSTEM_PROMPT, full_msg, model,
        max_turns=15, backend=backend
    )

    if full_verdict is None:
        full_verdict = {
            "verdict": "SUSPICIOUS",
            "confidence": "LOW",
            "risk_score": 0,
            "recommendation": "INVESTIGATE",
            "summary": "Hierarchical agent did not produce a parseable verdict.",
            "key_indicators": [],
            "reasoning_chain": [],
        }

    full_verdict["mode"] = "hierarchical_full"
    full_verdict["triage_result"] = triage_verdict
    full_verdict["sample"] = features.get("sample", {})
    full_verdict["agent_tool_calls"] = triage_tool_calls + full_tool_calls
    full_verdict["inference_backend"] = "claude"
    full_verdict["extraction_backend"] = backend.name
    return full_verdict


# ---------------------------------------------------------------------------
# Mode: react_thinking
# ---------------------------------------------------------------------------

def run_react_thinking(
    features: dict,
    model: str = DEFAULT_CLAUDE_MODEL,
    thinking_budget: int = 8000,
    max_turns: int = 15,
    backend=None,
) -> dict:
    """ReAct loop with extended thinking enabled between tool calls.

    Uses the Anthropic beta `interleaved-thinking-2025-05-14` feature so the
    model reasons explicitly before each tool call. Thinking blocks are
    preserved in message history as required by the API.

    max_tokens = thinking_budget + 4096 to budget both reasoning and output JSON.
    """
    import anthropic
    backend = _resolve_backend(backend)
    TOOLS = backend.tools
    from macskillet.common.utils import _parse_json_verdict

    client = anthropic.Anthropic()
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
        "Begin your analysis. Use tools to gather information, then deliver your verdict as JSON."
    )

    messages = [{"role": "user", "content": initial_message}]
    tool_call_log = []
    last_response = None

    print(f"[react-thinking] Analyzing: {sample.get('name', '?')}", file=sys.stderr)

    for turn in range(max_turns):
        last_response = client.beta.messages.create(
            model=model,
            max_tokens=thinking_budget + 4096,
            betas=["interleaved-thinking-2025-05-14"],
            thinking={"type": "enabled", "budget_tokens": thinking_budget},
            system=REACT_SYSTEM_PROMPT,
            tools=TOOLS,
            messages=messages,
        )

        tool_calls = [b for b in last_response.content if b.type == "tool_use"]
        print(
            f"[react-thinking] Turn {turn + 1}: stop={last_response.stop_reason}, "
            f"tools={[t.name for t in tool_calls]}",
            file=sys.stderr,
        )

        if last_response.stop_reason == "end_turn":
            break

        tool_result_blocks = []
        for tc in tool_calls:
            result = backend.dispatch(features, tc.name, tc.input)
            tool_result_blocks.append({
                "type": "tool_result",
                "tool_use_id": tc.id,
                "content": json.dumps(result, default=str),
            })
            tool_call_log.append({"tool": tc.name, "input": tc.input, "result": result})

        # Preserve thinking blocks in history — required by interleaved-thinking beta
        messages.append({"role": "assistant", "content": last_response.content})
        messages.append({"role": "user", "content": tool_result_blocks})

    # Extract final text, skipping thinking blocks
    final_text = ""
    if last_response is not None:
        for block in last_response.content:
            if hasattr(block, "type") and block.type == "text":
                final_text = block.text
                break

    verdict = _parse_json_verdict(final_text)
    if verdict is None:
        verdict = {
            "verdict": "SUSPICIOUS",
            "confidence": "LOW",
            "risk_score": 0,
            "recommendation": "INVESTIGATE",
            "summary": "ReAct+thinking agent did not produce a parseable verdict.",
            "key_indicators": [],
            "reasoning_chain": [],
            "raw_output": final_text[:500],
        }

    verdict["mode"] = "react_thinking"
    verdict["sample"] = features.get("sample", {})
    verdict["agent_tool_calls"] = tool_call_log
    verdict["inference_backend"] = "claude"
    return verdict


# ---------------------------------------------------------------------------
# Mode: react (plain ReAct loop, the default)
# ---------------------------------------------------------------------------

def run_react(
    features: dict,
    model: str = DEFAULT_CLAUDE_MODEL,
    max_turns: int = 15,
    backend=None,
) -> dict:
    """Plain ReAct loop over the full tool set — the default mode.

    Observe -> plan -> act -> reflect, repeating until the model produces a
    verdict or ``max_turns`` is spent.
    """
    import anthropic

    backend = _resolve_backend(backend)
    client = anthropic.Anthropic()

    sample = features.get("sample", {})
    sig = features.get("signature") or {}
    pf = features.get("preflight") or {}

    extraction = (
        "Native macOS tools (otool, codesign, nm, spctl, xattr)"
        if backend.name == "native"
        else "Cross-platform LIEF parsing (no OS-held signals available)"
    )

    initial_message = (
        f"Please analyze this macOS sample:\n\n"
        f"**Sample:** {sample.get('name', 'unknown')}\n"
        f"**Type:** {sample.get('type', 'unknown')}\n"
        f"**SHA256:** {sample.get('sha256', 'N/A')}\n"
        f"**Size:** {sample.get('filesize_bytes', 'N/A')} bytes\n"
        f"**Extraction:** {extraction}\n\n"
        f"**Quick context:**\n"
        f"- Code signature: {sig.get('signing_status', 'unknown')}\n"
        f"- Quarantine present: {pf.get('has_quarantine', 'unknown')}\n"
        f"- Strings of interest: {len(features.get('strings_of_interest', []))}\n"
        f"{_precomputed_signals_block(features)}\n"
        "Begin your analysis. Use tools to gather information, then deliver your verdict as JSON."
    )

    print(f"[react] Analyzing: {sample.get('name', 'unknown')}", file=sys.stderr)
    verdict, tool_call_log = _run_react_loop(
        client, features, backend.tools, REACT_SYSTEM_PROMPT,
        initial_message, model, max_turns, backend=backend,
    )

    if verdict is None:
        verdict = {
            "verdict": "SUSPICIOUS",
            "confidence": "LOW",
            "risk_score": 0,
            "recommendation": "INVESTIGATE",
            "summary": "Agent did not produce a parseable verdict. Manual review required.",
            "key_indicators": [],
            "reasoning_chain": [],
        }

    verdict["mode"] = "react"
    verdict["agent_tool_calls"] = tool_call_log
    verdict["sample"] = features.get("sample", {})
    verdict["inference_backend"] = "claude"
    verdict["extraction_backend"] = backend.name
    return verdict


# ---------------------------------------------------------------------------
# Mode dispatch
# ---------------------------------------------------------------------------

#: Every agentic mode, keyed by its ``--mode`` value.
MODES = {
    "one_shot": run_one_shot,
    "react": run_react,
    "hierarchical": run_hierarchical,
    "react_thinking": run_react_thinking,
}

#: Modes that do not use tools, and therefore ignore the backend's tool set.
_TOOLLESS_MODES = frozenset({"one_shot"})


def run_mode(features: dict, mode: str = "react", backend=None, **kwargs) -> dict:
    """Run one agentic mode against ``features``.

    Single entry point for both pipelines: the mode decides *how* the agent
    reasons, the backend decides *who answers its tool calls*.
    """
    if mode not in MODES:
        raise ValueError(f"unknown mode '{mode}' (choose from {sorted(MODES)})")
    if mode in _TOOLLESS_MODES:
        return MODES[mode](features, **kwargs)
    return MODES[mode](features, backend=backend, **kwargs)
