#!/usr/bin/env python3
"""
agent_loop_local.py — Agentic classification loop using a local LLM via Ollama.

Drop-in replacement for classify_bundle_native.py's Claude-based agent.
Uses Ollama for fully on-device, offline inference with tool-use support.

Supported models (tool-use capable):
  - llama3.1:8b     (fast, ~5GB VRAM, good for M-series Mac)
  - llama3.1:70b    (high quality, needs ~40GB RAM)
  - qwen2.5:7b      (fast, reliable tool calling)
  - qwen2.5:14b     (better reasoning, ~9GB)
  - mistral:7b      (OpenAI-compatible format)
  - deepseek-r1:8b  (reasoning model, slower but thorough)

Install:  brew install ollama && ollama pull qwen2.5:14b
Run:      ollama serve  (starts local server on :11434)

Usage:
  python3 agent_loop_local.py --sample /path/to/App.app --model qwen2.5:14b
  python3 agent_loop_local.py --features features.json
"""

import argparse
import json
import os
import sys
from pathlib import Path

from macskillet.native.tools_native import TOOLS, dispatch_tool
from macskillet.native.extract_features_native import extract
from macskillet.native.utils import _parse_json_verdict

try:
    import ollama as ollama_client
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False


# ---------------------------------------------------------------------------
# Default model — best balance of speed + tool-use quality on Apple Silicon
# ---------------------------------------------------------------------------

DEFAULT_MODEL = "qwen2.5:14b"
FALLBACK_MODEL = "llama3.1:8b"

# ---------------------------------------------------------------------------
# Convert Anthropic-style tool schema → Ollama format
# Ollama uses OpenAI-compatible tool schema (same structure, different client)
# ---------------------------------------------------------------------------

def _to_ollama_tools(anthropic_tools: list) -> list:
    """Convert Anthropic tool schema to Ollama/OpenAI-compatible format."""
    ollama_tools = []
    for tool in anthropic_tools:
        ollama_tools.append({
            "type": "function",
            "function": {
                "name": tool["name"],
                "description": tool["description"],
                "parameters": tool.get("input_schema", {
                    "type": "object",
                    "properties": {},
                    "required": []
                }),
            }
        })
    return ollama_tools


# ---------------------------------------------------------------------------
# System prompt — same analytical approach, Ollama-optimised formatting
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are an expert macOS malware analyst. Analyze the provided sample
using the available tools, then classify it as MALICIOUS, SUSPICIOUS, or BENIGN.

Analysis order:
1. get_xattr → quarantine/provenance (missing = Gatekeeper bypassed)
2. get_signature_info → signing status, notarization
3. get_entitlements → private/dangerous entitlements
4. get_bundle_info → persistence, LSUIElement, embedded scripts
5. get_dylibs → suspicious load paths
6. get_symbols + check_injection_triad → high-risk API imports
7. get_objc_info → ObjC class/method names (often very revealing)
8. get_segment_entropy → packing indicators
9. get_strings with patterns like "https?://" or "LaunchAgent"

Use tools iteratively. When done, output ONLY a JSON object:

{
  "verdict": "MALICIOUS | SUSPICIOUS | BENIGN",
  "confidence": "HIGH | MEDIUM | LOW",
  "risk_score": <integer 0-20>,
  "recommendation": "BLOCK | INVESTIGATE | ALLOW",
  "summary": "<2-4 sentences>",
  "key_indicators": ["<signal 1>", "<signal 2>"],
  "reasoning_chain": [
    {"step": 1, "observation": "...", "inference": "...", "risk_delta": <int>}
  ]
}

Output ONLY the JSON. No surrounding text, no markdown fences."""


# ---------------------------------------------------------------------------
# Agent loop
# ---------------------------------------------------------------------------

def _check_ollama_running() -> bool:
    """Check if Ollama server is reachable."""
    try:
        import urllib.request
        urllib.request.urlopen("http://localhost:11434/api/tags", timeout=2)
        return True
    except Exception:
        return False


def _list_available_models() -> list:
    """List models currently available in Ollama."""
    try:
        models_resp = ollama_client.list()
        return [m.model for m in models_resp.models]
    except Exception:
        return []


def _select_model(preferred: str) -> str:
    """Select best available model, falling back gracefully."""
    available = _list_available_models()
    if not available:
        return preferred  # Will fail later with a clear error

    # Exact match
    if preferred in available:
        return preferred

    # Prefix match (e.g. "qwen2.5:14b" matches "qwen2.5:14b-instruct-q4_K_M")
    for m in available:
        if m.startswith(preferred.split(":")[0]):
            print(f"[local-llm] Using '{m}' (closest to '{preferred}')", file=sys.stderr)
            return m

    # Fallback priority list
    for fallback in [FALLBACK_MODEL, "llama3.1:8b", "mistral:7b", "qwen2.5:7b"]:
        for m in available:
            if m.startswith(fallback.split(":")[0]):
                print(f"[local-llm] Falling back to '{m}'", file=sys.stderr)
                return m

    # Last resort: first available
    print(f"[local-llm] Using first available model: {available[0]}", file=sys.stderr)
    return available[0]


def run_agent_local(
    features: dict,
    model: str = DEFAULT_MODEL,
    max_turns: int = 15,
) -> dict:
    """
    Run the agentic classification loop using a local Ollama model.
    Returns the same structured dict as run_agent() in classify_bundle_native.py.
    """
    if not OLLAMA_AVAILABLE:
        return {
            "error": "ollama Python package not installed. Run: uv sync --extra ollama",
            "verdict": "ERROR",
        }

    if not _check_ollama_running():
        return {
            "error": (
                "Ollama server not running. Start it with: ollama serve\n"
                f"Then pull a model: ollama pull {model}"
            ),
            "verdict": "ERROR",
        }

    model = _select_model(model)
    ollama_tools = _to_ollama_tools(TOOLS)

    sample = features.get("sample", {})
    sig = (features.get("signature") or {})
    pf = (features.get("preflight") or {})

    initial_message = (
        f"Analyze this macOS sample:\n\n"
        f"Name: {sample.get('name', 'unknown')}\n"
        f"Type: {sample.get('type', 'unknown')}\n"
        f"SHA256: {sample.get('sha256', 'N/A')}\n"
        f"Size: {sample.get('filesize_bytes', 'N/A')} bytes\n"
        f"Signature: {sig.get('signing_status', 'unknown')}\n"
        f"Quarantine: {pf.get('has_quarantine', 'unknown')}\n\n"
        "Use tools to analyze, then output your verdict as a JSON object."
    )

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": initial_message},
    ]

    tool_call_log = []
    print(f"[local-llm] Model: {model} | Sample: {sample.get('name', '?')}", file=sys.stderr)

    for turn in range(max_turns):
        try:
            response = ollama_client.chat(
                model=model,
                messages=messages,
                tools=ollama_tools,
            )
        except Exception as e:
            return {"error": f"Ollama inference failed: {e}", "verdict": "ERROR"}

        msg = response.message
        tool_calls = msg.tool_calls or []

        print(
            f"[local-llm] Turn {turn+1}: "
            f"tools={[tc.function.name for tc in tool_calls]}",
            file=sys.stderr
        )

        # No tool calls → agent is done
        if not tool_calls:
            break

        # Process tool calls
        messages.append({"role": "assistant", "content": msg.content or "", "tool_calls": [
            {"function": {"name": tc.function.name, "arguments": tc.function.arguments}}
            for tc in tool_calls
        ]})

        for tc in tool_calls:
            fn_name = tc.function.name
            fn_args = tc.function.arguments
            if isinstance(fn_args, str):
                try:
                    fn_args = json.loads(fn_args)
                except Exception:
                    fn_args = {}

            print(f"[local-llm]   → {fn_name}({json.dumps(fn_args)[:80]})", file=sys.stderr)
            tool_result = dispatch_tool(features, fn_name, fn_args)
            print(f"[local-llm]     ← {str(tool_result)[:120]}", file=sys.stderr)

            tool_call_log.append({
                "tool": fn_name,
                "input": fn_args,
                "result": tool_result,
            })

            # Ollama expects tool results as role="tool" messages
            messages.append({
                "role": "tool",
                "content": json.dumps(tool_result, default=str),
            })

    # Extract final verdict from last assistant message
    final_text = ""
    for msg_item in reversed(messages):
        if msg_item.get("role") == "assistant" and msg_item.get("content"):
            final_text = msg_item["content"]
            break

    verdict = _parse_json_verdict(final_text)
    if verdict is None:
        # Prompt the model explicitly to produce JSON
        messages.append({
            "role": "user",
            "content": (
                "Based on your analysis, output ONLY a JSON verdict object with keys: "
                "verdict, confidence, risk_score, recommendation, summary, "
                "key_indicators, reasoning_chain. No other text."
            )
        })
        try:
            final_resp = ollama_client.chat(model=model, messages=messages)
            verdict = _parse_json_verdict(final_resp.message.content or "")
        except Exception:
            pass

    if verdict is None:
        verdict = {
            "verdict": "SUSPICIOUS",
            "confidence": "LOW",
            "risk_score": 0,
            "recommendation": "INVESTIGATE",
            "summary": "Local LLM did not produce a parseable verdict. Manual review required.",
            "key_indicators": [],
            "reasoning_chain": [],
            "raw_output": final_text[:500],
        }

    verdict["agent_tool_calls"] = tool_call_log
    verdict["sample"] = features.get("sample", {})
    verdict["inference_backend"] = f"ollama/{model}"
    return verdict


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="macOS App Classifier — local LLM via Ollama (offline, on-device)"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--sample", help=".app bundle or Mach-O binary")
    group.add_argument("--features", help="Pre-extracted features JSON file")
    parser.add_argument("--model", default=DEFAULT_MODEL,
                        help=f"Ollama model to use (default: {DEFAULT_MODEL})")
    parser.add_argument("-o", "--output", help="Write report to file")
    parser.add_argument("--pretty", action="store_true")
    parser.add_argument("--list-models", action="store_true",
                        help="List available Ollama models and exit")
    args = parser.parse_args()

    if args.list_models:
        if not _check_ollama_running():
            print("Ollama not running. Start with: ollama serve", file=sys.stderr)
            sys.exit(1)
        models = _list_available_models()
        print("Available models:")
        for m in models:
            print(f"  {m}")
        return

    if not OLLAMA_AVAILABLE:
        print("[!] ollama not installed. Run: uv sync --extra ollama", file=sys.stderr)
        sys.exit(1)

    if args.features:
        with open(args.features) as f:
            features = json.load(f)
    else:
        print(f"[*] Extracting features: {args.sample}", file=sys.stderr)
        features = extract(args.sample)

    print(f"[*] Running local LLM classification ({args.model})...", file=sys.stderr)
    report = run_agent_local(features, model=args.model)

    # Pretty print
    v = report.get("verdict", "?")
    colors = {"MALICIOUS": "\033[91m", "SUSPICIOUS": "\033[93m", "BENIGN": "\033[92m"}
    col = colors.get(v, "")
    R = "\033[0m"
    print(f"\n{col}Verdict: {v}{R} ({report.get('confidence','?')} confidence)", file=sys.stderr)
    print(f"Summary: {report.get('summary','')}", file=sys.stderr)

    output = json.dumps(report, indent=2 if args.pretty else None, default=str)
    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        print(f"[*] Report → {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
