#!/usr/bin/env python3
"""
classify_bundle_native.py — End-to-end macOS app classifier using native tools + Claude AI.

Zero external dependencies except anthropic SDK.
All feature extraction uses built-in macOS tools only.

Usage:
    python3 classify_bundle_native.py /path/to/App.app
    python3 classify_bundle_native.py /path/to/binary --pretty
    python3 classify_bundle_native.py --batch /path/to/samples/ -o results.jsonl
"""

import argparse
import json
import os
import sys
from pathlib import Path

from macskillet import DEFAULT_CLAUDE_MODEL

from macskillet.native.extract_features_native import extract, is_macho
from macskillet.native.tools_native import TOOLS, dispatch_tool
from macskillet.native.utils import _parse_json_verdict
from macskillet.native.agent_modes import (
    REACT_SYSTEM_PROMPT as SYSTEM_PROMPT,
    _run_react_loop,
    _precomputed_signals_block,
    run_one_shot,
    run_hierarchical,
    run_react_thinking,
)

#: Re-exported for backwards compatibility; the single definition lives in
#: macskillet/__init__.py so every backend and mode stays in lockstep.
CLAUDE_MODEL = DEFAULT_CLAUDE_MODEL


# ---------------------------------------------------------------------------
# Agent loop
# ---------------------------------------------------------------------------

def run_agent(features: dict, model: str = CLAUDE_MODEL, max_turns: int = 15) -> dict:
    """ReAct agent loop (react mode). Delegates to _run_react_loop."""
    import anthropic
    client = anthropic.Anthropic()

    sample = features.get("sample", {})
    sig = features.get("signature") or {}
    pf = features.get("preflight") or {}

    initial_message = (
        f"Please analyze this macOS sample:\n\n"
        f"**Sample:** {sample.get('name', 'unknown')}\n"
        f"**Type:** {sample.get('type', 'unknown')}\n"
        f"**SHA256:** {sample.get('sha256', 'N/A')}\n"
        f"**Size:** {sample.get('filesize_bytes', 'N/A')} bytes\n"
        f"**Extraction:** Native macOS tools (otool, codesign, nm, etc.)\n\n"
        f"**Quick context:**\n"
        f"- Code signature: {sig.get('signing_status', 'unknown')}\n"
        f"- Quarantine present: {pf.get('has_quarantine', 'unknown')}\n"
        f"- Strings of interest: "
        f"{len(features.get('binary', {}).get('strings_of_interest', []) if features.get('binary') else [])}\n"
        f"{_precomputed_signals_block(features)}\n"
        "Begin your analysis. Use tools to gather information, then deliver your verdict as JSON."
    )

    print(f"[agent] Analyzing: {sample.get('name', 'unknown')}", file=sys.stderr)
    verdict, tool_call_log = _run_react_loop(
        client, features, TOOLS, SYSTEM_PROMPT, initial_message, model, max_turns
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

    verdict["agent_tool_calls"] = tool_call_log
    verdict["sample"] = features.get("sample", {})
    verdict["inference_backend"] = "claude"
    return verdict


# ---------------------------------------------------------------------------
# Pretty print
# ---------------------------------------------------------------------------

COLORS = {"MALICIOUS": "\033[91m", "SUSPICIOUS": "\033[93m", "BENIGN": "\033[92m"}
R, B = "\033[0m", "\033[1m"

def print_report(report: dict):
    v = report.get("verdict", "?")
    c = report.get("confidence", "?")
    score = report.get("risk_score", "?")
    name = report.get("sample", {}).get("name", "?")
    sha = report.get("sample", {}).get("sha256", "?")
    col = COLORS.get(v, "")
    backend = report.get("inference_backend", "claude")
    print(f"\n{'='*58}", file=sys.stderr)
    print(f"{B}Sample:{R}  {name}", file=sys.stderr)
    print(f"{B}SHA256:{R}  {str(sha)[:20]}...", file=sys.stderr)
    print(f"{B}Backend:{R} {backend}", file=sys.stderr)
    print(f"{B}Verdict:{R} {col}{B}{v}{R} ({c} confidence, score={score})", file=sys.stderr)
    print(f"{B}Action:{R}  {report.get('recommendation', '?')}", file=sys.stderr)
    print(f"\n{B}Summary:{R}\n  {report.get('summary', '')}", file=sys.stderr)

    # ClickFix / obfuscation quick summary from features
    cf = report.get("clickfix_detection") or {}
    if cf.get("clickfix_suspected"):
        print(f"\n{B}⚠ ClickFix:{R} {cf.get('summary', '')}", file=sys.stderr)
    ob = report.get("obfuscation_detection") or {}
    if ob.get("obfuscation_suspected") or ob.get("packing_suspected"):
        print(f"\n{B}⚠ Packing:{R} {ob.get('summary', '')}", file=sys.stderr)

    indicators = report.get("key_indicators", [])
    if indicators:
        print(f"\n{B}Key indicators:{R}", file=sys.stderr)
        for i in indicators[:6]:
            print(f"  • {i}", file=sys.stderr)
    chain = report.get("reasoning_chain", [])
    if chain:
        print(f"\n{B}Reasoning ({len(chain)} steps):{R}", file=sys.stderr)
        for step in chain:
            d = step.get("risk_delta", 0)
            ds = f"+{d}" if d > 0 else str(d)
            print(f"  [{step.get('step','?')}] {step.get('observation','')} → {step.get('inference','')} (Δ{ds})", file=sys.stderr)
    print(f"{'='*58}\n", file=sys.stderr)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="macOS App Classifier (Native) — static analysis + agentic AI verdict"
    )
    parser.add_argument("sample", nargs="?", help=".app bundle or Mach-O binary")
    parser.add_argument("--batch", metavar="DIR", help="Classify all samples in directory")
    parser.add_argument("-o", "--output", help="Output file")
    parser.add_argument("--pretty", action="store_true")
    parser.add_argument("--features-only", action="store_true", help="Extract features only, no AI")
    parser.add_argument("--ollama", action="store_true",
                        help="Use local Ollama LLM instead of Claude API")
    parser.add_argument("--apple", action="store_true",
                        help="Use Apple Foundation Models (on-device, macOS 26+ with Apple Intelligence)")
    parser.add_argument("--model", default="qwen2.5:14b",
                        help="Ollama model when using --ollama (default: qwen2.5:14b)")
    parser.add_argument(
        "--mode",
        choices=["react", "one_shot", "hierarchical", "react_thinking"],
        default="react",
        help="Agentic analysis mode: react (default), one_shot, hierarchical, react_thinking",
    )
    args = parser.parse_args()

    use_ollama = args.ollama
    use_apple = args.apple
    if use_ollama and use_apple:
        print("[!] --ollama and --apple are mutually exclusive.", file=sys.stderr)
        sys.exit(1)
    if not use_ollama and not use_apple and not os.environ.get("ANTHROPIC_API_KEY") and not args.features_only:
        print("[!] ANTHROPIC_API_KEY not set. Use --ollama for Ollama or --apple for on-device inference.", file=sys.stderr)
        sys.exit(1)

    def _run_agent(features):
        if use_apple:
            if args.mode != "react":
                print(
                    f"[!] --apple only supports react mode; ignoring --mode {args.mode}",
                    file=sys.stderr,
                )
            from macskillet.native.agent_loop_foundation import run_agent_foundation
            return run_agent_foundation(features)
        if use_ollama:
            if args.mode != "react":
                print(
                    f"[!] --ollama only supports react mode; ignoring --mode {args.mode}",
                    file=sys.stderr,
                )
            from macskillet.native.agent_loop_local import run_agent_local
            return run_agent_local(features, model=args.model)
        dispatch = {
            "react": lambda: run_agent(features, model=CLAUDE_MODEL),
            "one_shot": lambda: run_one_shot(features, model=CLAUDE_MODEL),
            "hierarchical": lambda: run_hierarchical(features, model=CLAUDE_MODEL),
            "react_thinking": lambda: run_react_thinking(features, model=CLAUDE_MODEL),
        }
        return dispatch[args.mode]()

    if args.sample:
        print(f"[*] Extracting features (native tools)...", file=sys.stderr)
        features = extract(args.sample)
        if features.get("errors"):
            print(f"[!] {features['errors']}", file=sys.stderr)

        if args.features_only:
            out = json.dumps(features, indent=2 if args.pretty else None, default=str)
            if args.output:
                with open(args.output, "w") as fh:
                    fh.write(out)
            else:
                print(out)
            return

        report = _run_agent(features)
        report["clickfix_detection"] = features.get("clickfix")
        report["obfuscation_detection"] = features.get("obfuscation")
        print_report(report)
        out = json.dumps(report, indent=2 if args.pretty else None, default=str)
        if args.output:
            with open(args.output, "w") as fh:
                fh.write(out)
        else:
            print(out)

    elif args.batch:
        if not args.output:
            print("[!] --batch requires -o", file=sys.stderr); sys.exit(1)
        samples = []
        for root, dirs, files in os.walk(args.batch):
            for name in files:
                fp = os.path.join(root, name)
                if is_macho(fp): samples.append(fp)
            for d in list(dirs):
                if d.endswith(".app"):
                    samples.append(os.path.join(root, d)); dirs.remove(d)
        print(f"[*] {len(samples)} samples found", file=sys.stderr)
        with open(args.output, "w") as f:
            for i, s in enumerate(samples):
                print(f"\n[{i+1}/{len(samples)}] {s}", file=sys.stderr)
                try:
                    features = extract(s)
                    if args.features_only:
                        report = features
                    else:
                        report = _run_agent(features)
                        report["clickfix_detection"] = features.get("clickfix")
                        report["obfuscation_detection"] = features.get("obfuscation")
                        print_report(report)
                    f.write(json.dumps(report, default=str) + "\n"); f.flush()
                except Exception as e:
                    print(f"[!] Error: {e}", file=sys.stderr)
                    f.write(json.dumps({"sample": {"path": s}, "error": str(e)}) + "\n")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
