#!/usr/bin/env python3
"""
report.py — Human-readable verdict report formatting.

Shared by both pipelines: reads only fixed-schema fields (verdict, confidence,
risk_score, sample, inference_backend, recommendation, summary, key_indicators,
reasoning_chain, obfuscation_detection) that are populated identically on
native and portable, so one implementation serves both regardless of which
`--backend` produced the report. Used by `cli.py` for every classify run.
"""

import sys

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

    # Obfuscation quick summary from features
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
