---
name: macskillet
description: >
  Use when asked to analyze, classify, or investigate a macOS .app bundle or
  Mach-O binary for malware, risk, or suspicious behavior. Triggers on
  "analyze this app", "is this binary malicious", "check this Mac sample",
  "classify this binary", "ClickFix detection", "does this app have
  persistence mechanisms".
---

# MacSkillet — macOS Malware Classifier

## Overview

Classifies macOS `.app` bundles and Mach-O binaries as **MALICIOUS / SUSPICIOUS / BENIGN** using an agentic AI reasoning loop over static features extracted via native macOS tools or LIEF. Returns a verdict with full explainable reasoning chain.

## When to Use

- Analyzing a macOS sample for threats or suspicious behavior
- Investigating a binary from an incident (ClickFix delivery, dropper, stealer)
- Batch-classifying a malware research dataset
- Checking signing status, notarization, entitlements, or ClickFix indicators

**Not for:** Dynamic analysis, network traffic, memory forensics.

## Quick Reference

```bash

# Single sample — Claude API
macskillet /path/to/App.app --pretty

# Single sample — offline (local LLM)
macskillet /path/to/App.app --ollama --model qwen2.5:14b

# Feature extraction only (no AI, cacheable)
macskillet /path/to/App.app --features-only --pretty

# Deep scan: also analyze embedded AppleScripts/dylibs/helper binaries (default limit 10)
macskillet /path/to/App.app --deep --pretty

# Batch
macskillet --batch /path/to/samples/ -o results.jsonl

# Zero-dependency bash triage
bash quick_risk.sh /path/to/App.app
```

Cross-platform (Linux/Windows, no macOS toolchain):
```bash
uv sync --extra portable
macskillet --backend portable /path/to/binary --pretty
```

## Output

| Field | Values |
|---|---|
| `verdict` | `MALICIOUS` / `SUSPICIOUS` / `BENIGN` |
| `confidence` | `HIGH` / `MEDIUM` / `LOW` |
| `risk_score` | Integer — <3 benign, 6–8 suspicious, 13+ malicious |
| `recommendation` | `BLOCK` / `INVESTIGATE` / `ALLOW` |
| `key_indicators` | Ordered list of top signals |
| `reasoning_chain` | Step-by-step: observation → inference → risk_delta |
| `obfuscation_detection` | Packing/entropy/packer-signature/run-only-AppleScript result |
| `deep_scan` | (with `--deep`) embedded AppleScript/dylib/helper-binary findings |

There is no dedicated `clickfix_detection` field — ClickFix-style delivery indicators are
covered by the general suspicious-string categories (`gatekeeper_bypass`, `automation`,
`download_execute`, `malware_family_marker`, ...) and `obfuscation_detection`'s
`runonly_applescript` check, not a separate precomputed score/chain-label.

## Key Capabilities

- **ClickFix-style delivery detection** — via suspicious-string categories (quarantine
  tampering, shell piping, `do shell script`/`applescript://` automation, AMOS/Odyssey
  family markers) and run-only AppleScript detection, not a dedicated ClickFix module
- **Process injection triad** — mach_vm_allocate + mach_vm_write + thread_create_running
- **Signature & trust** — codesign status, notarization, Gatekeeper verdict, team ID
- **Packing detection** — entropy analysis, packer signatures (UPX/MPRESS/Nuitka/...), string
  density anomalies; Nuitka-compiled Python binaries are treated as a suspicion boost, not a
  legitimate-runtime suppression (unlike Go/Rust/Swift)
- **Decoded base64 classification** — validated base64 strings are decoded and classified
  (compiled Python bytecode, compressed payload, encoded script, or a recursive suspicious-
  string match), not left as a flat generic finding
- **Deep bundle scan** (`--deep`) — statically analyzes embedded AppleScripts, dylibs, and
  helper binaries inside a bundle, catching e.g. a clean wrapper app shipping a
  PyInstaller/Nuitka-compiled stealer as a helper binary
- **ObjC class/method analysis** — often unstripped, reveals capability intent
- **Quarantine xattr** — download origin URL, source application

## Prerequisites

```bash
xcode-select --install          # macOS native toolchain

# Pick one inference backend:
export ANTHROPIC_API_KEY="..."              # Claude API → use default mode
# OR: brew install ollama && ollama pull qwen2.5:14b && ollama serve  # → add --ollama
# Neither available? Use --features-only for offline extraction without AI verdict
```

## Sub-Skills

Load these for deeper context during analysis:

- `macskillet-tools` — all 13 agent tools, recommended call order, what each returns
- `macskillet-risk-signals` — scoring tables, signal weights, verdict thresholds
- `macskillet-modes` — when to use `--mode one_shot|react|hierarchical|react_thinking`; cost vs accuracy tradeoffs
