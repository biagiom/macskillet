---
name: macskillet-modes
description: Use when choosing the --mode flag for a macskillet run, comparing cost vs accuracy across modes, or understanding how hierarchical triage differs from full ReAct analysis.
---

# MacSkillet — Analysis Modes

## Modes at a Glance

| Mode | Flag | Tools | Relative cost | Best for |
|------|------|-------|---------------|---------|
| `react` | (default) | all backend tools (native: 13, portable: 9) | medium | Unknown/novel samples |
| `one_shot` | `--mode one_shot` | none | cheapest | Bulk triage, known-clean batches |
| `hierarchical` | `--mode hierarchical` | 3 triage → all backend tools | 3-5× cheaper on benign-heavy sets | Large dataset with high benign ratio |
| `react_thinking` | `--mode react_thinking` | all backend tools + thinking | most expensive | Obfuscated, high-stakes, ambiguous |

## Decision Guide

- Single incident sample → `react` (default)
- Batch of 1000+ samples, >60% expected benign → `hierarchical`
- Obfuscated or novel packer, edge case → `react_thinking`
- Quick verdict, cost matters more than reasoning depth → `one_shot`

## How `hierarchical` Works

Stage 1: calls `get_xattr` + `get_signature_info` + `get_segment_entropy` (max 5 turns).
- Returns BENIGN/HIGH → early exit, skips Stage 2. Saves ~70% cost on clean samples.
- Any other result → Stage 2: full react loop with all backend tools.

## Output Fields

All modes return the same JSON schema (`verdict`, `confidence`, `risk_score`, etc.).
Extra fields populated differently:
- `mode`: `"one_shot"` | `"react"` | `"hierarchical"` | `"react_thinking"`
- `input_tokens` / `output_tokens`: tracked in `one_shot`; not per-turn in loop modes

## Local LLM Constraint

`--ollama` and `--apple` only support `react`. Other modes silently fall back to `react` with a stderr warning.
