# MacSkillet — Command Reference

## Setup

```bash
# macOS toolchain (required for src/macskillet/native/)
xcode-select --install

# Install Python deps (pick what you need)
uv sync --extra claude           # Claude API mode
uv sync --extra ollama            # Ollama local LLM mode
uv sync --extra portable         # cross-platform portable backend (LIEF)
uv sync --group dev              # tests only
uv sync --all-extras --group dev # everything

# Install Claude Code skill (one-time)
python3 install-skill.py
```

---

## Classify a Sample

```bash

# Claude API — default ReAct loop
macskillet /path/to/App.app --pretty

# Choose analysis mode explicitly
macskillet /path/to/App.app --mode react          # default
macskillet /path/to/App.app --mode one_shot       # fastest, no tools
macskillet /path/to/App.app --mode hierarchical   # triage → full
macskillet /path/to/App.app --mode react_thinking # extended thinking

# Save report to file
macskillet /path/to/App.app -o report.json --pretty

# Bare Mach-O binary (e.g. ClickFix-dropped)
macskillet /tmp/helper --pretty
```

---

## Local LLM (Ollama, offline)

```bash
# Start Ollama (keep running in background)
ollama serve
ollama pull qwen2.5:14b

# Classify
macskillet /path/to/App.app --ollama --model qwen2.5:14b --pretty
```

---

## Apple Foundation Models (on-device, no API key)

```bash
# Requirements: macOS 26.0+ (Tahoe), Apple Intelligence enabled, Xcode 26.0+
uv sync --extra apple

# Classify — runs entirely on-device via Apple Intelligence
macskillet /path/to/App.app --apple --pretty
```

---

## Feature Extraction Only

```bash
# Extract features without AI verdict (no API key needed, cacheable)
macskillet /path/to/App.app --features-only --pretty

# Save features for later re-classification
macskillet /path/to/App.app --features-only -o features.json

# Re-classify from cached features (local LLM)
python3 agent_loop_local.py --features features.json --model qwen2.5:14b
```

---

## Deep Scan (`--deep` / `--deep-limit`)

By default, only the bundle's main executable is statically analyzed. `--deep` extends
extraction to embedded bundle-internal items too — a notarized wrapper app hiding malicious
logic in an embedded AppleScript or helper binary would otherwise look clean.

```bash
# Also analyze embedded AppleScripts/dylibs/helper binaries (default limit: 10)
macskillet /path/to/App.app --deep --pretty

# Override the limit
macskillet /path/to/App.app --deep-limit 25 --pretty
```

Priority order when there are more candidates than the limit: embedded AppleScript files
first (common ClickFix Chain-B vector), then dylibs, then other Mach-O binaries (helper
tools, XPC services, framework executables). Results land in `features["deep_scan"]`.
Extraction-only — no extra API calls, no new agent tool; findings feed
`signature_trust`'s trust-revocation gate and a summary line in the agent's precomputed
signals, same as `obfuscation_detection` already does.

---

## Batch Analysis

```bash
# Batch — Claude API
macskillet --batch /path/to/samples/ -o results.jsonl

# Batch — local LLM
macskillet --batch /path/to/samples/ -o results.jsonl \
  --ollama --model qwen2.5:14b

# Batch with specific mode
macskillet --batch /path/to/samples/ -o results.jsonl \
  --mode hierarchical
```

---

## Zero-Dependency Bash Triage

```bash
# No Python, no API key — pure macOS tools
bash src/macskillet/native/quick_risk.sh /path/to/App.app
```

---

## Cross-Platform Portable Backend (Linux / Windows)

```bash
pip install "macskillet[claude,portable]"
export ANTHROPIC_API_KEY="sk-ant-..."
macskillet /path/to/binary --backend portable --pretty
macskillet --batch /path/to/samples/ --backend portable -o results.jsonl

# On a non-macOS host the portable backend is chosen automatically:
macskillet /path/to/binary --pretty
macskillet --list-backends
```

---

## Tests

```bash
# Run all tests
uv run pytest tests/ -v

# Run only native detector tests (no LIEF needed)
uv run pytest tests/test_obfuscation_detector.py tests/test_agent_modes.py -v

# Run with timeout enforcement
uv run pytest tests/ --timeout=30
```

---

## Output Fields

| Field | Values |
|-------|--------|
| `verdict` | `MALICIOUS` / `SUSPICIOUS` / `BENIGN` |
| `confidence` | `HIGH` / `MEDIUM` / `LOW` |
| `risk_score` | 0–20+ (≥13 = malicious) |
| `recommendation` | `BLOCK` / `INVESTIGATE` / `ALLOW` |
| `mode` | `react` / `one_shot` / `hierarchical` / `react_thinking` |
| `obfuscation_detection` | Packing techniques, entropy, packer signatures, run-only AppleScript |
| `reasoning_chain` | Step-by-step: observation → inference → risk_delta |
| `agent_tool_calls` | Full audit log of tool calls |
