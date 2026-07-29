# MacSkillet — Command Reference

## Setup

```bash
# macOS toolchain (required for src/macskillet/native/)
xcode-select --install

# Install Python deps (pick what you need)
uv sync --extra claude           # Claude API mode
uv sync --extra ollama            # Ollama local LLM mode
uv sync --extra detector         # cross-platform detector (LIEF)
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

## Cross-Platform Detector (Linux / Windows)

```bash
pip install "macskillet[claude,detector]"
export ANTHROPIC_API_KEY="sk-ant-..."
macskillet /path/to/binary --backend detector --pretty
macskillet --batch /path/to/samples/ --backend detector -o results.jsonl

# On a non-macOS host the detector backend is chosen automatically:
macskillet /path/to/binary --pretty
macskillet --list-backends
```

---

## Tests

```bash
# Run all tests
uv run pytest tests/ -v

# Run only native detector tests (no LIEF needed)
uv run pytest tests/test_clickfix_detector.py tests/test_obfuscation_detector.py tests/test_agent_modes.py -v

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
| `clickfix_detection` | ClickFix chain, score, matched indicators |
| `obfuscation_detection` | Packing techniques, entropy, packer signatures |
| `reasoning_chain` | Step-by-step: observation → inference → risk_delta |
| `agent_tool_calls` | Full audit log of tool calls |
