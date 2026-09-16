<img src="docs/assets/banner.png" height="64" alt="MacSkillet">

**MacSkillet is an AI skill for analyzing and classify macOS malware samples using an Agentic AI approach.**  
MacSkillet classifies a sample as **MALICIOUS / SUSPICIOUS / BENIGN** and returns a full
reasoning chain explaining *why* — not just a score.  
An LLM agent drives the analysis in a ReAct loop: it calls analysis tools iteratively and decides what to look at next based on
what it has already found, the way a human analyst would.

```bash
macskillet /path/to/Suspicious.app --pretty
```

```
══════════════════════════════════════════════════════
Sample:  helper
SHA256:  b4f68a58658ceceb...
Backend: native
Verdict: MALICIOUS (HIGH confidence, score=17)
Action:  BLOCK

Summary:
  Binary dropped to /tmp/helper with quarantine stripped. Complete
  process injection triad detected. AMOS-family ClickFix indicators
  present. Ad-hoc signed only.

⚠ ClickFix: HIGH confidence. Chain A (Terminal). 11 indicators matched.
⚠ Packing:  HIGH confidence. Techniques: UPX, high entropy, low string density.

Key indicators:
  • binary in /tmp/ with no quarantine xattr
  • complete injection triad: mach_vm_allocate+mach_vm_write+thread_create_running
  • UPX packer signature detected
  • /tmp/osalogging.zip exfil staging path in strings
══════════════════════════════════════════════════════
```

---

## Two pipelines

MacSkillet ships two feature-extraction backends behind one interface:

| Backend | Requires | Sees |
|---|---|---|
| `native` | macOS 12+, Xcode CLI tools | Everything below **plus** quarantine xattrs, Gatekeeper verdict, notarization staple, download provenance, ObjC class/method names, DRM encryption state |
| `portable` | LIEF (any OS) | Mach-O structure, imports, segment entropy, entitlements, strings, bundle layout, offline code-signature verification |

Both backends expose the same tool contract, so every agentic mode runs unchanged against
either one:

```bash
macskillet --list-backends
```

```
native    available
          macOS built-in tooling; zero pip dependencies; sees OS-held signals
portable  available
          LIEF-based; runs on any OS; sees everything derivable from bytes
```

The backend is selected automatically — `native` on a working macOS host, `portable`
everywhere else. An explicit `--backend` is never silently downgraded: swapping backends
changes which signals are observable, and therefore what a verdict means.

---

## Agentic modes

The agent runs a ReAct loop — observe, plan, act, reflect, repeat — until it has enough
evidence for a verdict, typically 5–12 tool calls.

| Mode | Behaviour | Use for |
|---|---|---|
| `react` | Full ReAct over the whole tool set (default) | General analysis |
| `one_shot` | Single prompt, no tools | Ablation baseline; cost floor |
| `hierarchical` | 3-tool triage, escalating to full ReAct only when not clearly benign | Benign-heavy corpora — 3–5× cheaper |
| `react_thinking` | ReAct with extended thinking between tool calls | Obfuscated or novel samples |

Analysis order, encoded in the agent's system prompt:

1. `get_xattr` — quarantine/provenance first; missing quarantine means Gatekeeper was bypassed
2. `get_signature_info` — signing status, notarization, cryptographic verification level
3. `get_entitlements` — dangerous and private entitlements
4. `get_bundle_info` — persistence dirs, `LSUIElement`, embedded scripts
5. `get_dylibs` — suspicious load paths
6. `get_symbols` + `check_injection_triad` — high-risk imports
7. `get_objc_info` — ObjC class and method names, usually unstripped and highly revealing
8. `get_segment_entropy` — packing
9. `get_strings` — C2 URLs, persistence strings, shell commands

### Inference backends

| Backend | Flag | Notes |
|---|---|---|
| Claude API | *(default)* | `claude-sonnet-5`; needs `ANTHROPIC_API_KEY` |
| Local LLM (Ollama) | `--ollama --model qwen2.5:14b` | Fully offline, on-device |
| Apple Foundation Models | `--apple` | On-device via Apple Intelligence, macOS 26 (Tahoe)+; the SDK manages the tool-calling loop itself |

```bash
# Local, offline, private
macskillet /path/to/App.app --ollama --model qwen2.5:14b --pretty

# On-device Apple Intelligence — no network call at all
macskillet /path/to/App.app --apple --pretty
```

---

## Detectors that run before the agent

Detectors run automatically during extraction, so their results are already in the
agent's context on turn one instead of being something it has to go find:

- **ClickFix** (no dedicated module) — ClickFix is the dominant macOS initial-access
  vector as of 2025–2026, covering both delivery chains:
  - **Chain A — Terminal:** `fake page → base64 -d | bash → curl download → /tmp/helper → xattr -c → exec`
  - **Chain B — Script Editor** (evades Terminal-focused protections): `fake page → applescript:// URL → Script Editor → do shell script → curl|zsh → /tmp/helper → exec`

  Detection targets the *dropped Mach-O binary itself* — drop paths, delivery primitives,
  C2 endpoints, data-harvesting targets, AMOS persistence markers, anti-analysis strings,
  packer signatures — not the delivery webpage. This is covered by two general mechanisms
  rather than a standalone detector: `common/strings.py`'s suspicious-string categories
  (`gatekeeper_bypass`, `download_execute`, `automation`, `malware_family_marker`, ...)
  and `obfuscation_detector.py`'s run-only-AppleScript check. See `docs/architecture.md`
  for why the earlier dedicated `clickfix_detector.py` was retired.
- **Obfuscation** (`obfuscation_detector.py`) — 7 methods: entropy analysis, UPX/packer
  signatures, string density, symbol anomalies, junk code detection, with a Swift
  false-positive guard.

---

## Suspicious strings

All string analysis goes through one pattern table
([`macskillet.common.strings`](src/macskillet/common/strings.py)), shared by both backends
so a pattern fix lands everywhere at once. Findings are ranked by severity, deduplicated,
and capped *after* ranking — the cap keeps the worst hits, not whichever appeared first.  
Base64 candidates are validated by decode + entropy + a compiler-mangled-symbol filter to avoid false positives.

---

## Install

```bash
# macOS, native pipeline + Claude API — the normal case
pip install "macskillet[claude]"

# Non-macOS host, or bulk cross-platform pipelines
pip install "macskillet[claude,portable]"

# Local inference instead of the API
pip install "macskillet[ollama]"

# On-device Apple Foundation Models (macOS 26+ with Apple Intelligence, Xcode 26+)
pip install "macskillet[apple]"

# Everything, including the classical-ML baseline used for evaluation
pip install "macskillet[all]"
```

The native pipeline itself has **zero Python dependencies** — it shells out only to tools
that ship with macOS (`codesign`, `spctl`, `otool`, `nm`, `lipo`, `strings`, `xattr`,
`mdls`, `plutil`). Feature extraction works on a bare install, no API key needed:

```bash
pip install macskillet
macskillet /path/to/App.app --features-only --pretty
```

Prerequisites:

```bash
xcode-select --install          # otool, nm, lipo (native backend)
export ANTHROPIC_API_KEY="sk-ant-..."
```

---

## Usage

```bash
# Classify (auto backend, react mode)
macskillet /path/to/App.app --pretty

# Force the cross-platform backend
macskillet /path/to/binary --backend portable --pretty

# Cheaper triage-first mode, good on benign-heavy corpora
macskillet /path/to/App.app --mode hierarchical

# Extraction only — no model call, no API key
macskillet /path/to/App.app --features-only -o features.json

# Batch
macskillet --batch samples/ -o results.jsonl

# Bash-only zero-dependency triage, no Python
bash src/macskillet/native/quick_risk.sh /path/to/App.app
```

Feature extraction is deliberately separate from classification. `--features-only`
produces a JSON blob that can be cached, re-classified with a different model, or fed
into an ML pipeline without paying for inference twice.

---

## Output format

Every report is JSON with these top-level fields:

| Field | Description |
|---|---|
| `verdict` | `MALICIOUS` / `SUSPICIOUS` / `BENIGN` |
| `confidence` | `HIGH` / `MEDIUM` / `LOW` |
| `risk_score` | Integer — <3 benign, 6–8 suspicious, 13+ malicious |
| `recommendation` | `BLOCK` / `INVESTIGATE` / `ALLOW` |
| `summary` | 2–4 sentence explanation |
| `key_indicators` | Ordered list of top signals |
| `reasoning_chain` | Step-by-step: observation → inference → risk_delta |
| `clickfix_detection` | ClickFix result: suspected, delivery chain, matched indicators |
| `obfuscation_detection` | Packing result: techniques, entropy, packer signatures |
| `agent_tool_calls` | Full audit log of every tool call the agent made |
| `inference_backend` | `claude`, `ollama/<model>`, or `apple_foundation_models` |
| `extraction_backend` | `native` or `portable` |

Full schema: [`docs/references-machopy/output-schema.md`](docs/references-machopy/output-schema.md)

---

## Python API

```python
from macskillet.backends import select_backend

backend = select_backend()                     # or select_backend("portable")
features = backend.extract("/path/to/App.app") # no model call
verdict  = backend.classify("/path/to/App.app", mode="react")
```

Tool implementations never raise — they return `{"error": "..."}` so a bad tool call
cannot kill the agent loop mid-analysis.

---

## Claude Code integration

MacSkillet ships as a [Claude Code skill](https://agentskills.io/specification) — Claude
Code invokes it automatically on prompts like *"analyze this app for malware"* or *"is
this binary malicious?"*, choosing the right `--mode` and returning the structured verdict
without you specifying flags.

```bash
python3 install-skill.py
```

Works on macOS, Linux, and Windows; symlinks into `~/.claude/skills/` on Unix, falls back
to copies on Windows if symlink privilege is unavailable.

Three sub-skills load on demand: `macskillet-tools` (deciding which tool to call next),
`macskillet-risk-signals` (scoring rubric reference), `macskillet-modes` (choosing between
`react`/`hierarchical`/`one_shot`/`react_thinking`).

---

## Development

```bash
git clone https://github.com/biagiom/macskillet
cd macskillet
uv sync --extra all
uv run pytest                  # unit tests
uv run pytest -m integration   # exercises the real macOS toolchain
```

Integration tests are opt-in because they require macOS and shell out to the real
toolchain (`codesign`, `spctl`, live OCSP against Apple's responder).

Never commit malware samples. `data/samples/` is gitignored and intentionally empty.

---

## References

- [`docs/architecture.md`](docs/architecture.md) — system design, the 8-phase pipeline
- [`docs/commands.md`](docs/commands.md) — full command reference
- [`docs/references-native/risk-signals.md`](docs/references-native/risk-signals.md) — risk scoring rubric
- [`docs/references-native/native-tool-cheatsheet.md`](docs/references-native/native-tool-cheatsheet.md) — macOS tool reference
- [`docs/references-machopy/api-risk-db.md`](docs/references-machopy/api-risk-db.md) — API symbol risk database
- [`docs/references-machopy/output-schema.md`](docs/references-machopy/output-schema.md) — JSON report schema
- [`docs/references-machopy/code-signature-verification.md`](docs/references-machopy/code-signature-verification.md) — the four-link offline signature verifier
- [`docs/usage-guide.html`](docs/usage-guide.html) — interactive HTML usage guide
- [`DEVELOPMENT.md`](DEVELOPMENT.md) — architecture decisions, roadmap, known issues

---

## License

Apache License 2.0 — see [LICENSE](LICENSE).
