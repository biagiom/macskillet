# Architecture

## System Overview

The classifier is a pipeline of three loosely-coupled stages:

```
[Static Feature Extraction] → [Agentic AI Loop] → [Classification Report]
        ↑                              ↑
   native tools              tools.py (13 tools)
   (no API calls)            dispatches back to features
```

Each stage can be run independently. Feature extraction produces a deterministic
JSON blob. The AI loop consumes that blob via tool calls and produces a JSON report.

---

## Stage 1: Feature Extraction (`feature_extractor.py`)

Entry point: `extract(path: str) -> dict`

Runs 7 phases in sequence:

```python
features = {
    "sample":      {...},   # name, path, sha256, type
    "preflight":   {...},   # file type, xattr, mdls metadata
    "bundle":      {...},   # Info.plist, structure, persistence
    "signature":   {...},   # codesign, spctl, xcrun stapler
    "binary":              {...},   # otool, nm, lipo (segments, symbols, entropy)
    "strings_of_interest": [...],   # common/strings.py taxonomy — same top-level field on both pipelines
    "obfuscation":         {...},   # obfuscation_detector output (auto)
    "errors":              [...],
}
```

Each phase is implemented as a standalone function (`analyze_preflight`,
`analyze_bundle`, `analyze_signature`, `analyze_binary`). They're called in
sequence with error handling — a failure in one phase doesn't abort the others.
`strings_of_interest` used to sit nested inside `analyze_binary()`'s own return dict
(`features["binary"]["strings_of_interest"]`) — it's now relocated to the top level
by `extract()` right after `analyze_binary()` runs, matching the portable pipeline's
shape (which always had it flat).

`obfuscation_detector.py` is called at the end of `extract()` and receives the full
features dict. It's lazy-imported with try/except so a missing module doesn't break
extraction. There is no dedicated ClickFix detector — ClickFix-style delivery
indicators are covered by the shared suspicious-string taxonomy in `common/strings.py`
(top-level `strings_of_interest`) plus obfuscation's `runonly_applescript` check.

### subprocess wrapper

All tool invocations go through:
```python
def run(cmd: list, timeout: int = 30) -> tuple[str, str, int]:
    # returns (stdout, stderr, returncode)
    # handles: TimeoutExpired, FileNotFoundError
```

This ensures consistent timeout handling and graceful degradation when a tool
isn't available (e.g. `xcrun` without Xcode installed).

---

## Stage 2: Agent Tools (`tools.py`)

The 13 tools are the interface between the AI loop and the features blob.
They don't run any subprocesses — they query the pre-extracted features JSON.

```
Tool call from AI                   →    Tool implementation
get_signature_info()                →    reads features["signature"]
get_entitlements()                  →    reads features["signature"]["entitlements"]
check_injection_triad()             →    reads features["binary"]["symbols_imported"]
...
```

Each tool returns a `dict`. If data is missing it returns `{"error": "..."}`.
The AI agent is designed to handle these gracefully in its reasoning.

### Adding a new tool

1. Add schema entry to `TOOLS` list (Anthropic JSON schema format)
2. Add implementation function: `def tool_new_name(features: dict, ...) -> dict`
3. Add entry in `dispatch_tool()` dispatch table
4. Update system prompt in `common/agent_modes.py` to describe the tool

The tool automatically becomes available in both Claude and Ollama modes.

---

## Stage 3: AI Agent Loop

Two implementations with the same interface: given `features`, return a verdict `dict`.

### Claude API (`common/agent_modes.py` → `run_react()`)

```python
client = anthropic.Anthropic()
response = client.messages.create(
    model="claude-sonnet-4-20250514",
    system=SYSTEM_PROMPT,
    tools=TOOLS,               # Anthropic format
    messages=messages,
)
```

The agent loop:
```
1. Send features summary + SYSTEM_PROMPT
2. If response has tool_calls → execute via dispatch_tool() → append results
3. Repeat until stop_reason == "end_turn" (no more tool calls)
4. Extract JSON verdict from final assistant message
5. Fallback: parse JSON from any pattern match in output
```

### Ollama local (`agent_loop_local.py` → `run_agent_local()`)

Same loop, different client:
```python
response = ollama_client.chat(
    model=model,
    messages=messages,
    tools=ollama_tools,        # OpenAI format (auto-converted)
)
tool_calls = response.message.tool_calls
```

Tool results are sent back as `role="tool"` messages (OpenAI convention)
rather than `role="user"` with `tool_result` blocks (Anthropic convention).

### Verdict parsing

The agent is prompted to output a JSON object as its final message. The parser
tries three strategies in order:
1. Extract JSON from ` ```json ... ``` ` fence
2. Extract first `{...}` containing `"verdict"` key
3. Parse entire message as JSON

If all fail, returns a default `SUSPICIOUS / LOW` verdict with a note for manual review.

---

## ClickFix Detection (no dedicated module)

There is no `clickfix_detector.py` — a dedicated detector existed briefly but was retired:
its string-indicator table was fed from a separate, narrower pre-filter that made 82% of its
own indicators unreachable, and its binary-signature scan duplicated
`obfuscation_detector.py`'s packer detection (which scans the whole file, not just 64KB).

ClickFix-style delivery is now detected via two already-general mechanisms:
- **Suspicious strings** (`common/strings.py`, surfaced at top-level `strings_of_interest`):
  quarantine tampering (`gatekeeper_bypass`), shell piping (`download_execute`),
  `do shell script`/`osascript`/`applescript://` (`automation`), AMOS/Odyssey family markers
  (`malware_family_marker`), TCC abuse, developer-secret harvesting, legitimate-cloud C2
  abuse, and shell-config persistence.
- **Run-only AppleScript detection** (`obfuscation_detector.py`'s `runonly_applescript`
  check) — AMOS/ClickFix payloads ship run-only applets to hide their logic from static
  analysis; this is detected via the `0xFADEDEAD` marker.

`common/signature_trust.py`'s "notarized ≠ safe" trust-revocation gate reads both signals
directly, rather than a dedicated ClickFix score/confidence/delivery-chain output. There is
no equivalent to the old `clickfix_suspected` boolean or Chain A/Chain B label — the
underlying evidence (which category matched, or whether run-only AppleScript was found) is
available to the agent's reasoning chain without a precomputed summary.

---

## Obfuscation Detector (`obfuscation_detector.py`)

Input: `features` dict
Output: `dict` with `packing_suspected`, `obfuscation_suspected`, `confidence`, `techniques_detected`, `score`

### Detection methods (ordered by reliability)

1. **Packer signatures** (highest confidence) — byte pattern match
   - `UPX!`, `MPRESS1`, `VMProtect` — near-certain if found
   
2. **Section name anomalies** — otool section names
   - `UPX0`, `UPX1`, `MPRESS1/2` — confirms packer

3. **Segment entropy** — per-segment Shannon entropy
   - `__TEXT > 7.5` = packed (normal legitimate range is 4.5–6.5)
   - Uses actual fileoff+filesize from otool output to read the right bytes

4. **String density** — strings/KB
   - `< 5 strings/KB` in a large binary = packed
   - Normal legitimate apps: 20–80 strings/KB

5. **Symbol table anomalies** — nm output
   - 0 symbols in >500KB binary = stripped/packed
   - >5000 symbols = junk code padding (OSX.Zuru pattern)

6. **Import count** — nm -u output
   - `< 3 imports` in >200KB binary = suspicious

7. **Encryption flag** — otool -l
   - `LC_ENCRYPTION_INFO` with `cryptid=1`

### Language runtime adjustment

Go/Rust/Nim produce high entropy and low string density legitimately.
The detector identifies the runtime via byte signatures and string patterns,
then reduces the score to avoid false positives:
- Go/Rust: subtract 3 from entropy score, 2 from string density score
- Nim: add 2 (Nim is more commonly found in macOS malware)

---

## Risk Signal Taxonomy

See `docs/references-native/risk-signals.md` for the full rubric.

Eight categories, each with numeric weights:
1. Code Signature Signals (-2 to +5)
2. Bundle Structure Signals (+2 to +4)
3. Mach-O Header Signals (+1 to +4)
4. Segment Entropy Signals (+2 to +4)
5. Import/API Signals (+1 to +5)
6. Dylib/Dependency Signals (+1 to +5)
7. String Indicators (+2 to +4)
8. Entitlement Signals (-1 to +5)

Verdict thresholds (for agent guidance — final verdict is AI-determined):
```
score ≤ 2   → BENIGN / HIGH
score 3–5   → BENIGN / MEDIUM
score 6–8   → SUSPICIOUS / LOW–MEDIUM
score 9–12  → SUSPICIOUS / HIGH
score 13–17 → MALICIOUS / MEDIUM
score ≥ 18  → MALICIOUS / HIGH
```

The agent uses these thresholds as a starting point but can override based on
strong individual indicators (e.g. complete injection triad alone warrants MALICIOUS).

---

## Data Flow Diagram

```
cli.py
  │
  ├── backend.extract(path)                  # feature_extractor.py
  │     ├── analyze_preflight(path)          # xattr, mdls, file
  │     ├── analyze_bundle(path)             # plutil, find
  │     ├── analyze_signature(path)          # codesign, spctl, xcrun
  │     ├── analyze_binary(main_binary)      # otool, nm, lipo, strings
  │     │     ├── detect_packer_signatures() # bytes scan
  │     │     ├── _calculate_segment_entropy()# otool + python3
  │     │     ├── extract_strings_of_interest()# common/strings.py
  │     │     └── (nm symbols, lipo arches, otool sections...)
  │     └── detect_obfuscation(features)     # obfuscation_detector.py
  │
  └── run_react(features)                    # common/agent_modes.py
        │                                    # OR agent_loop_local.py / agent_loop_foundation.py
        ├── [tool call] get_xattr()
        ├── [tool call] get_signature_info()
        ├── [tool call] get_symbols()
        ├── [tool call] check_injection_triad()
        ├── [tool call] get_strings("LaunchAgent")
        ├── ...up to 15 tool calls...
        └── → JSON verdict
```
