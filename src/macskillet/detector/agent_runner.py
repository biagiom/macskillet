#!/usr/bin/env python3
"""
agent_runner.py — Agentic reasoning loop for macOS app classification.

Uses the Claude API with tool use to iteratively analyze extracted features
and produce a structured verdict with a full reasoning chain.

Usage:
    python agent_runner.py --features features.json
    python agent_runner.py --sample /path/to/App.app   # runs extraction first
"""

import argparse
import json
import os
import sys
from pathlib import Path

import anthropic

from macskillet import DEFAULT_CLAUDE_MODEL

from macskillet.detector.tool_dispatcher import TOOLS, dispatch_tool
from macskillet.detector.feature_extractor import extract

# ---------------------------------------------------------------------------
# System prompt for the analyst agent
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are an expert macOS malware analyst performing static analysis on a macOS application.

Your goal is to classify the sample as MALICIOUS, SUSPICIOUS, or BENIGN, and provide a detailed,
step-by-step reasoning chain explaining your verdict.

## Your analysis approach

Work through the following areas **in order**, using tools to retrieve information:

1. **Signature & Trust**: Start by checking the code signature status. Is it signed? By whom?
   Is it notarized? Does the bundle ID match the signing identity?

2. **Bundle Structure**: If it's a .app bundle, check Info.plist flags: LSUIElement,
   LSBackgroundOnly, any persistence mechanisms (LaunchAgents, LaunchDaemons).

3. **Import Analysis**: Get all imports. Look for high-risk APIs. Specifically check:
   - The injection triad (mach_vm_allocate + mach_vm_write + thread_create_running)
   - Dynamic loading (dlopen + dlsym)
   - Shell execution (system, popen, posix_spawn + exec)
   - Keychain access
   For any suspicious symbol, use lookup_api_risk to confirm its risk level.

4. **Entitlements**: Check for private Apple entitlements, debug entitlements (get-task-allow),
   or overly broad permissions.

5. **Entropy**: Check segment entropy. High entropy in __TEXT (>7.0) suggests packing.

6. **Strings**: Search for suspicious patterns: C2 URLs, /tmp/ paths, shell commands,
   anti-VM strings, persistence-related paths.

7. **Cross-reference signals**: Combine findings. A single suspicious signal is weak;
   multiple corroborating signals is strong evidence.

## When to stop

Stop when you have enough evidence for a confident verdict. Don't call tools unnecessarily.
Aim for 5-10 tool calls for a typical sample; more for complex cases.

## Output format

When you have reached a verdict, output a JSON object (and ONLY this JSON, no surrounding text):

```json
{
  "verdict": "MALICIOUS | SUSPICIOUS | BENIGN",
  "confidence": "HIGH | MEDIUM | LOW",
  "risk_score": <integer>,
  "recommendation": "BLOCK | INVESTIGATE | ALLOW",
  "summary": "<2-4 sentence human-readable summary>",
  "key_indicators": ["<top signal 1>", "<top signal 2>", ...],
  "reasoning_chain": [
    {"step": 1, "observation": "...", "inference": "...", "risk_delta": <int>},
    ...
  ]
}
```
"""


# ---------------------------------------------------------------------------
# Agent loop
# ---------------------------------------------------------------------------

def run_agent(features: dict, model: str = DEFAULT_CLAUDE_MODEL, max_turns: int = 15) -> dict:
    """
    Run the agentic reasoning loop.
    Returns the structured classification result.
    """
    client = anthropic.Anthropic()  # uses ANTHROPIC_API_KEY env var

    # Build initial user message with a compact feature summary
    sample = features.get("sample", {})
    sig = features.get("signature", {})
    bundle = features.get("bundle", {})

    initial_message = f"""Please analyze this macOS sample:

**Sample:** {sample.get('name', 'unknown')}
**Type:** {sample.get('type', 'unknown')}
**SHA256:** {sample.get('sha256', 'N/A')}
**Size:** {sample.get('filesize_bytes', 'N/A')} bytes

**Quick context:**
- Code signature: {sig.get('signing_status', 'unknown') if sig else 'not extracted'}
- Bundle ID: {bundle.get('bundle_id', 'N/A') if bundle else 'N/A'}
- LSUIElement: {bundle.get('lsui_element', 'N/A') if bundle else 'N/A'}
- String indicators found: {len(features.get('strings_of_interest', []))}

Begin your analysis. Use tools to gather detailed information, then provide your verdict as JSON.
"""

    messages = [{"role": "user", "content": initial_message}]
    reasoning_turns = []

    print(f"[agent] Starting analysis: {sample.get('name', 'unknown')}", file=sys.stderr)

    for turn in range(max_turns):
        response = client.messages.create(
            model=model,
            max_tokens=4096,
            system=SYSTEM_PROMPT,
            tools=TOOLS,
            messages=messages,
        )

        # Collect text from this turn
        turn_text = ""
        tool_calls = []
        tool_results = []

        for block in response.content:
            if block.type == "text":
                turn_text += block.text
            elif block.type == "tool_use":
                tool_calls.append(block)

        print(f"[agent] Turn {turn+1}: stop_reason={response.stop_reason}, tools={[t.name for t in tool_calls]}", file=sys.stderr)

        # If no tool calls and model stopped, we're done
        if response.stop_reason == "end_turn" and not tool_calls:
            # Extract JSON verdict from final text
            break

        # If end_turn with tool_calls (shouldn't happen, but handle it)
        if response.stop_reason == "end_turn":
            break

        # Process tool calls
        tool_result_blocks = []
        for tc in tool_calls:
            print(f"[agent]   → {tc.name}({json.dumps(tc.input)})", file=sys.stderr)
            result = dispatch_tool(features, tc.name, tc.input)
            print(f"[agent]     ← {str(result)[:200]}", file=sys.stderr)
            tool_result_blocks.append({
                "type": "tool_result",
                "tool_use_id": tc.id,
                "content": json.dumps(result),
            })
            reasoning_turns.append({
                "tool": tc.name,
                "input": tc.input,
                "result": result,
            })

        # Add assistant turn and tool results to messages
        messages.append({"role": "assistant", "content": response.content})
        messages.append({"role": "user", "content": tool_result_blocks})

    # Extract the final JSON verdict from the last assistant message
    final_text = ""
    for msg in reversed(messages):
        if msg["role"] == "assistant":
            content = msg["content"]
            if isinstance(content, list):
                for block in content:
                    if hasattr(block, "text"):
                        final_text = block.text
                        break
                    elif isinstance(block, dict) and block.get("type") == "text":
                        final_text = block.get("text", "")
                        break
            elif isinstance(content, str):
                final_text = content
            if final_text:
                break

    # Parse JSON verdict
    verdict = _extract_json(final_text)
    if verdict is None:
        verdict = {
            "verdict": "SUSPICIOUS",
            "confidence": "LOW",
            "risk_score": 0,
            "recommendation": "INVESTIGATE",
            "summary": "Agent did not produce a parseable verdict. Manual review required.",
            "key_indicators": [],
            "reasoning_chain": [],
            "raw_output": final_text,
        }

    # Attach agent reasoning turns to verdict
    verdict["agent_tool_calls"] = reasoning_turns
    verdict["sample"] = features.get("sample", {})

    return verdict


def _extract_json(text: str) -> dict | None:
    """Extract the first JSON object from text."""
    if not text:
        return None
    # Try to find JSON block
    import re
    # Between ```json ... ``` or just raw {...}
    patterns = [
        r"```json\s*(\{.*?\})\s*```",
        r"```\s*(\{.*?\})\s*```",
        r"(\{[^{}]*\"verdict\"[^{}]*\})",
    ]
    for pattern in patterns:
        match = re.search(pattern, text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1))
            except json.JSONDecodeError:
                continue
    # Try parsing the whole text
    try:
        return json.loads(text.strip())
    except json.JSONDecodeError:
        return None


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Run agentic macOS malware classification")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--features", help="Path to pre-extracted features JSON")
    group.add_argument("--sample", help="Path to .app bundle or binary (extracts features first)")
    parser.add_argument("--output", help="Write report to this file")
    parser.add_argument("--model", default=DEFAULT_CLAUDE_MODEL, help="Claude model to use")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print output")
    args = parser.parse_args()

    if args.features:
        with open(args.features) as f:
            features = json.load(f)
    else:
        print(f"[*] Extracting features from: {args.sample}", file=sys.stderr)
        features = extract(args.sample)

    print("[*] Running agent classification loop...", file=sys.stderr)
    result = run_agent(features, model=args.model)

    output = json.dumps(result, indent=2 if args.pretty else None)
    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        print(f"[*] Report written to: {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
