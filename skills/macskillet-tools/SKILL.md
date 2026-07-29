---
name: macskillet-tools
description: Use when deciding which macskillet agent tools to call next, what order to call them, or what data each of the 13 tools returns during a ReAct analysis loop.
---

# MacSkillet — Agent Tools Reference

## Recommended Call Order

The system prompt specifies this order — follow it unless a specific signal warrants jumping ahead:

| # | Tool | Key output | Why first |
|---|------|------------|-----------|
| 1 | `get_xattr` | quarantine flag, download URL | Missing = Gatekeeper bypassed |
| 2 | `get_signature_info` | signing status, team ID, notarization | Sets trust baseline |
| 3 | `get_entitlements` | entitlement keys with risk labels | Private entitlements = high concern |
| 4 | `get_bundle_info` | LSUIElement, persistence dirs, scripts | Bundle structure tells intent |
| 5 | `get_dylibs` | dylib paths with risk flags | /tmp/ or ~/home loads = red flag |
| 6 | `get_symbols` | imports/exports, pre-flagged high-risk | Capability fingerprint |
| 7 | `check_injection_triad` | triad present/absent | Single strongest binary indicator |
| 8 | `get_objc_info` | class + method names | Often unstripped — reveals behavior directly |
| 9 | `get_segment_entropy` | per-segment entropy values | __TEXT > 7.5 = packed |
| 10 | `get_strings` | strings matching `pattern` arg | Targeted search for C2, /tmp/, shell |
| 11 | `get_lipo_info` | arch list for FAT/Universal | Context for multi-arch samples |
| 12 | `get_load_commands` | full Mach-O load command list | LC_ENCRYPTION_INFO, unusual loaders |
| 13 | `lookup_api_risk` | risk level for a symbol | Clarify an individual import |

## Tool Args

Most tools take no args. Exceptions:
- `get_strings` — **required**: `pattern` (regex or substring)
- `lookup_api_risk` — **required**: `symbol` (e.g. `"mach_vm_write"`)
- `get_symbols` — optional: `filter` (regex to narrow output)

## High-Value Findings

| Tool | Signal to watch for |
|------|---------------------|
| `get_xattr` | No quarantine on binary in /tmp/ = `xattr -c` was run (ClickFix pattern) |
| `check_injection_triad` | All 3 present → MALICIOUS override regardless of total score |
| `get_objc_info` | Class names like `PasswordHarvester`, `KeylogManager`, `C2Client` |
| `get_segment_entropy` | __TEXT > 7.0 suspicious, > 7.5 packed |
| `get_strings` | Patterns: `base64 -d`, `curl.*bash`, `/tmp/helper`, `receiveex.php` |

## Error Handling

Tools never raise exceptions. On failure: `{"error": "..."}`. Treat as missing data, not verdict.

## Hierarchical Triage

Stage 1 uses only: `get_xattr`, `get_signature_info`, `get_segment_entropy`.
