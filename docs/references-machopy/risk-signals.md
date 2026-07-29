# Risk Signal Taxonomy & Scoring Rubric

## Scoring Tiers

| Score | Meaning |
|-------|---------|
| 0-2   | Benign — expected behavior |
| 3-5   | Low risk — worth noting but not alarming |
| 6-8   | Medium risk — investigate further |
| 9-12  | High risk — likely malicious |
| 13+   | Very high risk — almost certainly malicious |

---

## Signal Categories

### 1. Code Signature Signals

| Signal | Score | Notes |
|--------|-------|-------|
| Valid Apple-signed binary | -2 | Strong trust indicator |
| Valid Developer ID + notarized | -1 | Normal App Store/distribution |
| Valid Developer ID, not notarized | +1 | A bit concerning, needs investigation |
| Ad-hoc signature | +3 | No identity, often used in malware |
| No signature at all | +4 | High concern |
| Invalid/broken signature | +5 | Almost certainly tampered |
| Signature present but certificate revoked | +5 | Explicitly untrusted |
| Bundle ID / signing identity mismatch | +4 | Spoofing attempt |
| Developer ID claims Apple Team but not in Apple CT log | +5 | Forgery |

### 2. Bundle Structure Signals

| Signal | Score | Notes |
|--------|-------|-------|
| `LSUIElement = true` (no Dock icon) | +2 | Common in legitimate helpers AND malware |
| `LSBackgroundOnly = true` | +2 | Background-only, hidden from user |
| `LSUIElement` + no signature | +4 | Combine with sig check |
| Executable not in `Contents/MacOS/` | +3 | Non-standard placement |
| `Contents/Library/LaunchAgents/` present | +3 | Persistence mechanism |
| `Contents/Library/LaunchDaemons/` present | +4 | Elevated persistence |
| Login item registration | +2 | Persistence |
| Embedded scripting files (.sh, .py, .rb) in Resources | +2 | Payload staging |
| Hidden files (dot-prefix) in bundle | +3 | Concealment |
| Bundle modification timestamp mismatch | +2 | Signs of tampering |

### 3. Mach-O Header Signals

| Signal | Score | Notes |
|--------|-------|-------|
| `MH_EXECUTE` filetype | 0 | Normal executable |
| `MH_DYLIB` masquerading as executable | +4 | Format confusion |
| Missing `PIE` flag | +1 | Not position-independent (older or suspicious) |
| Unusual CPU type for distribution context | +2 | e.g. i386 in 2024 |
| `MH_NOUNDEFS` flag missing | +1 | Unresolved symbols |

### 4. Segment Entropy Signals

High entropy in code segments can indicate packing or obfuscation.

| Segment | Normal Range | Suspicious Range | Score |
|---------|-------------|-----------------|-------|
| `__TEXT` | 4.5 – 6.5 | > 7.0 | +3 |
| `__DATA` | 2.0 – 5.0 | > 7.0 | +2 |
| `__LINKEDIT` | 5.0 – 7.5 | > 7.8 | +2 |
| Any segment | any | = 8.0 (max) | +4 |

### 5. Import/API Signals

See `references/api-risk-db.md` for the full symbol mapping.

| Signal | Score | Notes |
|--------|-------|-------|
| `dlopen` + `dlsym` imports | +2 | Dynamic loading; hides capabilities |
| `dlopen`/`dlsym` + no visible high-level API | +3 | Definitely loading hidden code |
| `system()` / `popen()` import | +2 | Shell command execution |
| `posix_spawn` / `fork` + `exec*` | +2 | Process spawning |
| `ptrace` import | +3 | Anti-debugging common in malware |
| `task_for_pid` | +3 | Process injection vector |
| `mach_vm_allocate` + `mach_vm_write` + `thread_create_running` | +5 | Classic injection triad |
| `CCCrypt` / `SecKeychainFind` | +1 | Crypto/keychain (legitimate but note context) |
| `kext` loading APIs | +4 | Kernel extension loading |
| `IOKit` + private entitlements | +3 | Hardware-level access |
| `NSTask` / shell invocation classes | +2 | Can run commands |
| No imports at all | +3 | Statically linked or packed |

### 6. Dylib/Dependency Signals

| Signal | Score | Notes |
|--------|-------|-------|
| All dylibs from `/usr/lib/` or `/System/` | 0 | Normal system libraries |
| Dylib loaded from `@executable_path` | +1 | Normal for embedded frameworks |
| Dylib loaded from `/tmp/` or `/var/folders/` | +5 | Highly suspicious staging path |
| Dylib loaded from user home directory | +3 | Unusual for legitimate apps |
| Dylib with suspicious name (random chars, `inject`, `hook`) | +3 | |
| Weak-linked suspicious dylib | +2 | Loaded optionally, can hide deps |
| Dylib path doesn't exist on system | +2 | Missing dependency |

### 7. String Indicators

Run targeted string searches. Each match in suspicious context:

| Pattern | Score | Notes |
|---------|-------|-------|
| Hard-coded IP addresses | +2 | Possible C2 |
| URL with uncommon TLD + encoded path | +3 | C2 indicator |
| `/tmp/` + executable path | +3 | Staging to temp |
| Base64-encoded blob in strings | +2 | Payload encoding |
| Shell commands (`chmod 777`, `curl \| bash`) | +4 | Dropper behavior |
| Keychain-related strings + network strings together | +3 | Credential theft |
| Anti-VM strings (`VMware`, `VirtualBox`, `sandbox`) | +3 | Evasion attempt |
| `LaunchAgents` or `LaunchDaemons` path | +2 | Persistence strings |
| `osascript` | +2 | AppleScript automation abuse |
| References to other process names (e.g. browsers, keychain) | +2 | Targeting |

### 8. Entitlement Signals

| Signal | Score | Notes |
|--------|-------|-------|
| No entitlements | 0 | Normal for unsigned/simple tools |
| `com.apple.security.app-sandbox = true` | -1 | Sandboxed = constrained |
| `com.apple.private.*` entitlements | +4 | Private Apple entitlements; not for 3rd parties |
| `get-task-allow = true` in release app | +3 | Debug entitlement left in |
| `com.apple.system-task-ports` | +5 | Can access all processes |
| `com.apple.security.cs.disable-library-validation` | +2 | Can load arbitrary dylibs |
| `com.apple.security.cs.allow-unsigned-executable-memory` | +2 | JIT or injection |
| `com.apple.security.automation.apple-events` | +1 | Can automate other apps |
| Entitlements present but signature invalid | +4 | Entitlements are spoofed |

---

## Verdict Thresholds

| Total Score | Verdict | Confidence |
|-------------|---------|-----------|
| ≤ 2 | BENIGN | HIGH |
| 3–5 | BENIGN | MEDIUM (with caveats) |
| 6–8 | SUSPICIOUS | LOW–MEDIUM |
| 9–12 | SUSPICIOUS | HIGH |
| 13–17 | MALICIOUS | MEDIUM |
| ≥ 18 | MALICIOUS | HIGH |

**Note:** The agent should use these thresholds as a starting point, but can override based on
specific high-confidence indicators (e.g. a single `mach_vm_allocate + mach_vm_write + thread_create_running`
triad is strong enough on its own for MALICIOUS regardless of total score).
