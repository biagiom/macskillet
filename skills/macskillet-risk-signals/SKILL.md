---
name: macskillet-risk-signals
description: Use when computing a macskillet risk score, interpreting signal weights, or determining the correct verdict and confidence level from cumulative evidence.
---

# MacSkillet — Risk Signals & Scoring

## Verdict Thresholds

| Score | Verdict | Confidence |
|-------|---------|-----------|
| ≤ 2 | BENIGN | HIGH |
| 3–5 | BENIGN | MEDIUM |
| 6–8 | SUSPICIOUS | LOW–MEDIUM |
| 9–12 | SUSPICIOUS | HIGH |
| 13–17 | MALICIOUS | MEDIUM |
| ≥ 18 | MALICIOUS | HIGH |

**Override:** injection triad (mach_vm_allocate + mach_vm_write + thread_create_running) all present → MALICIOUS regardless of total score.

## Signals by Category

### Code Signature
| Signal | Score |
|--------|-------|
| Apple-signed binary | -2 |
| Developer ID + notarized | -1 |
| Ad-hoc signature | +3 |
| No signature | +4 |
| Invalid/broken signature | +5 |
| Revoked certificate | +5 |
| Bundle ID / identity mismatch | +4 |

**"Notarized ≠ safe" override (signature_trust):** A Developer-ID-signed/notarized sample that ALSO shows ClickFix-style delivery, Script-Editor, or exfil behavior is NOT trusted. The `signature_trust` assessment (in `get_signature_info` → `trust_assessment`) revokes the normal trust credit and applies **+3** instead. 2025–2026 stealers (MacSync, Odyssey, BlueNoroff Hidden Risk) ship clean-at-scan-time notarized apps that fetch the payload post-Gatekeeper; certs are revoked only afterward. When `trust_assessment.credit_revoked = true`, use `risk_adjustment` (+3), not the −1/−2 credit.

### Bundle Structure
| Signal | Score |
|--------|-------|
| LSUIElement + no signature | +4 |
| LaunchAgents dir in bundle | +3 |
| LaunchDaemons dir in bundle | +4 |
| Embedded scripts (.sh/.py) in Resources | +2 |
| Executable outside Contents/MacOS/ | +3 |

### API Imports
| Signal | Score |
|--------|-------|
| Injection triad (all 3) | +5 |
| task_for_pid | +3 |
| ptrace | +3 |
| system() / popen() | +2 |
| dlopen + dlsym with no visible high-level API | +3 |
| No imports at all | +3 |
| kext loading APIs | +4 |

### Segment Entropy
| Condition | Score |
|-----------|-------|
| __TEXT > 7.0 | +3 |
| __TEXT > 7.5 | +4 |
| Any segment = 8.0 (max) | +4 |

### Dylibs
| Signal | Score |
|--------|-------|
| Load from /tmp/ | +5 |
| Load from ~/home (unusual) | +3 |
| Dylib name: inject/hook/patch/swizzle | +3 |

### Strings
| Pattern | Score |
|---------|-------|
| `base64 -d \| bash` or `curl \| zsh` | +4 |
| /tmp/ + executable path | +3 |
| Keychain strings + network strings together | +3 |
| Anti-VM strings (VMware, VirtualBox, sandbox) | +3 |
| LaunchAgents/Daemons path in strings | +2 |
| Hard-coded IP address | +2 |
| `applescript://` URL scheme / `do shell script` (Script-Editor delivery) | +4 |
| Decode chain: `openssl enc -d`, `xxd -p -r`, `base64 -d` | +3 |
| Shell-config persistence: `~/.zshenv` (alert-evasive) / `~/.zshrc` / `~/.bash_profile` | +3 |
| TCC abuse: `tccutil reset` / direct `TCC.db` access | +4 |
| Dev/cloud secret theft: `.ssh/id_rsa`, `.aws/credentials`, `.npmrc`, `.docker/config.json`, `kubeconfig`, `.config/gcloud`, Terraform state | +3 |
| Legitimate-cloud C2/exfil: `*.vercel.app`, `*.pages.dev`, `dropboxapi.com`, `api.telegram.org` | +3 |
| Process masquerade: `exec -a` (mdworker/distnoted) | +3 |
| Anti-analysis fingerprint: `hw.optional.arm.FEAT_`, `ioreg`, `system_profiler` | +3 |
| Crypto-wallet trojanizing: `Ledger Live` app.asar | +3 |

### Entitlements
| Signal | Score |
|--------|-------|
| com.apple.system-task-ports | +5 |
| com.apple.private.* | +4 |
| Entitlements present + invalid signature | +4 |
| get-task-allow in release build | +3 |
| cs.disable-library-validation | +2 |
| cs.allow-unsigned-executable-memory | +2 |
| Sandboxed (app-sandbox = true) | -1 |

## Correlation Rules

- Multiple MEDIUM signals outweigh a single HIGH signal
- `clickfix_detection.clickfix_suspected = true` + no quarantine → escalate to MALICIOUS if score ≥ 9
- `obfuscation_detection.packing_suspected = true` + no signature → add +3 to score
- `signature_trust.override_applied = true` → drop the signing trust credit; apply `signature_trust.adjustment` (+3) instead
- **Non-persistent ≠ benign:** most 2025–2026 macOS infostealers are smash-and-grab with no persistence. Weight delivery (ClickFix/`applescript://`) + exfil-target signals as heavily as persistence — absence of a LaunchAgent is not exculpatory.

> **Calibration note (provisional weights):** the new 2026 enrichment signals add cumulative score; the thresholds above predate them and are NOT yet recalibrated against a labeled set. Expect to re-fit the BENIGN/SUSPICIOUS/MALICIOUS bands once the eval harness exists (see project ADR-2). Benign-regression tests guard known-clean samples in the interim.
