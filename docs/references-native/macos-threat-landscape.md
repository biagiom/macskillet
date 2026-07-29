# macOS Threat Landscape (2026 vendor-blog synthesis)

Reference distilled from a systematic survey of macOS security-vendor research
(SentinelOne/Phil Stokes, Moonlock Lab, Objective-See/Wardle, Jamf Threat Labs,
Microsoft, CrowdStrike, Elastic, Volexity, Bitdefender, Huntress — 44 verified
primary sources). It grounds the agent's reasoning in concrete techniques,
on-disk locations, and capabilities.

**Conventions**
- Techniques are named, not tagged with MITRE IDs (vendor posts rarely print IDs;
  inferred IDs were unreliable). Use names.
- This file carries **patterns**, not literal IOCs. Specific hashes/IPs/domains
  rot quickly and are kept out of detection logic by design; verify and store any
  literal IOCs separately (dated, optional) after citation verification.

---

## 1. Delivery / initial access (dominant 2025–2026)

| Vector | What to look for |
|---|---|
| **ClickFix (Terminal)** | fake CAPTCHA / "fix your Mac" page → user pastes `base64 -d \| bash` / `curl \| zsh` |
| **ClickFix (Script Editor)** | `applescript://` URL scheme → Script Editor pre-filled with `do shell script`; evades macOS Tahoe 26.4 Terminal paste-scanning |
| **Deceptive `.dmg`** | background-image / filename "drag to Terminal" / "right-click Open" to bypass Gatekeeper socially; attackers prefer `.dmg` over `.pkg` |
| **Fake job / recruitment** | DPRK "Contagious Interview": trojanized coding task, VS Code `tasks.json` abuse, fake camera/mic-fix app |
| **Supply chain** | Xcode `.pbxproj` injection + Git pre-commit hooks (XCSSET); trojanized dev tools; re-signed + re-notarized installers (3CX) |
| **Malvertising / SEO poisoning** | spoofed GitHub repos, fake "Mac help" sites, cracked apps |

## 2. Persistence taxonomy (on-disk locations)

| Mechanism | Indicator | Technique name |
|---|---|---|
| LaunchAgent (user) | `~/Library/LaunchAgents/*.plist`, `RunAtLoad=true` | Launch agent |
| LaunchDaemon (root) | `/Library/LaunchDaemons/*.plist` | Launch daemon |
| Apple/Google-mimic labels | `com.apple.softwareupdate.plist`, `com.google.keystone.agent.plist`, `com.apple.fsevents.plist` | Masquerading |
| **Shell-config (evasive)** | `~/.zshenv` (avoids macOS 13+ bg-item alert), `~/.zshrc`, `~/.zshrc_aliases`, `~/.bash_profile` | Shell-profile persistence |
| Login items / BTM | `~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm` | Background task mgmt |
| Git hooks | `.git/hooks/pre-commit` | Event-triggered |
| Dylib hijack / proxy / insert | anomalous dylib in `*.framework/.../Libraries/`, `DYLD_INSERT_LIBRARIES` | Dylib hijacking |
| Cron / periodic / login hooks | crontab, `/etc/periodic`, loginhooks | Scheduled task |
| Legacy: emond, Folder Actions, Mail Rules | `/private/var/db/emondClients`, `SyncedRules.plist` | Event-triggered |

> **Counter-trend:** most 2025–2026 infostealers (AMOS, Poseidon, Cthulhu, Banshee)
> are **non-persistent** smash-and-grab. Absence of a LaunchAgent is **not**
> exculpatory — weight delivery + exfil signals as heavily as persistence.

## 3. Defense evasion

| Technique | Indicator |
|---|---|
| Quarantine removal | `xattr -c` / `xattr -d com.apple.quarantine` / `xattr -cr` + `chmod +x` |
| **Notarization abuse** | signed/notarized app clean at scan time, fetches payload post-Gatekeeper; cert revoked later — "notarized ≠ safe" |
| TCC abuse | `tccutil reset` to re-prompt; direct `TCC.db` access; AppleScript fake password dialogs (`dscl . authonly`) |
| Anti-VM / anti-analysis | `system_profiler SPHardwareDataType`, `sysctl`, `ioreg` serial/MAC-OUI; Activity-Monitor polling kill-switch; `hw.optional.arm.FEAT_*` Apple-Silicon gating |
| Obfuscation / packing | run-only AppleScript (`0xFADEDEAD`, `osadecompile` fails); UPX/MPRESS; base64/RC4/XOR layering; `xxd -p -r` + `base64 -d` + `openssl enc -d`; junk/dead-code padding |
| In-memory / fileless | `NSCreateObjectFileImageFromMemory` + `NSLinkModule`; `curl -kSsfL ... \| zsh` |
| Process masquerade | `exec -a mdworker_local` / `distnoted` — name vs path/signature mismatch |

## 4. Credential / data targets

Keychain (login/iCloud); browser creds & cookies (`Local State`, `Login Data`,
`key4.db`, `logins.json`); Apple Notes/iMessages; desktop crypto wallets (Exodus,
Electrum, **Ledger Live `app.asar` trojanizing**, Trezor); and increasingly
developer/cloud secrets: `.ssh/id_rsa`, `.aws/credentials`, `kubeconfig`,
`.npmrc`, `.docker/config.json`, `.config/gcloud`, Terraform state.

## 5. C2 patterns

HTTP POST base64; REST task-polling (`/api/tasks/`); persistent WebSocket +
keep-alive; **DNS TXT dead-drop resolver**; **legitimate-cloud C2** (Google Drive,
Dropbox API, `*.vercel.app`, `*.pages.dev`); Telegram-bot exfil; non-standard
ports.

## 6. Compiled-language indicators

| Language | Signal | Example families |
|---|---|---|
| Rust | large universal Mach-O to temp dir, C2 URL as argv | RustBucket, RustDoor |
| Go | Go-runtime strings; tiny backdoors with single-letter command tokens | FlexibleFerret, notnullOSX |
| Swift | notarized Swift Mach-O that network-fetches + shell-execs after launch | MacSync, Odyssey |
| Objective-C | runtime string-concatenated C2 URL; `NSRunLoop` beacon | ObjCShellz, AMOS |
| C | dylib injection via altered load commands; Khepri C2 | ZuRu-like |
| Nim/Zig | compile-time exec; whitespace/junk padding | NimDoor; Phoenix/ShadeStager |

## 7. Family quick-reference

**Infostealers:** AMOS/Atomic, Banshee, Cthulhu, Poseidon, SHub Reaper, Mac.c,
MacSync, notnullOSX, Odyssey, DigitStealer, SHAMOS, Phoenix, ShadeStager.
**Backdoors/APT (heavy DPRK/Chinese lineage):** RustBucket, ObjCShellz, NimDoor,
KANDYKORN, FlexibleFerret, RustDoor, GIMMICK, HZ RAT, LightSpy, ChillyHell.
**Supply chain:** XCSSET (Xcode worm), 3CX/SmoothOperator. **Dylib hijack:** ZuRu.

---

## 8. How MacSkillet covers this

| Landscape item | MacSkillet coverage |
|---|---|
| ClickFix Terminal + Script Editor | `clickfix_detector` (Chain A/B, `applescript://`, decode chains) |
| Notarization abuse ("notarized ≠ safe") | `signature_trust.assess_signature_trust` override → `get_signature_info.trust_assessment` |
| Run-only AppleScript | `obfuscation_detector.scan_runonly_applescript` (`0xFADEDEAD`) |
| Quarantine removal / provenance | `get_xattr` (`download_origin_urls`, `quarantine_bypassed`) |
| Shell-config persistence, TCC, dev-secrets, cloud-C2, masquerade | `clickfix_detector` string indicators |
| Packing / entropy / language runtime | `obfuscation_detector` |
| Injection triad, entitlements, dylibs, symbols | agent tools (`check_injection_triad`, `get_entitlements`, `get_dylibs`, `get_symbols`) |

**Notarization-revocation** (online OCSP) and a dedicated shell-config tool were
considered but not added: trust revocation is surfaced by `signature_trust`, and
shell-config references are already flagged by `clickfix_detector`. See the
session lit-search note (`projects/biagiom/macos-ai-skill/notes/active/`) for full
provenance and source caveats.
