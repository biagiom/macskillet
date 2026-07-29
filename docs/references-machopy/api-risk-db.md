# macOS API Symbol → Capability/Risk Mapping

## Risk Levels
- **CRITICAL**: Direct attack capability, almost never in legitimate apps
- **HIGH**: Powerful capability, legitimate but commonly abused
- **MEDIUM**: Normal in some app types; suspicious in others (check context)
- **LOW**: Common, note for context only

---

## Process Execution & Injection

| Symbol | Risk | Capability | Notes |
|--------|------|-----------|-------|
| `system` | HIGH | Execute shell command | Legitimate in CLI tools; suspicious in GUI apps |
| `popen` / `pclose` | HIGH | Execute shell + get output | Same as above |
| `posix_spawn` / `posix_spawnp` | MEDIUM | Spawn process | Common in legitimate apps |
| `fork` + `execve`/`execl`/`execlp` | HIGH | Fork+exec pattern | Launcher/dropper pattern |
| `NSTask` (via Obj-C symbols) | MEDIUM | Run subprocess | Common but worth noting |
| `mach_vm_allocate` | HIGH | Allocate VM in target process | Core of process injection |
| `mach_vm_write` | HIGH | Write to target process memory | Core of process injection |
| `mach_vm_protect` | HIGH | Change memory permissions | Often used to make injected code executable |
| `thread_create_running` | CRITICAL | Create thread in target process | Completes injection triad |
| `task_for_pid` | HIGH | Get task port for process | Required for inter-process manipulation |
| `processor_set_tasks` | CRITICAL | Get all task ports | Can access all processes |
| `ptrace` (via syscall or import) | HIGH | Process tracing / anti-debug | Used in anti-analysis |
| `mach_inject` (if present) | CRITICAL | Explicit injection library | No legitimate use in apps |

## Dynamic Loading

| Symbol | Risk | Capability | Notes |
|--------|------|-----------|-------|
| `dlopen` | MEDIUM | Load dynamic library at runtime | Legitimately used; suspicious if combined with dlsym + no visible API |
| `dlsym` | MEDIUM | Look up symbol in loaded library | Same as above |
| `NSBundle loadNibNamed` | LOW | Load nib/xib files | Normal UI apps |
| `objc_getClass` / `objc_msgSend` | LOW | ObjC runtime calls | Normal |
| `NSClassFromString` | MEDIUM | Dynamic class lookup by string | Can hide capabilities |
| `NSSelectorFromString` | MEDIUM | Dynamic selector by string | Can hide method calls |

## Filesystem Operations

| Symbol | Risk | Capability | Notes |
|--------|------|-----------|-------|
| `unlink` / `remove` | LOW | Delete files | Normal |
| `chmod` / `chown` | MEDIUM | Change permissions/ownership | Suspicious in non-admin apps |
| `chroot` | HIGH | Change root filesystem | Almost never in apps |
| `copyfile` / `clonefile` | LOW | Copy files | Normal |
| `kqueue` + `kevent` | LOW | File system events | Normal for file monitoring |
| `FSEventStreamCreate` | LOW | Monitor filesystem | Normal for backup/sync tools |

## Network

| Symbol | Risk | Capability | Notes |
|--------|------|-----------|-------|
| `CFSocketCreate` | MEDIUM | Raw socket | Lower-level than usual for apps |
| `socket` / `connect` / `bind` | MEDIUM | Network I/O | Note without accompanying URL |
| `NSURLSession` | LOW | HTTP networking | Very common, legitimate |
| `SecKeychainFind` + network symbols | HIGH | Credential theft pattern | Combination is suspicious |
| `getifaddrs` | LOW | Network interface enumeration | Note in context |

## Keychain & Credentials

| Symbol | Risk | Capability | Notes |
|--------|------|-----------|-------|
| `SecKeychainFindGenericPassword` | MEDIUM | Read keychain passwords | Legitimate in password managers; suspicious otherwise |
| `SecKeychainFindInternetPassword` | MEDIUM | Read internet passwords | Same as above |
| `SecKeychainItemCopyAttributesAndData` | HIGH | Dump keychain item | Likely credential theft |
| `SecKeychainSearchCreateFromAttributes` | HIGH | Search entire keychain | Credential harvesting |

## Anti-Analysis / Evasion

| Symbol | Risk | Capability | Notes |
|--------|------|-----------|-------|
| `ptrace` with PT_DENY_ATTACH | CRITICAL | Anti-debugging | Classic macOS anti-analysis |
| `sysctl` with CTL_KERN/KERN_PROC | HIGH | Check for debugger | Via process info check |
| `getppid` | MEDIUM | Check parent process | Often used to detect sandbox/analysis |
| `IOServiceGetMatchingService` with VM-detection names | HIGH | Anti-VM check | |
| `gettimeofday` in tight loops | MEDIUM | Timing-based anti-analysis | Hard to detect statically |

## Cryptography

| Symbol | Risk | Capability | Notes |
|--------|------|-----------|-------|
| `CCCrypt` / `CCKeyDerivationPBKDF` | MEDIUM | Symmetric encryption | Could be ransomware; check context |
| `SecKeyEncrypt` / `SecKeyDecrypt` | MEDIUM | Asymmetric crypto | Could be ransomware; check context |
| `CC_MD5` / `CC_SHA1` | LOW | Hashing | Common, normal |
| `RijndaelEncrypt` / `AES` strings | MEDIUM | AES encryption | Note in context |

## Kernel / Kext

| Symbol | Risk | Capability | Notes |
|--------|------|-----------|-------|
| `kmod_*` | CRITICAL | Kernel module operations | Should not appear in user-space apps |
| `IOKitLib` + kernel communication | HIGH | Direct kernel IPC | Only in system tools |
| `mach_port_allocate` | MEDIUM | Mach IPC | Low-level, note context |

## Persistence Mechanisms (via Strings, not Imports)

These appear as strings, not necessarily as imported symbols:

| String Pattern | Risk | Notes |
|----------------|------|-------|
| `LaunchAgents` path | HIGH | User-level persistence |
| `LaunchDaemons` path | CRITICAL | System-level persistence |
| `crontab` | HIGH | Cron-based persistence |
| `~/.bash_profile`, `~/.zshrc` | HIGH | Shell init hijacking |
| `login items` | MEDIUM | Login item persistence |
| `SMLoginItemSetEnabled` | MEDIUM | Programmatic login item |
