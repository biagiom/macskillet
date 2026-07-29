# Native macOS Tool Cheatsheet for App Analysis

## codesign — Code Signing Tool

```bash
# Verify signature integrity
codesign --verify --verbose=4 /path/to/App.app

# Full display: identity, team, flags, authorities
codesign -d --verbose=4 /path/to/App.app 2>&1

# Entitlements as raw plist XML
codesign -d --entitlements :- /path/to/App.app 2>/dev/null

# Entitlements to a file
codesign -d --entitlements /tmp/ents.plist /path/to/App.app 2>/dev/null

# Extract DER certificates
codesign -d --extract-certificates /tmp/certs/ /path/to/App.app 2>/dev/null
# → /tmp/certs/codesign0 (leaf), codesign1 (intermediate), codesign2 (root)

# Check hardened runtime (look for "runtime" flag)
codesign -d --verbose=4 /path/to/binary 2>&1 | grep flags

# Verify with designated requirement
codesign --verify --verbose=4 -R="anchor apple" /path/to/binary 2>&1

# Remove signature (for testing, NOT on live evidence)
codesign --remove-signature /path/to/binary
```

**Signing status interpretation:**
- `valid on disk` + `satisfies its Designated Requirement` → intact signature
- `code object is not signed at all` → unsigned
- `object is a Mach-O file, but an embedded signature is missing/invalid` → tampered
- `a sealed resource is missing or invalid` → bundle contents modified after signing

---

## spctl — Gatekeeper Policy Tool

```bash
# Full Gatekeeper assessment
spctl --assess --verbose=4 --type exec /path/to/App.app 2>&1

# Raw XML plist output
spctl --assess --verbose=4 --type exec --raw /path/to/App.app 2>&1

# Check globally enabled/disabled state
spctl --status
```

**Verdict strings:**
- `accepted source=Notarized Developer ID` → fully trusted, Apple-verified
- `accepted source=Developer ID` → signed, not notarized
- `accepted source=Apple` → Apple-distributed binary
- `rejected source=no usable signature` → unsigned
- `rejected` → Gatekeeper would block

**Note:** From macOS Sequoia 15+, spctl can no longer modify Gatekeeper config.

---

## otool — Object File Display Tool

```bash
# Mach-O header
otool -h /path/to/binary

# All load commands (most comprehensive)
otool -l /path/to/binary

# Dynamic library dependencies
otool -L /path/to/binary

# Segment/section info (from load commands)
otool -l /path/to/binary | grep -E "segname|sectname|vmaddr|fileoff|filesize|size"

# Disassemble __TEXT __text section
otool -V -t /path/to/binary

# Hexdump __DATA __data section
otool -v -d /path/to/binary

# ObjC class structures (very useful for revealing behavior)
otool -ov /path/to/binary

# ObjC class names only
otool -s __DATA __objc_classname /path/to/binary 2>/dev/null | strings

# ObjC method names only
otool -s __TEXT __objc_methnames /path/to/binary 2>/dev/null | strings

# ObjC protocols
otool -s __DATA __objc_protoname /path/to/binary 2>/dev/null | strings

# Chained fixups / bind opcodes
otool -l /path/to/binary | grep -A10 "LC_DYLD_CHAINED_FIXUPS\|LC_DYLD_INFO_ONLY"

# Check for encryption (App Store DRM / obfuscation)
otool -l /path/to/binary | grep -A6 "LC_ENCRYPTION_INFO"
# cryptid=1 → encrypted; cryptid=0 → not encrypted

# Entry point
otool -l /path/to/binary | grep -A5 "LC_MAIN\|LC_UNIXTHREAD"

# Rpath entries (dylib search paths — check for suspicious ones)
otool -l /path/to/binary | grep -A3 "LC_RPATH"

# Specific architecture in FAT binary
otool -arch arm64 -L /path/to/universal_binary
otool -arch x86_64 -h /path/to/universal_binary
```

---

## nm — Symbol Table

```bash
# All symbols
nm /path/to/binary

# Undefined (imported) symbols only
nm -u /path/to/binary

# Defined (exported) external symbols
nm -g /path/to/binary

# With demangling (C++)
nm -u /path/to/binary | c++filt

# Only defined symbols (skip undefined)
nm -U /path/to/binary

# Sort by address
nm -n /path/to/binary

# Specific arch in FAT
nm -arch arm64 /path/to/binary

# High-risk symbol grep (copy-paste ready)
nm -u /path/to/binary | grep -E \
  "mach_vm_allocate|mach_vm_write|mach_vm_protect|thread_create_running|\
task_for_pid|processor_set_tasks|ptrace|\
dlopen|dlsym|NSClassFromString|NSSelectorFromString|\
system$|popen|posix_spawn|fork|execve|\
SecKeychain|SecKeychainFind|SecKeychainSearch|\
CCCrypt|CCKeyDerivation|\
kmod_|IOService"
```

---

## lipo — FAT/Universal Binary Tool

```bash
# Architectures present
lipo -info /path/to/binary

# Detailed FAT header
lipo -detailed_info /path/to/binary

# Extract single arch slice
lipo -extract arm64 /path/to/binary -output /tmp/binary.arm64
lipo -extract x86_64 /path/to/binary -output /tmp/binary.x86_64

# Thin a FAT binary (analyze individually)
lipo -thin arm64 /path/to/binary -output /tmp/thin.arm64
```

---

## strings — String Extraction

```bash
# All strings ≥4 chars (default)
strings /path/to/binary

# Minimum length 8 (reduces noise)
strings -n 8 /path/to/binary

# UTF-16 little-endian (Swift strings, many modern apps)
strings -encoding l /path/to/binary

# UTF-16 big-endian
strings -encoding b /path/to/binary

# All encodings combined
for enc in s S b l B L; do
    strings -encoding $enc /path/to/binary
done | sort -u

# Targeted malware indicator grep
strings /path/to/binary | grep -iE \
  "https?://[a-z0-9.-]+\.[a-z]{2,}|\
/tmp/[a-zA-Z]|\
LaunchAgent|LaunchDaemon|\
osascript|applescript|\
chmod 7|chmod \+x|\
curl.*bash|wget.*bash|\
VMware|VirtualBox|Parallels|sandbox|\
inject|hooking|dylib|\
keychain|password|credential"
```

---

## xattr — Extended Attributes

```bash
# List all extended attributes and their values
xattr -l /path/to/App.app

# Check quarantine (most important)
xattr -p com.apple.quarantine /path/to/App.app 2>/dev/null
# Format: flags;hex_timestamp;agent_name;UUID
# flags: 0001=quarantined, 0002=first launch, 0081=downloaded from internet

# Download origin URLs
xattr -p "com.apple.metadata:kMDItemWhereFroms" /path/to/App.app 2>/dev/null

# Check provenance (Ventura+)
xattr -p com.apple.provenance /path/to/App.app 2>/dev/null

# Recursive check on bundle
xattr -r -l /path/to/App.app 2>/dev/null | head -50
```

**Risk signals from xattr:**
- `com.apple.quarantine` absent → arrived via USB/script/automation (Gatekeeper bypassed)
- quarantine flags `0000` → Gatekeeper check cleared or manually bypassed
- `kMDItemWhereFroms` contains suspicious domain → phishing/malicious distribution site

---

## mdls — Spotlight Metadata

```bash
# All metadata
mdls /path/to/App.app

# Specific fields
mdls -name kMDItemWhereFroms /path/to/App.app     # download URLs
mdls -name kMDItemDownloadedDate /path/to/App.app  # when downloaded
mdls -name kMDItemContentType /path/to/App.app     # content type
mdls -name kMDItemFSCreationDate /path/to/App.app  # file creation
mdls -name kMDItemFSContentChangeDate /path/to/App.app  # last modified

# Raw output for scripting
mdls -raw -name kMDItemWhereFroms /path/to/App.app
```

---

## plutil — Property List Tool

```bash
# Pretty-print plist
plutil -p /path/to/Info.plist

# Convert to JSON
plutil -convert json -o - /path/to/Info.plist

# Convert to XML
plutil -convert xml1 -o - /path/to/binary.plist

# Extract single key (great for scripting)
plutil -extract CFBundleIdentifier raw /path/to/Info.plist
plutil -extract LSUIElement raw /path/to/Info.plist 2>/dev/null
```

---

## security — Keychain & Certificate Tool

```bash
# Decode CMS signature blob
security cms -D -i /path/to/App.app/Contents/_CodeSignature/CodeSignature

# Verify a certificate
security verify-cert -c codesign0 -p ssl

# Display certificate details
security find-certificate -p -c "Developer ID" /tmp/certs/codesign0

# Check if cert is trusted
openssl x509 -inform der -in codesign0 -text -noout
```

---

## xcrun — Xcode Tool Runner

```bash
# Validate notarization staple (offline check)
xcrun stapler validate /path/to/App.app
# "The validate action worked!" = stapled ticket present

# Notarize submission (for devs, not analysis)
# xcrun notarytool submit ...

# Other useful xcrun tools
xcrun dwarfdump --uuid /path/to/binary    # Extract UUIDs
xcrun dwarfdump --all /path/to/binary     # Full DWARF debug info
```

---

## Quick One-Liner Triage

```bash
# 5-second triage: the three most important signals
TARGET="/path/to/App.app"
BINARY="$TARGET/Contents/MacOS/$(plutil -extract CFBundleExecutable raw "$TARGET/Contents/Info.plist" 2>/dev/null)"
echo "--- Signature ---" && codesign --verify -v "$TARGET" 2>&1 | tail -2
echo "--- Gatekeeper ---" && spctl --assess -v "$TARGET" 2>&1
echo "--- Dangerous Symbols ---" && nm -u "$BINARY" 2>/dev/null | grep -E "mach_vm|task_for_pid|dlopen|system$|SecKeychain"
```
