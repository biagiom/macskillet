#!/bin/bash
# quick_risk.sh — Zero-Python macOS app triage
# Usage: bash quick_risk.sh /path/to/App.app [/path/to/binary]
# Requires: macOS with codesign, spctl, otool, nm, strings, xattr, mdls (all built-in)

TARGET="${1:?Usage: $0 /path/to/App.app}"
BINARY="$2"

# Resolve main binary if not provided
if [ -z "$BINARY" ] && [ -d "$TARGET" ]; then
    EXEC_NAME=$(plutil -extract CFBundleExecutable raw "$TARGET/Contents/Info.plist" 2>/dev/null)
    BINARY="$TARGET/Contents/MacOS/$EXEC_NAME"
fi

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BOLD='\033[1m'
NC='\033[0m'

echo ""
echo "${BOLD}════════════════════════════════════════════════${NC}"
echo "${BOLD}  macOS App Triage: $(basename "$TARGET")${NC}"
echo "${BOLD}════════════════════════════════════════════════${NC}"

# ── 1. File type
echo ""
echo "${BOLD}[1] FILE TYPE${NC}"
file "$BINARY" 2>/dev/null || file "$TARGET"

# ── 2. Extended attributes
echo ""
echo "${BOLD}[2] EXTENDED ATTRIBUTES${NC}"
QATTR=$(xattr -p com.apple.quarantine "$TARGET" 2>/dev/null)
if [ -n "$QATTR" ]; then
    echo "  quarantine: $QATTR"
else
    echo "  ${RED}⚠ NO quarantine xattr — arrived without Gatekeeper check${NC}"
fi
ORIGIN=$(xattr -p "com.apple.metadata:kMDItemWhereFroms" "$TARGET" 2>/dev/null)
[ -n "$ORIGIN" ] && echo "  download origin: $ORIGIN"

# ── 3. Signature
echo ""
echo "${BOLD}[3] CODE SIGNATURE${NC}"
SIG_VERIFY=$(codesign --verify --verbose=4 "$TARGET" 2>&1)
if echo "$SIG_VERIFY" | grep -q "valid on disk"; then
    echo "  ${GREEN}✓ Signature valid${NC}"
else
    echo "  ${RED}✗ Signature invalid or missing${NC}"
    echo "  $SIG_VERIFY" | head -5
fi
codesign -d --verbose=4 "$TARGET" 2>&1 | grep -E "^(Identifier|TeamIdentifier|Authority|flags)=" | \
    sed 's/^/  /'

# ── 4. Gatekeeper
echo ""
echo "${BOLD}[4] GATEKEEPER${NC}"
SPCTL=$(spctl --assess --verbose=4 "$TARGET" 2>&1)
if echo "$SPCTL" | grep -q "accepted"; then
    SRC=$(echo "$SPCTL" | grep "source=" | head -1)
    echo "  ${GREEN}✓ $SRC${NC}"
else
    echo "  ${RED}✗ REJECTED: $SPCTL${NC}"
fi

# ── 5. Notarization staple
echo ""
echo "${BOLD}[5] NOTARIZATION STAPLE${NC}"
STAPLE=$(xcrun stapler validate "$TARGET" 2>&1)
if echo "$STAPLE" | grep -qi "worked"; then
    echo "  ${GREEN}✓ Notarization ticket stapled${NC}"
else
    echo "  ${YELLOW}⚠ Not stapled (may require network check)${NC}"
fi

# ── 6. Entitlements
echo ""
echo "${BOLD}[6] ENTITLEMENTS${NC}"
ENTS=$(codesign -d --entitlements :- "$TARGET" 2>/dev/null)
if [ -n "$ENTS" ]; then
    echo "$ENTS" | grep -E "key|true|false" | head -20 | sed 's/^/  /'
    # Flag dangerous ones
    echo "$ENTS" | grep -E "private|get-task-allow|disable-library|system-task-ports" | \
        sed "s/^/  ${RED}⚠ HIGH-RISK: /" | sed "s/$/${NC}/"
else
    echo "  (none)"
fi

# ── 7. Architectures
echo ""
echo "${BOLD}[7] ARCHITECTURES${NC}"
[ -f "$BINARY" ] && lipo -info "$BINARY" 2>/dev/null | sed 's/^/  /'

# ── 8. Dylib dependencies
echo ""
echo "${BOLD}[8] DYNAMIC LIBRARIES${NC}"
if [ -f "$BINARY" ]; then
    otool -L "$BINARY" 2>/dev/null | tail -n +2 | while read line; do
        DYLIB_PATH=$(echo "$line" | awk '{print $1}')
        if echo "$DYLIB_PATH" | grep -qE "^/tmp/|^/var/folders/|inject|hook"; then
            echo "  ${RED}⚠ $DYLIB_PATH${NC}"
        elif echo "$DYLIB_PATH" | grep -qE "^/usr/lib|^/System|@executable_path|@loader_path"; then
            echo "  ${GREEN}  $DYLIB_PATH${NC}"
        else
            echo "  ${YELLOW}? $DYLIB_PATH${NC}"
        fi
    done
fi

# ── 9. High-risk symbols
echo ""
echo "${BOLD}[9] HIGH-RISK SYMBOLS${NC}"
if [ -f "$BINARY" ]; then
    RISKY=$(nm -u "$BINARY" 2>/dev/null | grep -E \
        "mach_vm_allocate|mach_vm_write|mach_vm_protect|thread_create_running|\
task_for_pid|processor_set_tasks|_ptrace|\
_dlopen|_dlsym|_system$|_popen|\
SecKeychainFind|SecKeychainSearch|SecKeychainItemCopy|\
_CCCrypt|NSClassFromString|NSSelectorFromString")
    if [ -n "$RISKY" ]; then
        echo "$RISKY" | sed "s/^/  ${RED}⚠ /" | sed "s/$/${NC}/"
    else
        echo "  ${GREEN}None found${NC}"
    fi
fi

# ── 10. Injection triad
echo ""
echo "${BOLD}[10] INJECTION TRIAD CHECK${NC}"
if [ -f "$BINARY" ]; then
    SYM_OUT=$(nm -u "$BINARY" 2>/dev/null)
    ALLOC=$(echo "$SYM_OUT" | grep -c "mach_vm_allocate")
    WRITE=$(echo "$SYM_OUT" | grep -c "mach_vm_write")
    THREAD=$(echo "$SYM_OUT" | grep -c "thread_create_running")
    COUNT=$((ALLOC + WRITE + THREAD))
    echo "  mach_vm_allocate: $([ $ALLOC -gt 0 ] && echo "${RED}YES${NC}" || echo "${GREEN}no${NC}")"
    echo "  mach_vm_write:    $([ $WRITE -gt 0 ] && echo "${RED}YES${NC}" || echo "${GREEN}no${NC}")"
    echo "  thread_create_running: $([ $THREAD -gt 0 ] && echo "${RED}YES${NC}" || echo "${GREEN}no${NC}")"
    [ $COUNT -eq 3 ] && echo "  ${RED}${BOLD}⚠⚠ COMPLETE INJECTION TRIAD DETECTED ⚠⚠${NC}"
fi

# ── 11. ObjC classes
echo ""
echo "${BOLD}[11] OBJC CLASSES (suspicious)${NC}"
if [ -f "$BINARY" ]; then
    otool -s __DATA __objc_classname "$BINARY" 2>/dev/null | strings | \
        grep -iE "inject|hook|swizzle|steal|keylog|screen|exfil" | \
        sed "s/^/  ${YELLOW}⚠ /" | sed "s/$/${NC}/" || echo "  (none suspicious)"
fi

# ── 12. Suspicious strings
echo ""
echo "${BOLD}[12] SUSPICIOUS STRINGS${NC}"
if [ -f "$BINARY" ]; then
    strings "$BINARY" 2>/dev/null | grep -iE \
        "https?://[a-z0-9.-]+\.[a-z]{2,}|/tmp/[a-z]|LaunchAgent|LaunchDaemon|\
osascript|chmod.*\+x|curl.*bash|wget.*sh|VMware|VirtualBox|inject" | \
        head -20 | sed "s/^/  ${YELLOW}/" | sed "s/$/${NC}/"
fi

# ── 13. Bundle structure anomalies
echo ""
echo "${BOLD}[13] BUNDLE ANOMALIES${NC}"
[ -d "$TARGET/Contents/Library/LaunchAgents" ] && \
    echo "  ${RED}⚠ Contains LaunchAgents directory (persistence)${NC}"
[ -d "$TARGET/Contents/Library/LaunchDaemons" ] && \
    echo "  ${RED}⚠ Contains LaunchDaemons directory (persistence)${NC}"
[ -d "$TARGET/Contents/Library/LoginItems" ] && \
    echo "  ${YELLOW}⚠ Contains LoginItems directory${NC}"
HIDDEN=$(find "$TARGET" -name ".*" -type f 2>/dev/null | head -5)
[ -n "$HIDDEN" ] && echo "  ${YELLOW}⚠ Hidden files: $HIDDEN${NC}"
SCRIPTS=$(find "$TARGET" -name "*.sh" -o -name "*.py" -o -name "*.rb" 2>/dev/null | head -5)
[ -n "$SCRIPTS" ] && echo "  ${YELLOW}⚠ Embedded scripts: $SCRIPTS${NC}"

echo ""
echo "${BOLD}════════════════════════════════════════════════${NC}"
echo "  Triage complete. Run 'macskillet' for AI verdict."
echo "${BOLD}════════════════════════════════════════════════${NC}"
echo ""
