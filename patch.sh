#!/usr/bin/env bash
# Usage: patch.sh [--dry-run] [--quiet] <binary>
# Exit codes: 0 patched, 3 no binary, 4 not found, 5 not writable, 6 already
# patched, 7 no licence key found, 8 only one half present, 9 write failed,
# 10 read-back mismatch.
set -uo pipefail

# Vendor key (license.rs: UnparsedPublicKey::new(&ED25519, vec![118, 10, ...]))
VENDOR_A=760ab623596f0b3c9a2fcd7f6be53768
VENDOR_B=48368d0e61db0204778f9c0a98d820c2

# Public half of the key pair in generate-license.sh
OUR_A=b45b434c0c2d0680ada62e2373a9ff49
OUR_B=674880e86afe047e06211d11b8a195ba

DRY_RUN=0
QUIET=0
BINARY_FILE=""

log() { [ "$QUIET" -eq 1 ] || printf '%s\n' "$*"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run)  DRY_RUN=1; shift ;;
        -q|--quiet) QUIET=1; shift ;;
        -h|--help)
            cat <<'EOF'
Usage: patch.sh [OPTIONS] <binary>

  --dry-run   report what would change and write nothing
  -q, --quiet suppress output
  -h, --help  show this help
EOF
            exit 0 ;;
        -*) echo "Error: unknown option '$1'" >&2; exit 1 ;;
        *)
            [ -z "$BINARY_FILE" ] || { echo "Error: more than one binary given." >&2; exit 1; }
            BINARY_FILE="$1"; shift ;;
    esac
done

for dep in tr grep dd xxd mktemp; do
    command -v "$dep" >/dev/null 2>&1 || { echo "Error: '$dep' is not installed." >&2; exit 2; }
done

[ -n "$BINARY_FILE" ] || { echo "Error: no binary given." >&2; exit 3; }
[ -f "$BINARY_FILE" ] || { echo "Error: '$BINARY_FILE' does not exist." >&2; exit 4; }
[ -w "$BINARY_FILE" ] || { echo "Error: no write permission for '$BINARY_FILE'." >&2; exit 5; }

TMP=$(mktemp) || exit 1
trap 'rm -f "$TMP"' EXIT

# Both halves contain 0x0a, so flatten first (0x0a -> 0x0d keeps offsets valid)
# and translate the needle the same way, then re-check every hit against the raw
# bytes - a real 0x0d would otherwise look like a translated 0x0a.
tr '\n' '\r' < "$BINARY_FILE" > "$TMP" || { echo "Error: cannot read '$BINARY_FILE'." >&2; exit 1; }

translate_0a() {
    local hex=$1 out="" i b
    for ((i = 0; i < ${#hex}; i += 2)); do
        b="${hex:i:2}"
        [ "$b" = "0a" ] && b="0d"
        out+="$b"
    done
    printf '%s' "$out"
}

hex_to_pcre() {
    local hex=$1 out="" i
    for ((i = 0; i < ${#hex}; i += 2)); do out+="\\x${hex:i:2}"; done
    printf '%s' "$out"
}

find_half() {
    local hex=$1 off raw
    LC_ALL=C grep -aboP "$(hex_to_pcre "$(translate_0a "$hex")")" "$TMP" 2>/dev/null |
    while IFS=: read -r off _; do
        [ -n "$off" ] || continue
        raw=$(dd if="$BINARY_FILE" bs=1 skip="$off" count=16 2>/dev/null | xxd -p -c 16)
        [ "$raw" = "$hex" ] && printf '%s\n' "$off"
    done
}

mapfile -t A_OFFS < <(find_half "$VENDOR_A")
mapfile -t B_OFFS < <(find_half "$VENDOR_B")
mapfile -t OURS_A < <(find_half "$OUR_A")
mapfile -t OURS_B < <(find_half "$OUR_B")

if [ "${#A_OFFS[@]}" -eq 0 ] && [ "${#B_OFFS[@]}" -eq 0 ]; then
    if [ "${#OURS_A[@]}" -ge 1 ] && [ "${#OURS_B[@]}" -ge 1 ]; then
        log "Already patched."
        exit 6
    fi
    echo "Error: no Stalwart licence public key found in '$BINARY_FILE'." >&2
    exit 7
fi
if [ "${#A_OFFS[@]}" -eq 0 ] || [ "${#B_OFFS[@]}" -eq 0 ]; then
    echo "Error: found only one of the two key halves" >&2
    echo "       (first: ${#A_OFFS[@]}, second: ${#B_OFFS[@]}); refusing to patch." >&2
    exit 8
fi

write_half() {
    local off=$1 hex=$2 got
    printf '%s' "$hex" | xxd -r -p | dd of="$BINARY_FILE" bs=1 seek="$off" conv=notrunc >/dev/null 2>&1 || {
        echo "Error: failed to write at offset 0x$(printf '%x' "$off")." >&2; exit 9; }
    got=$(dd if="$BINARY_FILE" bs=1 skip="$off" count=16 2>/dev/null | xxd -p -c 16)
    [ "$got" = "$hex" ] || {
        echo "Error: read-back mismatch at 0x$(printf '%x' "$off"): expected $hex, found $got" >&2; exit 10; }
}

COUNT=0
for off in "${A_OFFS[@]}"; do
    if [ "$DRY_RUN" -eq 1 ]; then log "would replace 0x$(printf '%x' "$off")"; else write_half "$off" "$OUR_A"; log "replaced 0x$(printf '%x' "$off")"; fi
    COUNT=$((COUNT + 1))
done
for off in "${B_OFFS[@]}"; do
    if [ "$DRY_RUN" -eq 1 ]; then log "would replace 0x$(printf '%x' "$off")"; else write_half "$off" "$OUR_B"; log "replaced 0x$(printf '%x' "$off")"; fi
    COUNT=$((COUNT + 1))
done

[ "$DRY_RUN" -eq 1 ] && { log "Dry run: $COUNT half(es) would be replaced."; exit 0; }
log "Public key replaced ($COUNT half(es), $((COUNT * 16)) bytes)."
