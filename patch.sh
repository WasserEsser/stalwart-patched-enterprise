#!/usr/bin/env bash
#
# Stalwart Enterprise license: swap the embedded Ed25519 public key.
#
# Every Stalwart release from 0.9.0 to 0.16.23 (x86-64 and aarch64, both image
# repos) embeds the same 32-byte Ed25519 public key that licence signatures are
# verified against. It appears exactly twice: as two 16-byte constants in
# .rodata, one copy of each, in every build checked.
#
# Replacing those 32 bytes with a key you hold makes the binary validate a
# licence *you* signed, using its own verifier, untouched. No code is modified,
# so nothing is bypassed: the signature really is checked. Compare with patching
# the branch at each licence site, which needs a separate pattern per release
# (and a re-derivation whenever the code layout moves).
#
# Usage: patch.sh --pubkey <hex|file> [--dry-run] [--quiet] <binary>
#
# Exit codes:
#   0   patched (or would be, with --dry-run)
#   1   general error
#   2   missing dependency
#   3   no binary given
#   4   binary not found
#   5   binary not writable
#   6   already patched
#   7   no licence public key found (not an Enterprise build?)
#   8   inconsistent: only one of the two key halves is present
#   9   failed to write the patch
#  10   patched bytes did not verify on read-back
set -uo pipefail

# The vendor's public key, as compiled into LicenseValidator::new()
# (license.rs: vec![118, 10, 182, 35, ...]). Masking: read as two 16-byte halves.
# Bytes 1 and 12 of the halves are 0x0a, which is why the search is newline-safe.
VENDOR_HALF_A=760ab623596f0b3c9a2fcd7f6be53768
VENDOR_HALF_B=48368d0e61db0204778f9c0a98d820c2

DRY_RUN=0
QUIET=0
PUBKEY=""
BINARY_FILE=""

log() {
    [ "$QUIET" -eq 1 ] || printf '%s\n' "$*"
}

show_help() {
    cat << 'EOF'
Usage: patch.sh --pubkey <hex|file> [OPTIONS] <binary>

Replaces the Ed25519 public key that a Stalwart binary verifies Enterprise
license keys against, so that keys signed with your own private key are
accepted. The binary's own verifier is left untouched.

Options:
  -p, --pubkey <hex|file>  Your Ed25519 public key: 64 hex chars, or a file
                           containing them. generate-license.sh --pubkey-only
                           prints it. A PEM file is not accepted; use
                           --pubkey-only to get the raw hex.
      --dry-run            Report what would change; write nothing
  -q, --quiet              Suppress informational output
  -h, --help               Show this help

Exit codes: 0 patched, 3 no binary, 4 not found, 5 not writable,
            6 already patched, 7 no licence key found, 8 only one half present,
            9 write failed, 10 read-back mismatch

Example:
  ./patch.sh --pubkey "$(./generate-license.sh --pubkey-only)" ./stalwart
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        -p|--pubkey) PUBKEY="${2:-}"; shift 2 ;;
        --dry-run)   DRY_RUN=1; shift ;;
        -q|--quiet)  QUIET=1; shift ;;
        -h|--help)   show_help; exit 0 ;;
        -*)          echo "Error: unknown option '$1'" >&2; show_help >&2; exit 1 ;;
        *)
            if [ -n "$BINARY_FILE" ]; then
                echo "Error: more than one binary given." >&2
                exit 1
            fi
            BINARY_FILE="$1"; shift ;;
    esac
done

for dep in tr grep dd xxd mktemp; do
    command -v "$dep" >/dev/null 2>&1 || {
        echo "Error: required command '$dep' is not installed." >&2
        exit 2
    }
done

if [ -z "$BINARY_FILE" ]; then
    echo "Error: no binary given." >&2
    show_help >&2
    exit 3
fi
[ -f "$BINARY_FILE" ] || { echo "Error: '$BINARY_FILE' does not exist." >&2; exit 4; }
[ -w "$BINARY_FILE" ] || { echo "Error: no write permission for '$BINARY_FILE'." >&2; exit 5; }

# --- our public key -> two 16-byte halves -----------------------------------
if [ -z "$PUBKEY" ]; then
    echo "Error: --pubkey is required (64 hex chars, or a file containing them)." >&2
    echo "       Get it with: ./generate-license.sh --pubkey-only" >&2
    exit 1
fi
if [ -f "$PUBKEY" ]; then
    PUBKEY=$(tr -d ' \t\r\n:' < "$PUBKEY")
fi
PUBKEY=$(printf '%s' "$PUBKEY" | tr 'A-F' 'a-f')
case "$PUBKEY" in
    *[!0-9a-f]*|'') echo "Error: --pubkey must be 64 hex characters." >&2; exit 1 ;;
esac
if [ "${#PUBKEY}" -ne 64 ]; then
    echo "Error: --pubkey must be exactly 64 hex characters (32 bytes); got ${#PUBKEY}." >&2
    exit 1
fi
if [ "$PUBKEY" = "${VENDOR_HALF_A}${VENDOR_HALF_B}" ]; then
    echo "Error: that is the vendor's public key; supply your own." >&2
    exit 1
fi
OUR_HALF_A="${PUBKEY:0:32}"
OUR_HALF_B="${PUBKEY:32:32}"

TMP=""
cleanup() { [ -n "$TMP" ] && rm -f "$TMP"; }
trap cleanup EXIT

# --- newline-safe search ----------------------------------------------------
# grep matches line by line and both halves contain 0x0a, so the needles would
# be unmatchable in the raw file. Flatten first: tr maps 0x0a to 0x0d
# one-to-one, so file offsets stay valid, and the needle is translated the same
# way. Every hit is then re-checked against the raw bytes, because a genuine
# 0x0d in the original would otherwise masquerade as a translated 0x0a.
TMP=$(mktemp) || { echo "Error: cannot create a temporary file." >&2; exit 1; }
if ! tr '\n' '\r' < "$BINARY_FILE" > "$TMP"; then
    echo "Error: failed to read '$BINARY_FILE'." >&2
    exit 1
fi

translate_0a() {   # 0x0a -> 0x0d, byte by byte (sed would match across pairs)
    local hex=$1 out="" i b
    for ((i = 0; i < ${#hex}; i += 2)); do
        b="${hex:i:2}"
        [ "$b" = "0a" ] && b="0d"
        out+="$b"
    done
    printf '%s' "$out"
}

hex_to_pcre() {    # literal bytes, no wildcards
    local hex=$1 out="" i
    for ((i = 0; i < ${#hex}; i += 2)); do
        out+="\\x${hex:i:2}"
    done
    printf '%s' "$out"
}

# Prints every true file offset of the 16-byte needle $1.
find_half() {
    local hex=$1 flat_off raw_hex
    LC_ALL=C grep -aboP "$(hex_to_pcre "$(translate_0a "$hex")")" "$TMP" 2>/dev/null |
    while IFS=: read -r flat_off _; do
        [ -n "$flat_off" ] || continue
        raw_hex=$(dd if="$BINARY_FILE" bs=1 skip="$flat_off" count=16 2>/dev/null | xxd -p -c 16)
        if [ "$raw_hex" = "$hex" ]; then
            printf '%s\n' "$flat_off"
        fi
    done
}

mapfile -t A_OFFS < <(find_half "$VENDOR_HALF_A")
mapfile -t B_OFFS < <(find_half "$VENDOR_HALF_B")
mapfile -t OUR_A_OFFS < <(find_half "$OUR_HALF_A")
mapfile -t OUR_B_OFFS < <(find_half "$OUR_HALF_B")

NA=${#A_OFFS[@]}
NB=${#B_OFFS[@]}
NOURA=${#OUR_A_OFFS[@]}
NOURB=${#OUR_B_OFFS[@]}

# --- already patched? -------------------------------------------------------
if [ "$NA" -eq 0 ] && [ "$NB" -eq 0 ]; then
    if [ "$NOURA" -ge 1 ] && [ "$NOURB" -ge 1 ]; then
        log "Already patched: this binary carries the public key you supplied."
        log "  ($NOURA copy of the first half, $NOURB of the second)"
        exit 6
    fi
    echo "Error: no Stalwart licence public key found in '$BINARY_FILE'." >&2
    echo "       Not an Enterprise build, or the key layout changed upstream." >&2
    exit 7
fi
if [ "$NA" -eq 0 ] || [ "$NB" -eq 0 ]; then
    echo "Error: found only one of the two public-key halves" >&2
    echo "       (first half: $NA, second half: $NB) - refusing to patch a" >&2
    echo "       binary that is in an unexpected state." >&2
    exit 8
fi

log " Licence public key found in '$BINARY_FILE':"
for off in "${A_OFFS[@]}"; do log "   first half  at file offset 0x$(printf '%x' "$off")"; done
for off in "${B_OFFS[@]}"; do log "   second half at file offset 0x$(printf '%x' "$off")"; done
log " Replacing with:"
log "   $OUR_HALF_A$OUR_HALF_B"

if [ "$NA" -ne 1 ] || [ "$NB" -ne 1 ]; then
    log " Note: $NA copy/copies of the first half and $NB of the second; all are"
    log "       replaced, so no code path keeps the vendor key."
fi

# --- patch ------------------------------------------------------------------
write_half() {   # <offset> <hex>
    local off=$1 hex=$2 got
    if ! printf '%s' "$hex" | xxd -r -p | dd of="$BINARY_FILE" bs=1 seek="$off" conv=notrunc >/dev/null 2>&1; then
        echo "Error: failed to write at offset 0x$(printf '%x' "$off")." >&2
        exit 9
    fi
    got=$(dd if="$BINARY_FILE" bs=1 skip="$off" count=16 2>/dev/null | xxd -p -c 16)
    if [ "$got" != "$hex" ]; then
        echo "Error: read-back mismatch at 0x$(printf '%x' "$off"): expected $hex, found $got" >&2
        exit 10
    fi
}

PATCHED=0
for off in "${A_OFFS[@]}"; do
    if [ "$DRY_RUN" -eq 1 ]; then
        log "   would replace first half at 0x$(printf '%x' "$off")"
    else
        write_half "$off" "$OUR_HALF_A"
        log "   replaced first half at 0x$(printf '%x' "$off")"
    fi
    PATCHED=$((PATCHED + 1))
done
for off in "${B_OFFS[@]}"; do
    if [ "$DRY_RUN" -eq 1 ]; then
        log "   would replace second half at 0x$(printf '%x' "$off")"
    else
        write_half "$off" "$OUR_HALF_B"
        log "   replaced second half at 0x$(printf '%x' "$off")"
    fi
    PATCHED=$((PATCHED + 1))
done

if [ "$DRY_RUN" -eq 1 ]; then
    log "Dry run: would replace $PATCHED half(es). No changes made."
    exit 0
fi

log "Licence public key replaced ($PATCHED half(es), $((PATCHED * 16)) bytes)."
log "The signature check itself is untouched. Sign keys with your private key:"
log "  ./generate-license.sh --domain <registrable-domain>"
