#!/bin/bash
set -euo pipefail

# CLI options
QUIET=0
DRY_RUN=0
BINARY_FILE=""

# Help text
show_help() {
    cat << EOF
Usage: $0 [OPTIONS] <binary_file>

Patches the Stalwart Mail Server binary to bypass Enterprise license
signature validation.

Stalwart validates Enterprise licenses offline: the base64 license key is
parsed and its Ed25519 signature is checked against a public key embedded in
the binary. The verification result is a Rust Result whose discriminant is
tested with a conditional jump, and the fall-through path raises
LicenseError::Validation. Rewriting that test to "xor eax, eax" makes the
conditional always take the valid-signature path, so the signature check
always succeeds. The license key itself (valid_from/valid_to/accounts/domain)
is still parsed and enforced normally, so you still need a well-formed key
issued for your own domain -- see generate-license.sh.

Unlike Mattermost, one Stalwart binary contains FOUR inlined copies of the
validator (LicenseKey::new is inlined into its call sites), so every copy has
to be patched. The patterns are listed per version and every pattern of a
version must match exactly once.

Supported: Stalwart 0.16.x (stalwartlabs/stalwart, binary "stalwart") and
Stalwart Mail Server 0.11.x (stalwartlabs/mail-server, binary "stalwart-mail"),
x86-64 only so far. Run with --list to see all versions.

The architecture (x86-64 / ARM64) is detected from the ELF header.

Options:
  -h, --help     Show this help message and exit
  -q, --quiet    Suppress non-error output
  --dry-run      Show what would be patched without making changes
  --list         List supported Stalwart versions and exit

Exit codes:
  0  Success
  1  General error
  2  Missing dependencies
  3  No binary file specified
  4  File does not exist
  5  No write permission
  6  Already patched
  7  Pattern not found (unsupported version)
  8  Invalid offset calculated
  9  Failed to write patch
  10 Patch verification failed
  11 Not an ELF binary
  12 Unsupported architecture

EOF
}

# Pattern table: "versions|sites|pattern|offset|replacement"
#   versions    Human-readable list of Stalwart versions this pattern covers
#   sites       Total number of validator sites that must be patched for this
#               version (sum of the matches of all of its patterns)
#   pattern     Hex bytes of the license check, "??" = any single byte
#   offset      Byte offset into the pattern of the byte to modify
#   replacement Hex value to write at that byte
#
# Every pattern of a version is applied together. A single pattern legitimately
# matches more than once (once per inlined copy of the validator), so instead
# of requiring "exactly once" the total number of matches (intact + already
# patched) across the version's patterns must equal `sites`; otherwise the
# version is considered unsupported and nothing is written. The call's
# relative displacement is wildcarded so the pattern survives unrelated code
# shifts.
#
# The check is the inlined body of:
#     self.public_key.verify(&key[..payload_len], signature)
#         .map_err(|_| LicenseError::Validation)?;
# verify returns a Result<(), _> whose discriminant lands in al (0 = Ok, i.e.
# the signature is valid), so the compiler emits
#     call <verify> ; test al, al ; je <valid path>
# with the fall-through path materialising LicenseError::Validation. Patching
# the test into "xor eax, eax" (84 C0 -> 31 C0) forces ZF=1, so the je always
# takes the valid-signature path: the signature check always succeeds, for a
# genuine signature and a forged one alike. This is deliberately used instead
# of inverting the branch (74 -> 75 / 0F 84 -> 0F 85), which would accept only
# *invalid* signatures and reject a real license by sending it down the
# LicenseError::Validation path.
#
# The argument-loading sequence in front of the call is what distinguishes
# these sites from the other Ed25519 verifications in the binary (DKIM et al),
# which share the same callee but never load the 32-byte license public key:
#   * 0.16.23 - 48 89 DE (mov rsi, rbx) / 48 8B 74 24 38 (mov rsi,[rsp+0x38])
#   * 0.11.8  - 48 8B 74 24 xx (mov rsi,[rsp+disp8]) /
#               48 8B B4 24 xx xx xx xx (mov rsi,[rsp+disp32])
# All of them load the key with "mov edx, 0x20" (BA 20 00 00 00) immediately
# before, which pins the 32-byte public key as the verification input.
#
# Note on cross-version overlap: the 0.11.8 disp8 pattern is a suffix of the
# 0.16.23 disp8 pattern, so it also matches the two 0.16.23 disp8 sites. That
# is harmless -- version selection compares each version's total match count
# (intact + already patched) against that version's own declared site count, so
# for a 0.16.23 binary the 0.11.8 group only reaches 2 of its 4 required sites
# and is discarded. Only the correct version can ever be selected.
#
# Stalwart 0.16.23, x86-64, virtual addresses of the patched test bytes:
#   0x14b9af0  LicenseKey::new (inlined into Enterprise::parse)
#   0x2429be8  LicenseKey::new (second inlining)
#   0x4842930  LicenseKey::new (third inlining)
#   0x4843798  LicenseKey::new (fourth inlining)
#
# Stalwart 0.11.8, x86-64, virtual addresses of the patched test bytes:
#   0x1949286  LicenseKey::new (inlined)
#   0x194d34b  LicenseKey::new (second inlining, short branch)
#   0x272abd7  LicenseKey::new (third inlining)
#   0x2737004  LicenseKey::new (fourth inlining)
PATTERNS_X86_64=(
    # Stalwart 0.16.23 (stalwartlabs/stalwart): the pubkey Vec argument is
    # passed in rbx (48 89 DE) or reloaded from the stack (48 8B 74 24 38).
    "0.16.23|4|BF 01 00 00 00 BA 20 00 00 00 48 89 DE E8 ?? ?? ?? ?? 84 C0 74 38|18|31"
    "0.16.23|4|BF 01 00 00 00 BA 20 00 00 00 48 8B 74 24 38 E8 ?? ?? ?? ?? 84 C0 0F 84 40 03 00 00|20|31"
    # Stalwart Mail Server 0.11.8 (stalwartlabs/mail-server): stack-slot
    # encodings differ per inlining (disp8 vs disp32), and one of the four
    # sites branches with a short je, so its pattern anchors on the error
    # discriminant that the fall-through path materialises instead.
    "0.11.8|4|BA 20 00 00 00 48 8B 74 24 ?? E8 ?? ?? ?? ?? 84 C0 0F 84 ?? ?? ?? ??|15|31"
    "0.11.8|4|BA 20 00 00 00 48 8B B4 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 84 C0 0F 84 ?? ?? ?? ??|18|31"
    "0.11.8|4|E8 ?? ?? ?? ?? 84 C0 48 B8 03 00 00 00 00 00 00 80 48 8B 7C 24 ?? 74|5|31"
)

# ARM64 (aarch64) patterns. The check is a compare-and-branch on the returned
# discriminant right after the call; ARM64 is little-endian, so the opcode's
# high byte is the LAST byte of the 4-byte instruction (cbz/ldrb style branch
# bytes are inverted the same way as on x86-64).
PATTERNS_ARM64=(
)

# Sanity anchors: the 32 bytes of the embedded Ed25519 license public key,
# stored as two separate 16-byte .rodata constants. These are version-stable
# constants, so finding them confirms the binary really is an Enterprise build
# with this validation code in it. Informational only.
PUBKEY_ANCHORS=(
    "pubkey[0..16]|76 0A B6 23 59 6F 0B 3C 9A 2F CD 7F 6B E5 37 68"
    "pubkey[16..32]|48 36 8D 0E 61 DB 02 04 77 8F 9C 0A 98 D8 20 C2"
)

# List supported versions (deduplicated: one line per version, not per pattern)
list_versions() {
    local seen=() entry v s skip
    echo "Supported Stalwart versions:"
    echo "x86-64:"
    if [ ${#PATTERNS_X86_64[@]} -eq 0 ]; then
        echo "  (none yet)"
    else
        for entry in "${PATTERNS_X86_64[@]}"; do
            v=$(echo "$entry" | cut -d'|' -f1)
            skip=0
            for s in ${seen[@]+"${seen[@]}"}; do
                [ "$s" = "$v" ] && skip=1
            done
            [ "$skip" -eq 1 ] && continue
            seen+=("$v")
            echo "  - $v ($(echo "$entry" | cut -d'|' -f2) sites)"
        done
    fi
    seen=()
    echo "ARM64 (aarch64):"
    if [ ${#PATTERNS_ARM64[@]} -eq 0 ]; then
        echo "  (none yet)"
    else
        for entry in "${PATTERNS_ARM64[@]}"; do
            v=$(echo "$entry" | cut -d'|' -f1)
            skip=0
            for s in ${seen[@]+"${seen[@]}"}; do
                [ "$s" = "$v" ] && skip=1
            done
            [ "$skip" -eq 1 ] && continue
            seen+=("$v")
            echo "  - $v ($(echo "$entry" | cut -d'|' -f2) sites)"
        done
    fi
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -q|--quiet)
            QUIET=1
            shift
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        --list)
            list_versions
            exit 0
            ;;
        -*)
            echo "Error: Unknown option: $1" >&2
            echo "Use '$0 --help' for usage information." >&2
            exit 1
            ;;
        *)
            if [ -z "$BINARY_FILE" ]; then
                BINARY_FILE="$1"
            else
                echo "Error: Multiple binary files specified." >&2
                exit 1
            fi
            shift
            ;;
    esac
done

# Helper for conditional output
log() {
    if [ "$QUIET" -eq 0 ]; then
        echo "$@"
    fi
}

# Build a PCRE byte pattern from the hex pattern ("??" -> any byte)
# Note: grep -P treats a literal 0x0a (newline) byte in the pattern as a line
# terminator, which would make such patterns unmatchable. We therefore emit a
# wildcard for any fixed 0x0a byte; the surrounding context keeps the pattern
# specific enough.
# Usage: hex_to_pcre <hex_pattern>
hex_to_pcre() {
    local pattern="$1" token out="" lower
    for token in $pattern; do
        if [ "$token" = "??" ]; then
            out+='[\x00-\xff]'
        else
            lower=$(echo "$token" | LC_ALL=C tr 'A-F' 'a-f')
            if [ "$lower" = "0a" ]; then
                out+='[\x00-\xff]'
            else
                out+="\\x$lower"
            fi
        fi
    done
    echo "$out"
}

# Build a plain regex from the hex pattern for the hexdump fallback.
# Each "??" becomes "." (one hex char pair = one byte).
# Usage: hex_to_regex <hex_pattern>
hex_to_regex() {
    local pattern="$1" token out=""
    for token in $pattern; do
        if [ "$token" = "??" ]; then
            out+='..'
        else
            out+="$(echo "$token" | LC_ALL=C tr 'A-F' 'a-f')"
        fi
    done
    echo "$out"
}

# Replace the byte at a given offset inside a hex pattern
# Usage: pattern_set_byte <hex_pattern> <offset> <value>
pattern_set_byte() {
    local pattern="$1" offset="$2" value="$3"
    local tokens=() i=0
    for token in $pattern; do
        tokens+=("$token")
    done
    tokens[$offset]="$value"
    echo "${tokens[*]}"
}

# Get the byte at a given offset inside a hex pattern
# Usage: pattern_get_byte <hex_pattern> <offset>
pattern_get_byte() {
    local pattern="$1" offset="$2"
    local tokens=() token
    for token in $pattern; do
        tokens+=("$token")
    done
    echo "${tokens[$offset]}"
}

# Setup cleanup for temp files
TEMP_FILE=""
cleanup() {
    if [ -n "$TEMP_FILE" ] && [ -f "$TEMP_FILE" ]; then
        rm -f "$TEMP_FILE"
    fi
}
trap cleanup EXIT

# Check for required dependencies
DEPENDENCIES=(xxd grep awk dd tr mktemp file fold)
MISSING_DEPS=()

for dep in "${DEPENDENCIES[@]}"; do
    if ! command -v "$dep" >/dev/null 2>&1; then
        MISSING_DEPS+=("$dep")
    fi
done

if [ ${#MISSING_DEPS[@]} -gt 0 ]; then
    echo "Error: The following required commands are not installed:"
    for dep in "${MISSING_DEPS[@]}"; do
        echo "  - $dep"
    done
    echo "Please install them and try again."
    exit 2
fi

# Check if grep supports PCRE (-P). BusyBox grep does not.
if echo "x" | grep -qP "x" 2>/dev/null; then
    HAVE_PCRE=1
else
    HAVE_PCRE=0
    log "Warning: grep does not support -P (PCRE). Falling back to hexdump method (slower)."
    if ! command -v hexdump >/dev/null 2>&1; then
        echo "Error: grep without -P support requires hexdump, which is not installed." >&2
        exit 2
    fi
fi

# Check binary file argument exists and is writable
if [ -z "$BINARY_FILE" ]; then
    echo "Error: No binary file specified." >&2
    show_help >&2
    exit 3
fi

if [ ! -f "$BINARY_FILE" ]; then
    echo "Error: File '$BINARY_FILE' does not exist." >&2
    exit 4
fi

if [ ! -w "$BINARY_FILE" ]; then
    echo "Error: No write permission for '$BINARY_FILE'." >&2
    exit 5
fi

# Check if file is an ELF binary
FILE_TYPE=$(file -bL "$BINARY_FILE") || {
    echo "Error: Unable to determine file type for '$BINARY_FILE'." >&2
    exit 1
}
if ! echo "$FILE_TYPE" | grep -q "ELF"; then
    echo "Error: '$BINARY_FILE' does not appear to be an ELF binary (detected: $FILE_TYPE)." >&2
    exit 11
fi

# Select the pattern table matching the binary's architecture
if echo "$FILE_TYPE" | grep -q "x86-64"; then
    ARCH="x86-64"
    PATTERNS=("${PATTERNS_X86_64[@]}")
elif echo "$FILE_TYPE" | grep -q "ARM aarch64"; then
    ARCH="arm64"
    PATTERNS=("${PATTERNS_ARM64[@]}")
else
    echo "Error: Unsupported architecture (detected: $FILE_TYPE)." >&2
    echo "Supported architectures: x86-64 and ARM aarch64." >&2
    exit 12
fi
log "Detected architecture: $ARCH"

if [ ${#PATTERNS[@]} -eq 0 ]; then
    echo "Error: No patch patterns are known for $ARCH yet." >&2
    echo "Only x86-64 patterns have been derived so far. Please report this at:" >&2
    echo "  https://github.com/WasserEsser/stalwart-patched-enterprise/issues" >&2
    exit 7
fi

# Prepare a searchable copy of the binary.
# Fast path: strip newlines (1:1 byte mapping, preserves offsets) so grep -P
# can match byte sequences that would otherwise span line boundaries.
TEMP_FILE=$(mktemp) || {
    echo "Error: failed to create a temporary file (is TMPDIR writable and not full?)." >&2
    exit 1
}
if [ "$HAVE_PCRE" -eq 1 ]; then
    log "Preparing binary for search"
    if ! tr '\n' '\r' < "$BINARY_FILE" > "$TEMP_FILE"; then
        echo "Error: Failed to prepare '$BINARY_FILE' for search (unreadable file, or no space left in TMPDIR)." >&2
        exit 1
    fi
else
    log "Dumping hexcode of original binary"
    # Fold the hexdump into lines so grep processes short lines: a single
    # 2x-file-size line would exhaust memory on constrained systems and is
    # orders of magnitude slower. Byte offsets stay valid because grep -b
    # reports absolute file offsets; search_pattern() corrects for the
    # inserted newlines.
    if ! hexdump -ve '1/1 "%.2x"' "$BINARY_FILE" | fold -w 65536 > "$TEMP_FILE"; then
        echo "Error: Failed to hexdump '$BINARY_FILE' (unreadable file, or no space left in TMPDIR)." >&2
        exit 1
    fi
fi

if [ ! -s "$TEMP_FILE" ]; then
    echo "Error: Failed to extract binary data (empty output)." >&2
    exit 1
fi

# Search a pattern in the binary.
# Prints one "<byte_offset>" per match (byte offset into the original file).
#
# Patterns that contain a literal 0x0a byte are searched in the prepared
# newline-flattened copy (grep cannot match across line boundaries). All
# other patterns are searched in the raw binary: grep then processes short
# lines instead of one giant line, which keeps memory usage low even for
# huge binaries. (grep -P buffers the whole flattened line, which can
# exhaust memory on constrained systems and fail silently.)
#
# Usage: search_pattern <hex_pattern> <pcre_pattern> <plain_regex> <hex_mode(0|1)>
search_pattern() {
    local hex_pattern="$1" pcre="$2" plain="$3" hex_mode="$4"
    local search_file="$BINARY_FILE" result rc errf

    if [ "$hex_mode" -eq 1 ] || echo "$hex_pattern" | tr ' ' '\n' | grep -qxi '0a'; then
        search_file="$TEMP_FILE"
    fi

    errf=$(mktemp) || { echo "Error: failed to create a temporary file (is TMPDIR writable and not full?)." >&2; exit 1; }
    if [ "$hex_mode" -eq 1 ]; then
        # The hexdump is folded at 65536 chars per line. Unfold its offsets:
        # true_offset = p - floor((p + 1) / 65537).
        if result=$(LC_ALL=C grep -Eo -b "$plain" "$search_file" 2>"$errf" | LC_ALL=C awk -F: 'NF {print $1 - int(($1 + 1) / 65537)}'); then
            rc=0
        else
            rc=$?
        fi
    else
        # grep -o writes "<offset>:<raw match>". The match can contain NUL
        # bytes, so extract the offset before command substitution: Bash
        # cannot store NUL bytes and would otherwise warn while silently
        # dropping them. (With pipefail the pipeline still reports grep's
        # exit status, so the error handling below keeps working.)
        if result=$(LC_ALL=C grep -aboP "$pcre" "$search_file" 2>"$errf" | LC_ALL=C awk -F: 'NF {print $1}'); then
            rc=0
        else
            rc=$?
        fi
        # A pattern whose wildcard bytes span a literal 0x0a byte in the
        # binary can never match in the raw file (grep cannot match across
        # line boundaries). If the raw search found nothing, retry on the
        # newline-flattened copy before giving up on this pattern.
        if [ "$rc" -eq 1 ] && [ "$search_file" != "$TEMP_FILE" ]; then
            result=$(LC_ALL=C grep -aboP "$pcre" "$TEMP_FILE" 2>"$errf" | LC_ALL=C awk -F: 'NF {print $1}'); rc=$?
        fi
    fi

    if [ "$rc" -eq 2 ]; then
        echo "Warning: grep failed on '$search_file' ($(cat "$errf")), skipping this pattern" >&2
        result=""
    fi
    rm -f "$errf"
    printf '%s\n' "$result"
}

# Sanity-check the embedded license public key. Purely informational: it
# confirms we are looking at a Stalwart Enterprise binary.
for anchor in "${PUBKEY_ANCHORS[@]}"; do
    IFS='|' read -r label pattern <<< "$anchor"
    hits=$(search_pattern "$pattern" "$(hex_to_pcre "$pattern")" "$(hex_to_regex "$pattern")" "$((1 - HAVE_PCRE))")
    n=0
    first=""
    for off in $hits; do
        n=$((n + 1))
        [ -z "$first" ] && first="$off"
    done
    if [ "$n" -ge 1 ]; then
        log "Found license public key anchor ($label) at file offset 0x$(printf '%x' "$first")"
    else
        log "Warning: license public key anchor ($label) not found - this may not be a Stalwart Enterprise binary."
    fi
done

log "Searching for the Enterprise license signature check"

# Pass 1: count matches for every entry, in both original and patched form.
COUNT=0
for entry in "${PATTERNS[@]}"; do
    IFS='|' read -r versions sites pattern offset replacement <<< "$entry"
    patched_pattern=$(pattern_set_byte "$pattern" "$offset" "$replacement")

    orig_hits=$(search_pattern "$pattern" "$(hex_to_pcre "$pattern")" "$(hex_to_regex "$pattern")" "$((1 - HAVE_PCRE))")
    patched_hits=$(search_pattern "$patched_pattern" "$(hex_to_pcre "$patched_pattern")" "$(hex_to_regex "$patched_pattern")" "$((1 - HAVE_PCRE))")

    orig_count=0
    orig_list=""
    for off in $orig_hits; do
        orig_count=$((orig_count + 1))
        orig_list="$orig_list $off"
    done
    patched_count=0
    for off in $patched_hits; do
        patched_count=$((patched_count + 1))
    done

    EV_VERSION[$COUNT]="$versions"
    EV_SITES[$COUNT]="$sites"
    EV_PATTERN[$COUNT]="$pattern"
    EV_OFFSET[$COUNT]="$offset"
    EV_REPLACEMENT[$COUNT]="$replacement"
    EV_ORIG_COUNT[$COUNT]="$orig_count"
    EV_ORIG_OFFSETS[$COUNT]="$orig_list"
    EV_PATCHED_COUNT[$COUNT]="$patched_count"
    COUNT=$((COUNT + 1))
done

# Pass 2: pick the version for which the total number of matches
# (intact + already patched) equals the declared number of validator sites.
FOUND_VERSION=""
FOUND_SITES=0
VERSIONS_SEEN=()
for ((i = 0; i < COUNT; i++)); do
    v="${EV_VERSION[$i]}"
    skip=0
    for seen in ${VERSIONS_SEEN[@]+"${VERSIONS_SEEN[@]}"}; do
        [ "$seen" = "$v" ] && skip=1
    done
    [ "$skip" -eq 1 ] && continue
    VERSIONS_SEEN+=("$v")

    want="${EV_SITES[$i]}"
    got=0
    for ((j = 0; j < COUNT; j++)); do
        [ "${EV_VERSION[$j]}" = "$v" ] || continue
        got=$((got + EV_ORIG_COUNT[j] + EV_PATCHED_COUNT[j]))
    done

    if [ "$got" -eq "$want" ]; then
        if [ -n "$FOUND_VERSION" ]; then
            echo "Error: Both '$FOUND_VERSION' and '$v' match the binary. This is unexpected" >&2
            echo "and could patch the wrong code. Please report this at:" >&2
            echo "  https://github.com/WasserEsser/stalwart-patched-enterprise/issues" >&2
            exit 1
        fi
        FOUND_VERSION="$v"
        FOUND_SITES="$want"
    fi
done

if [ -z "$FOUND_VERSION" ]; then
    echo "Call not found!" >&2
    echo "Your Stalwart version may not be supported yet." >&2
    echo "Supported versions:" >&2
    for v in ${VERSIONS_SEEN[@]+"${VERSIONS_SEEN[@]}"}; do
        [ -n "$v" ] && echo "  - $v" >&2
    done
    echo "If your version is not listed, update this script or report the issue at:" >&2
    echo "  https://github.com/WasserEsser/stalwart-patched-enterprise/issues" >&2
    exit 7
fi

log "Detected version: $FOUND_VERSION"

# Collect the entries that still need patching.
PENDING=()
PENDING_TOTAL=0
ALREADY=0
for ((i = 0; i < COUNT; i++)); do
    [ "${EV_VERSION[$i]}" = "$FOUND_VERSION" ] || continue
    ALREADY=$((ALREADY + EV_PATCHED_COUNT[i]))
    if [ "${EV_ORIG_COUNT[$i]}" -gt 0 ]; then
        PENDING+=("$i")
        PENDING_TOTAL=$((PENDING_TOTAL + EV_ORIG_COUNT[i]))
    fi
done

if [ "$PENDING_TOTAL" -eq 0 ]; then
    log "Binary appears to already be patched ($ALREADY/$FOUND_SITES site(s) rewritten)."
    exit 6
fi

log "License signature check found: $FOUND_SITES site(s) total, $PENDING_TOTAL to patch, $ALREADY already patched"

PATCHED_COUNT=0
for i in "${PENDING[@]}"; do
    pattern="${EV_PATTERN[$i]}"
    offset="${EV_OFFSET[$i]}"
    replacement="${EV_REPLACEMENT[$i]}"
    ORIGINAL_BYTE=$(pattern_get_byte "$pattern" "$offset")
    if [ "$ORIGINAL_BYTE" = "??" ]; then
        echo "Error: Pattern offset $offset points at a wildcard byte." >&2
        exit 8
    fi

    for FOUND_OFFSET in ${EV_ORIG_OFFSETS[$i]}; do
        # Fast path offsets are already in bytes. Hexdump path needs /2.
        if [ "$HAVE_PCRE" -eq 1 ]; then
            BYTE_OFFSET=$((FOUND_OFFSET + offset))
        else
            BYTE_OFFSET=$((FOUND_OFFSET / 2 + offset))
        fi
        BYTE_OFFSET_HEX=$(printf "%x" "$BYTE_OFFSET")

        if [ "$BYTE_OFFSET" -lt 0 ]; then
            echo "Error: Calculated offset is before the start of the file!" >&2
            exit 8
        fi

        log "  Rewriting signature check at offset 0x$BYTE_OFFSET_HEX ($ORIGINAL_BYTE -> $replacement, test al,al -> xor eax,eax)"

        if [ "$DRY_RUN" -eq 1 ]; then
            continue
        fi

        if ! printf "$replacement" | xxd -r -p | dd of="$BINARY_FILE" bs=1 seek="$BYTE_OFFSET" conv=notrunc > /dev/null 2>&1; then
            echo "Error: Failed to write patch to '$BINARY_FILE'." >&2
            exit 9
        fi

        # Verify the patch was applied
        WRITTEN_BYTE=$(dd if="$BINARY_FILE" bs=1 skip="$BYTE_OFFSET" count=1 2>/dev/null | xxd -p) || {
            echo "Error: Failed to read back patched byte at offset 0x$BYTE_OFFSET_HEX for verification." >&2
            exit 1
        }
        if [ "$(echo "$WRITTEN_BYTE" | tr "A-F" "a-f")" != "$(echo "$replacement" | tr "A-F" "a-f")" ]; then
            echo "Error: Patch verification failed! Expected '$replacement' but found '$WRITTEN_BYTE' at offset 0x$BYTE_OFFSET_HEX." >&2
            exit 10
        fi

        PATCHED_COUNT=$((PATCHED_COUNT + 1))
    done
done

if [ "$DRY_RUN" -eq 1 ]; then
    log "Dry run: would patch $PENDING_TOTAL site(s). No changes made to '$BINARY_FILE'."
    exit 0
fi

log "Licensing code patched ($PATCHED_COUNT site(s))!"
log "Generate a license key for your own domain with generate-license.sh and set it"
log "in the Stalwart configuration as:"
log "  0.16.x (JSON):  \"enterprise\": { \"licenseKey\": \"<key>\" }"
log "  0.11.x (TOML):  [enterprise] license-key = \"<key>\""
