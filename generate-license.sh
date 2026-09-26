#!/usr/bin/env bash
#
# Generate a Stalwart Enterprise license key, signed with your own private key.
#
# The binary must first be patched to carry the matching public key (patch.sh
# --pubkey). The license is a real, correctly signed license: the binary's own
# Ed25519 verifier accepts it, nothing about the check is bypassed.
#
# Key layout (little-endian, no padding):
#   offset  size  field
#   0       8     valid_from   unix timestamp (u64 LE)
#   8       8     valid_to     unix timestamp (u64 LE)
#   16      4     accounts     maximum account count (u32 LE)
#   20      4     domain_len   length of the domain in bytes (u32 LE)
#   24      n     domain       registrable domain, UTF-8
#   24+n    64    signature    Ed25519 over bytes [0, 24+n)
# The whole structure is base64-encoded (standard alphabet, no line breaks).
#
# The private key never leaves this machine: it is created here if missing and
# does not need to be shared or committed.
#
# Usage: ./generate-license.sh --domain example.com [--days 3650]
#
# Exit codes: 0 ok, 1 general error, 2 missing dependency, 3 bad arguments,
#             4 key generation or signing failed.
set -uo pipefail

KEYFILE="stalwart-license.key"
DOMAIN=""
ACCOUNTS=1000
DAYS=3650
VALID_FROM=""
OUT=""
QUIET=0
PUBKEY_ONLY=0

log() {
    [ "$QUIET" -eq 1 ] || printf '%s\n' "$*" >&2
}

show_help() {
    cat << EOF
Usage: $0 --domain <domain> [OPTIONS]

Generates a Stalwart Enterprise license key (base64) accepted by a binary
patched with patch.sh --pubkey <your-public-key>.

Options:
  -d, --domain <domain>   Domain the license is issued to. For 0.11.x and
                          later this must be the registrable domain of the
                          configured hostname, e.g. "example.com" for
                          "mail.example.com" (required)
  -a, --accounts <n>      Maximum number of accounts (default: $ACCOUNTS)
  -D, --days <n>          Validity in days from now (default: $DAYS)
  -f, --from <epoch>      Valid-from unix timestamp (default: now - 1h)
  -k, --key <file>        Ed25519 private key (default: $KEYFILE), created if
                          it does not exist. Keep it safe and do not commit it.
  -o, --out <file>        Write the key to <file> instead of stdout
      --pubkey-only       Print only the 32-byte public key (hex) needed by
                          patch.sh, and exit
  -q, --quiet             Suppress informational output
  -h, --help              Show this help and exit

Exit codes: 0 ok, 1 general error, 2 missing dependency, 3 bad arguments,
            4 key generation or signing failed.

Examples:
  # first time: create a key pair, then patch the binary to trust it
  ./generate-license.sh --pubkey-only
  ./patch.sh --pubkey "\$(./generate-license.sh --pubkey-only)" ./stalwart

  # then mint licenses with the same private key
  ./generate-license.sh --domain example.com > license.key

EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        -d|--domain)   DOMAIN="${2:-}"; shift 2 ;;
        -a|--accounts) ACCOUNTS="${2:-}"; shift 2 ;;
        -D|--days)     DAYS="${2:-}"; shift 2 ;;
        -f|--from)     VALID_FROM="${2:-}"; shift 2 ;;
        -k|--key)      KEYFILE="${2:-}"; shift 2 ;;
        -o|--out)      OUT="${2:-}"; shift 2 ;;
        --pubkey-only) PUBKEY_ONLY=1; shift ;;
        -q|--quiet)    QUIET=1; shift ;;
        -h|--help)     show_help; exit 0 ;;
        *) echo "Error: unknown option '$1'" >&2; show_help >&2; exit 3 ;;
    esac
done

for dep in openssl xxd base64 date wc mktemp; do
    command -v "$dep" >/dev/null 2>&1 || {
        echo "Error: required command '$dep' is not installed." >&2
        exit 2
    }
done
if ! openssl genpkey -algorithm ED25519 -out /dev/null 2>/dev/null; then
    echo "Error: this openssl cannot generate Ed25519 keys (need 1.1.1 or newer)." >&2
    exit 2
fi

umask 077

# --- key pair ---------------------------------------------------------------
if [ ! -f "$KEYFILE" ]; then
    log "Creating a new Ed25519 key pair in $KEYFILE"
    if ! openssl genpkey -algorithm ED25519 -out "$KEYFILE" 2>/dev/null; then
        echo "Error: failed to create the key pair in '$KEYFILE'." >&2
        exit 4
    fi
    chmod 600 "$KEYFILE"
fi

PUBHEX=$(openssl pkey -in "$KEYFILE" -pubout -outform DER 2>/dev/null | tail -c 32 | xxd -p -c 32)
if [ "${#PUBHEX}" -ne 64 ]; then
    echo "Error: could not read a 32-byte public key from '$KEYFILE'." >&2
    exit 4
fi
PUBHEX=$(printf '%s' "$PUBHEX" | tr 'A-F' 'a-f')

if [ "$PUBKEY_ONLY" -eq 1 ]; then
    printf '%s\n' "$PUBHEX"
    log "Public key: $PUBHEX"
    log "Patch a binary with: ./patch.sh --pubkey $PUBHEX <binary>"
    exit 0
fi

if [ -z "$DOMAIN" ]; then
    echo "Error: --domain is required." >&2
    show_help >&2
    exit 3
fi

# A trailing dot or surrounding whitespace would not match what the server
# compares against, and only ASCII/UTF-8 bytes are meaningful here.
DOMAIN=$(printf '%s' "$DOMAIN" | tr -d ' \t\r\n')
case "$DOMAIN" in
    *.) DOMAIN="${DOMAIN%.}" ;;
esac
if [ -z "$DOMAIN" ]; then
    echo "Error: --domain must not be empty." >&2
    exit 3
fi

# The server rejects accounts == 0 as an invalid parameter.
case "$ACCOUNTS" in
    ''|*[!0-9]*) echo "Error: --accounts must be a positive integer." >&2; exit 3 ;;
esac
if [ "$ACCOUNTS" -lt 1 ]; then
    echo "Error: --accounts must be at least 1 (the server rejects keys with accounts == 0)." >&2
    exit 3
fi

case "$DAYS" in
    ''|*[!0-9]*) echo "Error: --days must be a positive integer." >&2; exit 3 ;;
esac
if [ "$DAYS" -lt 1 ]; then
    echo "Error: --days must be at least 1." >&2
    exit 3
fi

NOW=$(date +%s)
if [ -n "$VALID_FROM" ]; then
    case "$VALID_FROM" in
        ''|*[!0-9]*) echo "Error: --from must be a unix timestamp." >&2; exit 3 ;;
    esac
    if [ "$VALID_FROM" -gt "$NOW" ]; then
        echo "Error: --from ($VALID_FROM) is in the future; the server treats such a key as expired." >&2
        exit 3
    fi
else
    VALID_FROM=$((NOW - 3600))
fi
VALID_TO=$((NOW + DAYS * 86400))

if [ "$VALID_FROM" -eq 0 ] || [ "$VALID_TO" -eq 0 ] || [ "$VALID_FROM" -ge "$VALID_TO" ]; then
    echo "Error: invalid validity window (valid_from must be non-zero and before valid_to)." >&2
    exit 3
fi

# --- payload ----------------------------------------------------------------
# Little-endian hex encoding of an integer over n bytes.
le_hex() {
    local v=$1 n=$2 out="" i
    for ((i = 0; i < n; i++)); do
        out+=$(printf '%02x' $((v & 0xff)))
        v=$((v >> 8))
    done
    printf '%s' "$out"
}

DOMAIN_LEN=$(printf '%s' "$DOMAIN" | wc -c)
DOMAIN_HEX=$(printf '%s' "$DOMAIN" | xxd -p -c 4096 | tr -d '\n')
PAYLOAD_HEX="$(le_hex "$VALID_FROM" 8)$(le_hex "$VALID_TO" 8)$(le_hex "$ACCOUNTS" 4)$(le_hex "$DOMAIN_LEN" 4)${DOMAIN_HEX}"

WORK=$(mktemp -d) || { echo "Error: cannot create a temporary directory." >&2; exit 1; }
trap 'rm -rf "$WORK"' EXIT
printf '%s' "$PAYLOAD_HEX" | xxd -r -p > "$WORK/payload.bin"

# --- sign -------------------------------------------------------------------
# Ed25519 over exactly the bytes the server verifies: everything before the
# signature.
if ! openssl pkeyutl -sign -inkey "$KEYFILE" -rawin \
        -in "$WORK/payload.bin" -out "$WORK/sig.bin" 2>/dev/null; then
    echo "Error: signing failed. Is '$KEYFILE' a valid Ed25519 private key?" >&2
    exit 4
fi
SIG_HEX=$(xxd -p -c 64 "$WORK/sig.bin" | tr -d '\n')
if [ "${#SIG_HEX}" -ne 128 ]; then
    echo "Error: expected a 64-byte signature, got ${#SIG_HEX} hex chars." >&2
    exit 4
fi

# Self-check: verify with the public key before handing the license out.
if ! openssl pkeyutl -verify -pubin -inkey <(openssl pkey -in "$KEYFILE" -pubout 2>/dev/null) \
        -rawin -in "$WORK/payload.bin" -sigfile "$WORK/sig.bin" >/dev/null 2>&1; then
    echo "Error: the signature did not verify against its own public key." >&2
    exit 4
fi

KEY=$(printf '%s%s' "$PAYLOAD_HEX" "$SIG_HEX" | xxd -r -p | base64 -w0)

if [ -n "$OUT" ]; then
    printf '%s\n' "$KEY" > "$OUT"
    log "Wrote license key to $OUT"
else
    printf '%s\n' "$KEY"
fi

log "Domain:     $DOMAIN"
log "Accounts:   $ACCOUNTS"
log "Valid from: $(date -d "@$VALID_FROM" -Iseconds 2>/dev/null || echo "$VALID_FROM")"
log "Valid to:   $(date -d "@$VALID_TO" -Iseconds 2>/dev/null || echo "$VALID_TO")"
log "Public key: $PUBHEX"
log "Signed with: $KEYFILE"
