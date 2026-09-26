#!/usr/bin/env bash
# Usage: ./generate-license.sh --domain example.com [--accounts 1000] [--days 3650]
# Exit codes: 0 ok, 1 general error, 2 missing dependency, 3 bad arguments, 4 signing failed.
set -uo pipefail

# Ed25519 private key seed: the PKCS#8 DER below is built from these 32 bytes.
SEED=e86286e62ba71dd7f4b2d8c4a280416b64678764079b177033059030ea58b908

# Matching public key, for the self-check before the licence is printed.
PUBKEY=b45b434c0c2d0680ada62e2373a9ff49674880e86afe047e06211d11b8a195ba

DOMAIN=""
ACCOUNTS=1000
DAYS=3650
FROM=""
OUT=""
QUIET=0

log() { [ "$QUIET" -eq 1 ] || printf '%s\n' "$*" >&2; }

while [ $# -gt 0 ]; do
    case "$1" in
        -d|--domain)   DOMAIN="${2:-}"; shift 2 ;;
        -a|--accounts) ACCOUNTS="${2:-}"; shift 2 ;;
        -D|--days)     DAYS="${2:-}"; shift 2 ;;
        -f|--from)     FROM="${2:-}"; shift 2 ;;
        -o|--out)      OUT="${2:-}"; shift 2 ;;
        -q|--quiet)    QUIET=1; shift ;;
        -h|--help)
            cat <<'EOF'
Usage: ./generate-license.sh --domain <domain> [OPTIONS]

  -d, --domain <d>    registrable domain the licence is issued to (required)
  -a, --accounts <n>  maximum number of accounts (default: 1000)
  -D, --days <n>      validity in days from now (default: 3650)
  -f, --from <epoch>  valid-from unix timestamp (default: now - 1h)
  -o, --out <file>    write to a file instead of stdout
  -q, --quiet         suppress the summary on stderr
  -h, --help          show this help
EOF
            exit 0 ;;
        *) echo "Error: unknown option '$1'" >&2; exit 3 ;;
    esac
done

for dep in openssl xxd base64 date wc mktemp; do
    command -v "$dep" >/dev/null 2>&1 || { echo "Error: '$dep' is not installed." >&2; exit 2; }
done

[ -n "$DOMAIN" ] || { echo "Error: --domain is required." >&2; exit 3; }
case "$ACCOUNTS" in ''|*[!0-9]*) echo "Error: --accounts must be a positive integer." >&2; exit 3 ;; esac
[ "$ACCOUNTS" -ge 1 ] || { echo "Error: --accounts must be at least 1." >&2; exit 3; }
case "$DAYS" in ''|*[!0-9]*) echo "Error: --days must be a positive integer." >&2; exit 3 ;; esac
[ "$DAYS" -ge 1 ] || { echo "Error: --days must be at least 1." >&2; exit 3; }

NOW=$(date +%s)
if [ -n "$FROM" ]; then
    case "$FROM" in ''|*[!0-9]*) echo "Error: --from must be a unix timestamp." >&2; exit 3 ;; esac
    [ "$FROM" -le "$NOW" ] || { echo "Error: --from must not be in the future." >&2; exit 3; }
else
    FROM=$((NOW - 3600))
fi
TO=$((NOW + DAYS * 86400))
[ "$FROM" -ge 1 ] && [ "$TO" -ge 1 ] && [ "$FROM" -lt "$TO" ] || { echo "Error: invalid validity window." >&2; exit 3; }

# Licence layout, little-endian:
#   valid_from u64 | valid_to u64 | accounts u32 | domain_len u32 | domain | signature
le_hex() {
    local v=$1 n=$2 out="" i
    for ((i = 0; i < n; i++)); do
        out+=$(printf '%02x' $((v & 0xff)))
        v=$((v >> 8))
    done
    printf '%s' "$out"
}

DOMAIN_HEX=$(printf '%s' "$DOMAIN" | xxd -p -c 4096 | tr -d '\n')
PAYLOAD_HEX="$(le_hex "$FROM" 8)$(le_hex "$TO" 8)$(le_hex "$ACCOUNTS" 4)$(le_hex "$(printf '%s' "$DOMAIN" | wc -c)" 4)${DOMAIN_HEX}"

WORK=$(mktemp -d) || exit 1
trap 'rm -rf "$WORK"' EXIT
umask 077
printf '302e020100300506032b657004220420%s' "$SEED" | xxd -r -p > "$WORK/key.der"
printf '%s' "$PAYLOAD_HEX" | xxd -r -p > "$WORK/payload.bin"

openssl pkeyutl -sign -inkey "$WORK/key.der" -keyform DER -rawin \
    -in "$WORK/payload.bin" -out "$WORK/sig.bin" 2>/dev/null \
    || { echo "Error: signing failed." >&2; exit 4; }

SIG_HEX=$(xxd -p -c 64 "$WORK/sig.bin" | tr -d '\n')
[ "${#SIG_HEX}" -eq 128 ] || { echo "Error: signature is ${#SIG_HEX} hex chars, expected 128." >&2; exit 4; }

printf '302a300506032b6570032100%s' "$PUBKEY" | xxd -r -p > "$WORK/pub.der"
openssl pkeyutl -verify -pubin -inkey "$WORK/pub.der" -keyform DER -rawin \
    -in "$WORK/payload.bin" -sigfile "$WORK/sig.bin" >/dev/null 2>&1 \
    || { echo "Error: signature does not verify against the public key." >&2; exit 4; }

KEY=$(printf '%s%s' "$PAYLOAD_HEX" "$SIG_HEX" | xxd -r -p | base64 -w0)

if [ -n "$OUT" ]; then
    printf '%s\n' "$KEY" > "$OUT"
    log "Wrote $OUT"
else
    printf '%s\n' "$KEY"
fi
log "domain: $DOMAIN, accounts: $ACCOUNTS, valid $(date -d "@$FROM" +%F) to $(date -d "@$TO" +%F)"
