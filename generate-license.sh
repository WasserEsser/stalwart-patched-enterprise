#!/bin/bash
set -euo pipefail

# Generates a Stalwart Enterprise license key for a patched binary.
#
# The key format (all integers little-endian) is:
#
#   offset  size  field
#   0       8     valid_from   (unix seconds, must be <= now)
#   8       8     valid_to     (unix seconds, must be > now)
#   16      4     accounts     (max number of accounts, must be > 0)
#   20      4     domain_len   (byte length of the domain that follows)
#   24      n     domain       (UTF-8)
#   24+n    m     signature    (ignored by a patched binary)
#
# The whole structure is base64-encoded (standard alphabet, no line breaks).
#
# A patched binary accepts any signature, but the remaining fields are still
# enforced: the key must be well-formed and the domain must match the
# registrable domain of the server hostname (both sides are reduced with the
# Public Suffix List, so a key issued for "example.com" is accepted by a
# server whose hostname is "mail.example.com").

QUIET=0
DOMAIN=""
ACCOUNTS=1000
DAYS=3650
VALID_FROM=""
OUT=""

show_help() {
    cat << EOF
Usage: $0 --domain <domain> [OPTIONS]

Generates a Stalwart Enterprise license key (base64) accepted by a binary
patched with patch.sh.

Options:
  -d, --domain <domain>   Domain the license is issued to. Must be the
                          registrable domain of the Stalwart hostname,
                          e.g. "example.com" for "mail.example.com" (required)
  -a, --accounts <n>      Maximum number of accounts (default: $ACCOUNTS)
  -D, --days <n>          Validity in days from now (default: $DAYS)
  -f, --from <epoch>      Valid-from unix timestamp (default: now - 1h)
  -o, --out <file>        Write the key to <file> instead of stdout
  -q, --quiet             Suppress informational output
  -h, --help              Show this help message and exit

Exit codes:
  0  Success
  1  General error
  2  Missing dependencies
  3  Invalid arguments

Example:
  ./generate-license.sh --domain example.com > license.key

EOF
}

while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--domain) DOMAIN="${2:-}"; shift 2 ;;
        -a|--accounts) ACCOUNTS="${2:-}"; shift 2 ;;
        -D|--days) DAYS="${2:-}"; shift 2 ;;
        -f|--from) VALID_FROM="${2:-}"; shift 2 ;;
        -o|--out) OUT="${2:-}"; shift 2 ;;
        -q|--quiet) QUIET=1; shift ;;
        -h|--help) show_help; exit 0 ;;
        *) echo "Error: Unknown option: $1" >&2; echo "Use '$0 --help' for usage." >&2; exit 3 ;;
    esac
done

log() { [ "$QUIET" -eq 0 ] && echo "$@" || true; }

MISSING=()
for dep in xxd base64 date wc; do
    command -v "$dep" >/dev/null 2>&1 || MISSING+=("$dep")
done
if [ ${#MISSING[@]} -gt 0 ]; then
    echo "Error: The following required commands are not installed: ${MISSING[*]}" >&2
    exit 2
fi

if [ -z "$DOMAIN" ]; then
    echo "Error: --domain is required." >&2
    echo "Use '$0 --help' for usage." >&2
    exit 3
fi

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
# Dummy signature: a patched binary never verifies it. 64 bytes mirrors a real
# Ed25519 signature length so the key looks well-formed to anything inspecting
# the structure.
SIG_HEX=$(printf '78%.0s' $(seq 1 64))

FULL_HEX="$(le_hex "$VALID_FROM" 8)$(le_hex "$VALID_TO" 8)$(le_hex "$ACCOUNTS" 4)$(le_hex "$DOMAIN_LEN" 4)${DOMAIN_HEX}${SIG_HEX}"
KEY=$(printf '%s' "$FULL_HEX" | xxd -r -p | base64 -w0)

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
log ""
log "Set it as the license key in the Stalwart configuration:"
log "  0.16.x (JSON, /etc/stalwart/config.json):"
log '    { "enterprise": { "licenseKey": "<key>" }, "system": { "defaultHostname": "mail.'"$DOMAIN"'" } }'
log "  0.11.x (TOML, /opt/stalwart-mail/etc/config.toml):"
log '    [server]'
log '    hostname = "mail.'"$DOMAIN"'"'
log '    [enterprise]'
log '    license-key = "<key>"'
