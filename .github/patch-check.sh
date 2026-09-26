#!/usr/bin/env bash
#
# Verify a patched image.
#
# Usage: patch-check.sh <image> [binary] [json|toml] [original-image] [private-key]
#
#   toml  (0.9.x - 0.11.x): the license key lives in a plain TOML config, so
#         the whole flow can be exercised for real: generate a key pair, mint a
#         signed license for it, assert the image's binary carries that public
#         key, boot, and require the server to log that the license is valid.
#         Given the original image, the same license must be REJECTED by it -
#         that is the control proving the signature is really verified.
#
#   json  (0.12.x and later): the key lives in the registry and is set through
#         the admin API, whose first account is created interactively in
#         recovery mode, so acceptance cannot be asserted automatically. The
#         check is structural instead: the vendor public key must be gone, and
#         the server must still start.
#
# Exit 0 on success, 1 on failure, 2 on bad usage.
set -uo pipefail

IMAGE="${1:-}"
BINARY="${2:-/usr/local/bin/stalwart}"
MODE="${3:-json}"
ORIGINAL="${4:-}"
GIVEN_KEY="${5:-}"
[ -n "$IMAGE" ] || { echo "usage: $0 <image> [binary_path] [json|toml] [original-image] [private-key]"; exit 2; }
case "$MODE" in json|toml) ;; *) echo "mode must be json or toml"; exit 2 ;; esac

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
fail() { echo "ERROR: $*"; exit 1; }

TMP=$(mktemp -d)
CIDS=""
cleanup() {
    for c in $CIDS; do docker rm -f "$c" >/dev/null 2>&1 || true; done
    # RocksDB files are written by the container user, so the host user may not
    # be able to delete them. Remove them from a container running as that user,
    # falling back to root.
    if [ -n "$IMAGE" ] && [ -d "$TMP" ]; then
        docker run --rm -v "$TMP":/cleanup:Z --entrypoint /bin/rm "$IMAGE" -rf /cleanup >/dev/null 2>&1 || true
        docker run -u 0 --rm -v "$TMP":/cleanup:Z --entrypoint /bin/rm "$IMAGE" -rf /cleanup >/dev/null 2>&1 || true
    fi
    rm -rf "$TMP" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "checking $IMAGE ($BINARY, mode=$MODE)"

# --- extract the binary the image actually ships ----------------------------
CID=$(docker create "$IMAGE" /bin/true) || fail "cannot create a container from $IMAGE"
CIDS="$CIDS $CID"
docker cp "$CID:$BINARY" "$TMP/binary" >/dev/null 2>&1 || fail "no $BINARY in $IMAGE"
BIN="$TMP/binary"
echo "  extracted $BINARY ($(stat -c %s "$BIN") bytes)"

VENDOR_A=760ab623596f0b3c9a2fcd7f6be53768
VENDOR_B=48368d0e61db0204778f9c0a98d820c2

# Both halves contain 0x0a, so search the newline-flattened copy (offsets stay
# valid because tr maps 0x0a to 0x0d one-to-one).
count_hex() {
    local hex=$1 pat
    pat=$(printf '%s' "$hex" | sed 's/../\\x&/g')
    tr '\n' '\r' < "$BIN" | LC_ALL=C grep -aboP "$pat" 2>/dev/null | wc -l
}

# --- the vendor key must be gone --------------------------------------------
na=$(count_hex "$VENDOR_A")
nb=$(count_hex "$VENDOR_B")
if [ "$na" -ne 0 ] || [ "$nb" -ne 0 ]; then
    fail "the vendor licence public key is still present (halves found: $na, $nb)"
fi
echo "  vendor license public key replaced (0 of each half remain)"

if [ "$MODE" = "json" ]; then
    # No key pair is available for a structural check here, so verify that the
    # image still boots with its data store configured and does not crash.
    echo '{"@type":"RocksDb","path":"/var/lib/stalwart/data"}' > "$TMP/config.json"
    mkdir -p "$TMP/data"
    # The image runs as its own uid (2000 for 0.16.x), so it must be able to
    # traverse mktemp's 0700 directory and write to the data directory.
    chmod 755 "$TMP"
    chmod 777 "$TMP/data"
    CID2=$(docker run -d --entrypoint "$BINARY" \
        -e STALWART_HOSTNAME=mail.example.com \
        -v "$TMP/config.json":/etc/stalwart/config.json:ro,Z \
        -v "$TMP/data":/var/lib/stalwart:Z \
        "$IMAGE" --config /etc/stalwart/config.json) || fail "cannot start $IMAGE"
    CIDS="$CIDS $CID2"
    for _ in $(seq 1 15); do
        [ "$(docker inspect --format '{{.State.Status}}' "$CID2" 2>/dev/null)" = "running" ] || break
        sleep 2
    done
    if [ "$(docker inspect --format '{{.State.Status}}' "$CID2" 2>/dev/null)" != "running" ]; then
        echo "--- container log ---"
        docker logs "$CID2" 2>&1 | tail -20
        fail "the patched server did not stay running"
    fi
    echo "  patched server boots and stays running"
    echo "  NOTE: license acceptance is not asserted for 0.12.x+ (its key lives in"
    echo "        the registry and is set through the admin API); it is asserted on 0.11.x."
    echo "PATCH_OK: $IMAGE ($BINARY, mode=$MODE)"
    exit 0
fi

# --- toml: exercise the whole flow ------------------------------------------
# Use the key pair the image was built with when given one (the build passes
# its public key as a build-arg, so only that private key can mint a license the
# image accepts); otherwise generate a throwaway pair.
if [ -n "$GIVEN_KEY" ]; then
    [ -f "$GIVEN_KEY" ] || fail "no private key at '$GIVEN_KEY'"
    KEYFILE="$GIVEN_KEY"
    echo "  using the private key $GIVEN_KEY"
else
    KEYFILE="$TMP/signing.key"
    echo "  generating a throwaway key pair"
fi
PUB=$("$REPO/generate-license.sh" --pubkey-only --key "$KEYFILE" --quiet 2>/dev/null) \
    || fail "could not read the key pair"
[ -n "$PUB" ] || fail "empty public key"
echo "  public key ${PUB:0:16}..."

# The image must trust exactly this key: acceptance below would otherwise be
# meaningless (a different key would be rejected, and no key at all would mean
# the binary was never patched).
out=$("$REPO/patch.sh" --dry-run --pubkey "$PUB" "$BIN" 2>&1)
rc=$?
if [ "$rc" -ne 6 ]; then
    printf '%s\n' "$out" | sed 's/^/    /'
    fail "the image does not carry the expected public key (patch.sh exited $rc; 6 = already patched)"
fi
echo "  the image trusts the generated public key"

KEY=$("$REPO/generate-license.sh" --domain example.com --key "$KEYFILE" --quiet) \
    || fail "could not generate a license key"
[ -n "$KEY" ] || fail "empty license key"

mkdir -p "$TMP/etc" "$TMP/data"
cat > "$TMP/etc/config.toml" <<EOF
[server]
hostname = "example.com"

[storage]
data = "rocksdb"
fts = "rocksdb"
blob = "rocksdb"
lookup = "rocksdb"
directory = "internal"

[store."rocksdb"]
type = "rocksdb"
path = "/opt/stalwart-mail/data"
compression = "lz4"

[directory."internal"]
type = "internal"
store = "rocksdb"

[tracer."stdout"]
type = "stdout"
level = "info"
ansi = false
enable = true

[enterprise]
license-key = "$KEY"
EOF

boot_and_log() {   # $1 image  $2 logfile
    local cid
    rm -rf "$TMP/data"; mkdir -p "$TMP/data"
    cid=$(docker run -d --entrypoint "$BINARY" \
        -v "$TMP/etc/config.toml":/opt/stalwart-mail/etc/config.toml:ro,Z \
        -v "$TMP/data":/opt/stalwart-mail/data:Z \
        "$1" --config /opt/stalwart-mail/etc/config.toml) || return 1
    CIDS="$CIDS $cid"
    sleep 12
    docker logs "$cid" 2>&1 | grep -i 'licens' > "$2" 2>/dev/null
    docker rm -f "$cid" >/dev/null 2>&1
    return 0
}

boot_and_log "$IMAGE" "$TMP/log-patched.txt" || fail "cannot start $IMAGE"
if grep -qi 'license key is valid' "$TMP/log-patched.txt"; then
    echo "  license key accepted at runtime (Enterprise Edition active)"
else
    echo "--- licensing log ---"; cat "$TMP/log-patched.txt"
    fail "the patched server did not accept the signed license"
fi

if [ -n "$ORIGINAL" ]; then
    boot_and_log "$ORIGINAL" "$TMP/log-original.txt" || fail "cannot start $ORIGINAL"
    if grep -qi 'Failed to validate\|invalid' "$TMP/log-original.txt"; then
        echo "  control: the unpatched image rejects the same license (so it is really verified)"
    else
        echo "--- licensing log ---"; cat "$TMP/log-original.txt"
        fail "the unpatched image did not reject the license; the check would be vacuous"
    fi
else
    echo "  note: no original image given, so the rejection control was skipped"
fi

echo "PATCH_OK: $IMAGE ($BINARY, mode=$MODE)"
