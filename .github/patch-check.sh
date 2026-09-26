#!/usr/bin/env bash
# Usage: patch-check.sh <image> [binary] [json|toml|structural] [original-image]
# toml: mint a licence, require acceptance at runtime, and require the original
#   image (if given) to reject that same licence. 0.9.x - 0.11.x, where the
#   licence sits in a plain config.toml.
# json: structural check plus a boot. 0.16.x and up, which read config.json.
# structural: key replacement only. For releases whose licence is not set
#   through the config shipped here: 0.9.x - 0.10.x (a TOML schema this script
#   does not ship) and 0.12.x - 0.15.x (registry, and no config.json to boot
#   with), so there is nothing meaningful to assert at runtime.
set -uo pipefail

IMAGE="${1:-}"
BINARY="${2:-/usr/local/bin/stalwart}"
MODE="${3:-json}"
ORIGINAL="${4:-}"
[ -n "$IMAGE" ] || { echo "usage: $0 <image> [binary] [json|toml|structural] [original-image]"; exit 2; }
case "$MODE" in json|toml|structural) ;; *) echo "mode must be json, toml or structural"; exit 2 ;; esac

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
fail() { echo "ERROR: $*"; exit 1; }

TMP=$(mktemp -d)
CIDS=""
cleanup() {
    for c in $CIDS; do docker rm -f "$c" >/dev/null 2>&1 || true; done
    rm -rf "$TMP" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "checking $IMAGE ($BINARY, mode=$MODE)"

CID=$(docker create "$IMAGE" /bin/true) || fail "cannot create a container from $IMAGE"
CIDS="$CIDS $CID"
docker cp "$CID:$BINARY" "$TMP/binary" >/dev/null 2>&1 || fail "no $BINARY in $IMAGE"
BIN="$TMP/binary"
echo "  extracted $BINARY ($(stat -c %s "$BIN") bytes)"

# patch.sh exits 6 when the binary already carries our public key.
out=$("$REPO/patch.sh" --dry-run "$BIN" 2>&1); rc=$?
case "$rc" in
    6) echo "  vendor public key replaced, patch.sh recognises the replacement" ;;
    0) printf '%s\n' "$out" | sed 's/^/    /'; fail "the vendor key is still present (unpatched binary)" ;;
    *) printf '%s\n' "$out" | sed 's/^/    /'; fail "patch.sh exited $rc" ;;
esac

if [ "$MODE" = "structural" ]; then
    echo "  vendor key replaced; this release's licence is not set through the"
    echo "  config this script ships, so there is no runtime check to make"
    echo "PATCH_OK: $IMAGE ($BINARY, mode=$MODE)"
    exit 0
fi

if [ "$MODE" = "json" ]; then
    echo '{"@type":"RocksDb","path":"/var/lib/stalwart/data"}' > "$TMP/config.json"
    mkdir -p "$TMP/data"
    chmod 755 "$TMP"      # the image runs as its own uid and must reach the mounts
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
        docker logs "$CID2" 2>&1 | tail -20
        fail "the patched server did not stay running"
    fi
    echo "  patched server boots and stays running"
    echo "  note: licence acceptance is not asserted for 0.12.x+ (registry, set via the admin API)"
    echo "PATCH_OK: $IMAGE ($BINARY, mode=$MODE)"
    exit 0
fi

KEY=$("$REPO/generate-license.sh" --domain example.com --quiet) || fail "cannot generate a licence"
[ -n "$KEY" ] || fail "empty licence"

mkdir -p "$TMP/etc" "$TMP/data"
chmod 755 "$TMP"
chmod 777 "$TMP/data"
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

boot_and_log() {
    local cid
    rm -rf "$TMP/data"; mkdir -p "$TMP/data"; chmod 777 "$TMP/data"
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
    echo "  licence accepted at runtime"
else
    cat "$TMP/log-patched.txt"
    fail "the patched server did not accept the licence"
fi

if [ -n "$ORIGINAL" ]; then
    boot_and_log "$ORIGINAL" "$TMP/log-original.txt" || fail "cannot start $ORIGINAL"
    if grep -qi 'Failed to validate\|invalid' "$TMP/log-original.txt"; then
        echo "  control: the unpatched image rejects the same licence"
    else
        cat "$TMP/log-original.txt"
        fail "the unpatched image accepted the licence; the check would be vacuous"
    fi
fi

echo "PATCH_OK: $IMAGE ($BINARY, mode=$MODE)"
