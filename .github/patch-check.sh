#!/bin/bash
# Verifies that a patched Stalwart image is patched correctly and still runs.
#
# Usage: patch-check.sh <image> [binary_path] [mode]
#   binary_path  path of the server binary inside the image
#                (default /usr/local/bin/stalwart)
#   mode         json (default) - Stalwart 0.16.x
#                toml           - Stalwart Mail Server 0.11.x
#
# What this checks:
#   - the four license-check sites in the image's binary are already rewritten
#     (patch.sh run against the extracted binary must exit 6), so the image
#     really carries the patch;
#   - the embedded license public key is present, so this really is an
#     Enterprise build with the expected validation code in it;
#   - the patched server boots and stays running;
#   - in "toml" mode, additionally that it ACCEPTS a self-generated license key
#     at runtime: the 0.11.x server reads the key straight out of its TOML
#     config, so we can generate one, boot, and require the
#     "license key is valid" event in the log.
#
# In "json" mode that last part is not possible: 0.16.x keeps the key in its
# registry database and it is set through the admin API, whose first account is
# created interactively via recovery mode. See HOW_TO.md step 5/6.
set -uo pipefail

IMAGE="${1:-}"
BINARY="${2:-/usr/local/bin/stalwart}"
MODE="${3:-json}"
[ -n "$IMAGE" ] || { echo "usage: $0 <image> [binary_path] [json|toml]"; exit 1; }
case "$MODE" in json|toml) ;; *) echo "mode must be json or toml"; exit 1 ;; esac

HERE="$(cd "$(dirname "$0")" && pwd)"
fail() { echo "ERROR: $*"; exit 1; }

TMP=$(mktemp -d)
CIDS=""
cleanup() {
  for c in $CIDS; do docker rm -f "$c" >/dev/null 2>&1 || true; done
  # RocksDB files are written by the container user, so the host user may not be
  # able to delete them. Remove them from a throwaway container running as the
  # same user (the image's default), falling back to root.
  if [ -n "$IMAGE" ] && [ -d "$TMP" ]; then
    docker run --rm -v "$TMP":/cleanup:Z --entrypoint /bin/rm "$IMAGE" -rf /cleanup \
      >/dev/null 2>&1 || true
    docker run -u 0 --rm -v "$TMP":/cleanup:Z --entrypoint /bin/rm "$IMAGE" -rf /cleanup \
      >/dev/null 2>&1 || true
  fi
  rm -rf "$TMP" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# 1. Pull the binary out of the patched image and confirm the sites are
#    already rewritten. patch.sh exits 6 when every site is already patched.
# ---------------------------------------------------------------------------
CID=$(docker create "$IMAGE" /bin/true) || fail "cannot create container from $IMAGE"
CIDS="$CIDS $CID"
docker cp "$CID:$BINARY" "$TMP/stalwart" >/dev/null 2>&1 \
  || fail "no binary at $BINARY in $IMAGE"

echo "  checking patched binary"
if bash "$HERE/../patch.sh" --quiet "$TMP/stalwart"; then
  fail "patch.sh reported success on an already-patched image (expected exit 6)"
else
  rc=$?
  [ "$rc" = "6" ] || fail "patch.sh on the patched binary exited $rc, expected 6"
fi

# The two 16-byte Ed25519 license public-key constants, written as literal PCRE
# patterns rather than derived with sed: GNU sed expands \x00/\xff into real
# bytes, which corrupts a [\x00-\xff] class.
#
# 0x0a is wildcarded (grep -P cannot put a newline in a pattern) and the search
# runs against a newline-flattened copy: the match spans the 0x0a byte inside
# the constant, and grep cannot match across a line boundary in the raw file.
# -q avoids NUL-byte problems in command substitution.
ANCHORS=(
  '\x76[\x00-\xff]\xb6\x23\x59\x6f\x0b\x3c\x9a\x2f\xcd\x7f\x6b\xe5\x37\x68'
  '\x48\x36\x8d\x0e\x61\xdb\x02\x04\x77\x8f\x9c[\x00-\xff]\x98\xd8\x20\xc2'
)
tr '\n' '\r' < "$TMP/stalwart" > "$TMP/stalwart.flat" \
  || fail "cannot prepare flattened copy for searching"
for pat in "${ANCHORS[@]}"; do
  LC_ALL=C grep -qaP "$pat" "$TMP/stalwart.flat" \
    || fail "license public key anchor not found - not an Enterprise binary?"
done
echo "  license public key anchors present"

# ---------------------------------------------------------------------------
# 2. Boot it and make sure it stays up (a corrupt patch would crash here).
# ---------------------------------------------------------------------------
mkdir -p "$TMP/data" "$TMP/etc"
chmod 777 "$TMP/data" "$TMP/etc"

if [ "$MODE" = "toml" ]; then
  # 0.11.x: a normal TOML config with the license key in it. No listeners are
  # configured so the container does not fight the host for ports 25/443.
  KEY=$(bash "$HERE/../generate-license.sh" --domain example.com --quiet) \
    || fail "could not generate a license key"
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
  CID2=$(docker run -d --entrypoint "$BINARY" \
    -v "$TMP/etc/config.toml":/opt/stalwart-mail/etc/config.toml:ro,Z \
    -v "$TMP/data":/opt/stalwart-mail/data:Z \
    "$IMAGE" --config /opt/stalwart-mail/etc/config.toml) || fail "cannot start $IMAGE"
else
  # 0.16.x: --config takes the data-store settings document.
  echo '{"@type":"RocksDb","path":"/var/lib/stalwart/data"}' > "$TMP/etc/config.json"
  CID2=$(docker run -d --entrypoint "$BINARY" \
    -e STALWART_HOSTNAME=mail.example.com \
    -v "$TMP/etc/config.json":/etc/stalwart/config.json:ro,Z \
    -v "$TMP/data":/var/lib/stalwart:Z \
    "$IMAGE" --config /etc/stalwart/config.json) || fail "cannot start $IMAGE"
fi
CIDS="$CIDS $CID2"

LICENSE_OK=0
for _ in $(seq 1 20); do
  state=$(docker inspect --format '{{.State.Status}}' "$CID2" 2>/dev/null)
  if [ "$state" != "running" ]; then
    echo "--- container log ---"
    docker logs "$CID2" 2>&1 | tail -20
    fail "patched server exited (state: $state)"
  fi
  logs=$(docker logs "$CID2" 2>&1)
  case "$logs" in
    *"license key is valid"*)
      LICENSE_OK=1
      break
      ;;
    *"Failed to validate license key"*)
      echo "--- container log ---"
      printf '%s\n' "$logs" | tail -20
      fail "patched binary still rejects the license key"
      ;;
  esac
  sleep 2
done
echo "  patched server boots and stays running"

if [ "$MODE" = "toml" ]; then
  [ "$LICENSE_OK" = "1" ] || fail "no 'license key is valid' event within 40s"
  echo "  license key accepted at runtime (Enterprise Edition active)"
fi

echo "PATCH_OK: $IMAGE ($BINARY, mode=$MODE)"
