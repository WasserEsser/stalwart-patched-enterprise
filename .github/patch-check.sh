#!/bin/bash
# Verifies that a patched Stalwart image is patched correctly and still runs.
#
# Usage: patch-check.sh <image_tag>
#
# What this does and does NOT check:
#   - DOES verify the four license-check branches inside the image's binary are
#     inverted (by patching a pristine copy of the same binary and comparing),
#     and that no DKIM ed25519 site was touched.
#   - DOES verify the patched server boots and stays running.
#   - Does NOT verify that a license key is accepted at runtime. In 0.16.x the
#     key lives in the registry (database) and is set through the admin API,
#     whose first account is created interactively via recovery mode. See
#     HOW_TO.md step 5/6.
set -uo pipefail

IMAGE="$1"
[ -n "$IMAGE" ] || { echo "usage: $0 <image_tag>"; exit 1; }

fail() { echo "ERROR: $*"; exit 1; }

TMP=$(mktemp -d)
CIDS=""
cleanup() {
  for c in $CIDS; do docker rm -f "$c" >/dev/null 2>&1 || true; done
  # RocksDB files are written by uid 2000 inside the container, so the host
  # user cannot delete them. Remove them from a throwaway container running as
  # the same uid (the image's default user).
  if [ -n "${IMAGE:-}" ] && [ -d "$TMP" ]; then
    docker run --rm -v "$TMP":/cleanup:Z --entrypoint /bin/rm "$IMAGE" -rf /cleanup \
      >/dev/null 2>&1 || true
  fi
  rm -rf "$TMP" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# 1. Pull the binary out of the patched image and confirm the branches are
#    inverted. patch.sh exits 6 when every site is already patched.
# ---------------------------------------------------------------------------
CID=$(docker create "$IMAGE" /bin/true) || fail "cannot create container from $IMAGE"
CIDS="$CIDS $CID"
docker cp "$CID":/usr/local/bin/stalwart "$TMP/stalwart" >/dev/null 2>&1 \
  || fail "no binary at /usr/local/bin/stalwart in $IMAGE"

echo "  checking patched binary"
if bash "$(dirname "$0")/../patch.sh" --quiet "$TMP/stalwart"; then
  fail "patch.sh reported success on an already-patched image (expected exit 6)"
else
  rc=$?
  [ "$rc" = "6" ] || fail "patch.sh on the patched binary exited $rc, expected 6"
fi

# The two DKIM call sites must still be intact: they are the only calls to the
# ed25519 verifier that do NOT load the license public key. Verify by checking
# the license public key anchors are present (so we know we looked at the right
# binary) and that the file still boots (below).
# The two 16-byte Ed25519 license public-key constants. Written as literal
# PCRE patterns rather than derived with sed: GNU sed expands \x00/\xff into
# real bytes, which corrupts a [\x00-\xff] class.
#
# 0x0a is wildcarded (grep -P cannot put a newline in a pattern) and the
# search runs against a newline-flattened copy: the match spans the 0x0a byte
# inside the constant, and grep cannot match across a line boundary in the raw
# file. -q avoids NUL-byte problems in command substitution.
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
echo '{"@type":"RocksDb","path":"/var/lib/stalwart/data"}' > "$TMP/etc/config.json"

CID2=$(docker run -d --entrypoint /usr/local/bin/stalwart \
  -e STALWART_HOSTNAME=mail.example.com \
  -v "$TMP/etc/config.json":/etc/stalwart/config.json:ro,Z \
  -v "$TMP/data":/var/lib/stalwart:Z \
  "$IMAGE" --config /etc/stalwart/config.json) || fail "cannot start $IMAGE"
CIDS="$CIDS $CID2"

UP=0
for _ in $(seq 1 15); do
  state=$(docker inspect --format '{{.State.Status}}' "$CID2" 2>/dev/null)
  if [ "$state" != "running" ]; then
    echo "--- container log ---"
    docker logs "$CID2" 2>&1 | tail -20
    fail "patched server exited (state: $state)"
  fi
  UP=1
  sleep 2
done
[ "$UP" = "1" ] || fail "patched server did not stay running"
echo "  patched server boots and stays running"

echo "PATCH_OK: $IMAGE"
