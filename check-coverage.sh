#!/usr/bin/env bash
#
# Report whether a directory of reference binaries can be patched: for each
# binary, assert that the vendor licence public key is present as exactly one
# copy of each 16-byte half.
#
# This is the whole version matrix now. The key is identical in every Stalwart
# release from 0.9.0 on and on both architectures, so there is no per-version
# pattern table to validate - just this one property. A dry run with a throwaway
# public key exercises the real patch.sh search.
#
# Usage: check-coverage.sh [binary-dir]
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
BINS="${1:-$HOME/.hermes/cache/scratch/bins}"

if [ ! -d "$BINS" ]; then
    echo "No binary directory at '$BINS'" >&2
    exit 1
fi

# A throwaway key: the offsets reported are what matters, nothing is written.
THROWAWAY=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff

ok=0
fail=0
failed=""

for bin in "$BINS"/*; do
    name="$(basename "$bin")"
    out=$("$HERE/patch.sh" --dry-run --pubkey "$THROWAWAY" "$bin" 2>&1)
    rc=$?
    if [ "$rc" -ne 0 ]; then
        echo "FAIL $name: patch.sh exited $rc"
        printf '%s\n' "$out" | sed 's/^/       /'
        fail=$((fail + 1))
        failed="$failed $name"
        continue
    fi
    halves=$(printf '%s\n' "$out" | grep -c 'would replace .* at 0x')
    if [ "$halves" -ne 2 ]; then
        echo "FAIL $name: expected 2 key halves, found $halves"
        fail=$((fail + 1))
        failed="$failed $name"
        continue
    fi
    printf 'ok   %-28s %s\n' "$name" \
        "$(printf '%s\n' "$out" | grep 'would replace .* at 0x' | sed 's/.*at 0x/0x/' | tr '\n' ' ')"
    ok=$((ok + 1))
done

echo
echo "patchable: $ok   failed: $fail"
[ -n "$failed" ] && echo "failures:$failed"
[ "$fail" -eq 0 ]
