#!/usr/bin/env bash
#
# Asserts that every reference binary can be patched, i.e. that the vendor key
# is still present as exactly one copy of each half.
#
# Usage: check-coverage.sh [binary-dir]
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
BINS="${1:-$HOME/.hermes/cache/scratch/bins}"
[ -d "$BINS" ] || { echo "No binary directory at '$BINS'" >&2; exit 1; }

ok=0
fail=0
failed=""

for bin in "$BINS"/*; do
    name=$(basename "$bin")
    out=$("$HERE/patch.sh" --dry-run "$bin" 2>&1)
    rc=$?
    halves=$(printf '%s\n' "$out" | grep -c 'would replace 0x')
    if [ "$rc" -ne 0 ] || [ "$halves" -ne 2 ]; then
        echo "FAIL $name (exit $rc, $halves half(es))"
        printf '%s\n' "$out" | sed 's/^/       /'
        fail=$((fail + 1))
        failed="$failed $name"
        continue
    fi
    printf 'ok   %-28s %s\n' "$name" "$(printf '%s\n' "$out" | grep 'would replace 0x' | sed 's/would replace //' | tr '\n' ' ')"
    ok=$((ok + 1))
done

echo
echo "patchable: $ok   failed: $fail"
[ -z "$failed" ] || echo "failures:$failed"
[ "$fail" -eq 0 ]
