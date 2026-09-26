#!/usr/bin/env bash
# Sweep every reference binary in parallel. patch.sh searches ~200 MB per run
# (two greps per pattern, 102 patterns), so a serial sweep takes hours; the work
# is CPU-bound inside grep, so it parallelises cleanly.
#
# Usage: sweep_parallel.sh [jobs] [binary-dir]
set -u

JOBS="${1:-8}"
BINS="${2:-$HOME/.hermes/cache/scratch/bins}"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${OUT:-$HOME/.hermes/cache/scratch/sweep}"
rm -rf "$OUT"
mkdir -p "$OUT"

ls "$BINS"/* > "$OUT/all.txt"
split -n "l/$JOBS" "$OUT/all.txt" "$OUT/chunk-"

n=0
for chunk in "$OUT"/chunk-*; do
    n=$((n + 1))
    BINS_LIST="$chunk" "$HERE/verify_all.sh" > "$OUT/result-$n.txt" 2>&1 &
done
wait

cat "$OUT"/result-*.txt | grep -v '^$' > "$OUT/combined.txt"
ok=$(grep -c '^ok' "$OUT/combined.txt" || true)
bad=$(grep -c '^FAIL' "$OUT/combined.txt" || true)
echo "ok=$ok  fail=$bad  (jobs=$JOBS)"
grep '^FAIL' "$OUT/combined.txt" | head -20
[ "$bad" -eq 0 ] && [ "$ok" -eq "$(wc -l < "$OUT/all.txt")" ]
