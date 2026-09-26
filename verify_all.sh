#!/usr/bin/env bash
#
# Validate patch.sh against every reference binary collected from the published
# container images (bins/<repo>-<tag>; 64 builds from 0.9.0 to 0.16.23).
#
# For each binary the patch script must
#   * detect a version label that covers that tag,
#   * report the expected number of validator sites, and
#   * exit 0 under --dry-run.
#
# Usage: verify_all.sh [binary-dir]
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
BINS="${1:-$HOME/.hermes/cache/scratch/bins}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

if [ ! -d "$BINS" ]; then
    echo "No binary directory at '$BINS'" >&2
    exit 1
fi

# Optional: BINS_LIST names the binaries to check, one per line, so several
# instances can sweep the whole set in parallel (each run is grep-bound).
if [ -n "${BINS_LIST:-}" ]; then
    mapfile -t BIN_FILES < "$BINS_LIST"
else
    BIN_FILES=("$BINS"/*)
fi

# tag -> expected site count, from the per-version survey
declare -A SITES=(
    [0.9.0]=1 [0.9.1]=1 [0.9.2]=2 [0.9.3]=1 [0.9.4]=2
    [0.10.0]=2 [0.10.1]=2 [0.10.2]=2 [0.10.3]=2 [0.10.4]=2 [0.10.5]=2
    [0.10.6]=4 [0.10.7]=3
    [0.11.0]=4 [0.11.1]=4 [0.11.2]=4 [0.11.3]=4 [0.11.4]=4 [0.11.6]=4 [0.11.7]=4 [0.11.8]=4
    [0.12.0]=3 [0.12.1]=3 [0.12.2]=3 [0.12.3]=3 [0.12.4]=3 [0.12.5]=3
    [0.13.0]=3 [0.13.1]=3 [0.13.2]=3 [0.13.3]=3 [0.13.4]=4
    [0.14.0]=4 [0.14.1]=4
    [0.15.0]=4 [0.15.1]=4 [0.15.2]=4 [0.15.3]=4 [0.15.4]=4 [0.15.5]=4
    [0.16.0]=4 [0.16.1]=4 [0.16.2]=4 [0.16.3]=4 [0.16.4]=4 [0.16.5]=4
    [0.16.6]=4 [0.16.7]=4 [0.16.8]=4 [0.16.9]=4 [0.16.10]=4 [0.16.11]=4
    [0.16.12]=4 [0.16.13]=4 [0.16.14]=4 [0.16.15]=4 [0.16.16]=4 [0.16.17]=4
    [0.16.18]=4 [0.16.19]=4 [0.16.20]=4 [0.16.21]=4 [0.16.22]=4 [0.16.23]=4
)

# version comparison via sort -V
le() { [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" = "$1" ]; }

# Is <tag> covered by any label in the comma-separated list?
covers() {
    local labels="$1" tag="$2" lab lo hi
    local IFS=','
    for lab in $labels; do
        if [ "$lab" = "$tag" ]; then
            return 0
        fi
        case "$lab" in
            *-*)
                lo="${lab%%-*}"
                hi="${lab##*-}"
                if le "$lo" "$tag" && le "$tag" "$hi"; then
                    return 0
                fi
                ;;
        esac
    done
    return 1
}

pass=0
fail=0
failed_list=""

for bin in "${BIN_FILES[@]}"; do
    name="$(basename "$bin")"
    tag="${name#mail-server-}"
    tag="${tag#stalwart-}"
    tag="${tag#v}"
    want="${SITES[$tag]:-}"

    if [ -z "$want" ]; then
        echo "SKIP $tag (no expectation recorded)"
        continue
    fi

    cp "$bin" "$WORK/work"
    chmod u+w "$WORK/work"

    out="$("$HERE/patch.sh" --dry-run "$WORK/work" 2>&1)"
    rc=$?

    if [ "$rc" -ne 0 ]; then
        echo "FAIL $tag: patch.sh exited $rc"
        printf '%s\n' "$out" | tail -4 | sed 's/^/       /'
        fail=$((fail + 1)); failed_list="$failed_list $tag"
        continue
    fi

    got_version="$(printf '%s\n' "$out" | sed -n 's/.*Detected version: *//p' | head -1)"
    got_sites="$(printf '%s\n' "$out" | sed -n 's/.*check found: \([0-9]*\) site.*/\1/p' | head -1)"

    if [ -z "$got_version" ]; then
        echo "FAIL $tag: no version detected"
        printf '%s\n' "$out" | tail -4 | sed 's/^/       /'
        fail=$((fail + 1)); failed_list="$failed_list $tag"
        continue
    fi
    if [ "$got_sites" != "$want" ]; then
        echo "FAIL $tag: expected $want site(s), found ${got_sites:-none} (label $got_version)"
        fail=$((fail + 1)); failed_list="$failed_list $tag"
        continue
    fi
    if ! covers "$got_version" "$tag"; then
        echo "FAIL $tag: detected label '$got_version' does not cover this tag"
        fail=$((fail + 1)); failed_list="$failed_list $tag"
        continue
    fi

    echo "ok   $tag: label $got_version, $got_sites site(s)"
    pass=$((pass + 1))
done

echo
echo "passed: $pass   failed: $fail"
[ -n "$failed_list" ] && echo "failures:$failed_list"
[ "$fail" -eq 0 ]
