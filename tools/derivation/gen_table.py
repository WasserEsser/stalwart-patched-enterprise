"""Build the patch.sh pattern table from the detected licence sites.

Pattern shape (offset 18 is the 0x84 of `test al, al`, which becomes 0x31):

    16 context bytes | E8 ?? ?? ?? ?? | 84 C0 | branch(opcode + wild disp) | 8 post-branch bytes

The post-branch bytes matter: the licence check and its sibling call (the
licensing-API/renewal path, which verifies with the same key) share the argument
setup, so a pattern that stops at the branch matches both. The sibling's
fall-through is the *success* path, so including it separates them.

Coverage accounting is strict: identical patterns are grouped, each pattern must
match exactly as many places as it has sites, and two patterns may only be
merged (by wildcarding the bytes that differ) when the merged pattern matches
exactly the sum of their coverages.

Writes table.sh / table.json and reports the patch.sh selection simulation.
"""
import json
import re
import sys
from collections import defaultdict

import os

PREFIX = int(os.environ.get("PREFIX", "16"))
POST = int(os.environ.get("POST", "8"))
TEST_OFF = PREFIX + 5
SKIP_SIM = os.environ.get("SKIP_SIM") == "1"
REPLACEMENT = "31"


def site_tokens(data, site):
    """(tokens, offset-of-the-0x84). The offset must be computed per site: the
    context before the call can be shorter than PREFIX (the survey keeps only 13
    bytes), and the branch may be short or near, so a global offset points at a
    wildcard."""
    b = bytes.fromhex(site["before"].replace(" ", ""))[-PREFIX:]
    br = bytes.fromhex(site["branch"].replace(" ", ""))
    blen = 2 if site["branch_kind"] == "short" else 6
    post_off = site["test_file"] + 2 + blen
    post = data[post_off:post_off + POST]
    off = len(b) + 5                       # index of the 0x84 of `84 C0`
    toks = [f"{x:02X}" for x in b]
    toks += ["E8", "??", "??", "??", "??", "84", "C0"]
    if site["branch_kind"] == "short":
        toks += [f"{br[0]:02X}", "??"]
    else:
        toks += [f"{br[0]:02X}", f"{br[1]:02X}", "??", "??", "??", "??"]
    toks += [f"{x:02X}" for x in post]
    return toks, off


_rx_cache = {}


def _matcher(toks):
    """(leading literal run, rest as a byte-level matcher).

    Searching 100 MB binaries with a regex thousands of times is far too slow,
    so anchor on the leading literal run with bytes.find (which is memchr-fast)
    and verify the remainder by hand.
    """
    key = tuple(toks)
    if key in _rx_cache:
        return _rx_cache[key]
    lit, i = [], 0
    while i < len(toks) and toks[i] != "??" and toks[i].lower() != "0a":
        lit.append(bytes.fromhex(toks[i]))
        i += 1
    rest = toks[i:]
    head = b"".join(lit)
    n_lit = len(lit)
    rest_b = [None if (t == "??" or t.lower() == "0a") else bytes.fromhex(t) for t in rest]
    _rx_cache[key] = (head, n_lit, rest_b)
    return _rx_cache[key]


def count(path, toks):
    head, n_lit, rest_b = _matcher(toks)
    data = flat(path)
    if not head:
        return len(_regex_fallback(toks).findall(data))
    total, at = 0, 0
    while True:
        at = data.find(head, at)
        if at < 0:
            break
        pos = at + n_lit
        ok = True
        for t in rest_b:
            if t is None:
                pos += 1
            else:
                if data[pos:pos + len(t)] != t:
                    ok = False
                    break
                pos += len(t)
            if pos > len(data):
                ok = False
                break
        if ok:
            total += 1
        at += 1
    return total


def _regex_fallback(toks):
    key = ("rx", tuple(toks))
    if key not in _rx_cache:
        parts = []
        for t in toks:
            parts.append(rb"[\x00-\xff]" if (t == "??" or t.lower() == "0a")
                         else re.escape(bytes.fromhex(t)))
        _rx_cache[key] = re.compile(b"".join(parts), re.DOTALL)
    return _rx_cache[key]


# One binary at a time: the release binaries are ~100 MB each, so caching the
# flattened copy for all 64 of them exhausts RAM and thrashes.
_CUR = {"path": None, "data": None}


def flat(path):
    if _CUR["path"] != path:
        _CUR["path"] = path
        _CUR["data"] = open(path, "rb").read().replace(b"\n", b"\r")
    return _CUR["data"]


def unload():
    _CUR["path"] = None
    _CUR["data"] = None


def build_groups(data, path, sites):
    """Group identical patterns, verify each matches exactly its group size."""
    by_toks = defaultdict(list)
    for s in sites:
        toks, off = site_tokens(data, s)
        by_toks[tuple(toks)].append((s, off))
    groups = []
    for toks, members in by_toks.items():
        offs = {o for _, o in members}
        if len(offs) != 1:
            raise SystemExit(f"inconsistent offsets in one pattern group: {offs}")
        groups.append({"toks": list(toks), "cov": len(members),
                       "matches": count(path, toks), "off": offs.pop()})
    return groups


def merge(groups, path):
    changed = True
    while changed:
        changed = False
        for i in range(len(groups)):
            for j in range(i + 1, len(groups)):
                a, b = groups[i], groups[j]
                if len(a["toks"]) != len(b["toks"]) or a["off"] != b["off"]:
                    continue
                diff = [k for k in range(len(a["toks"])) if a["toks"][k] != b["toks"][k]]
                if not diff or len(diff) > 6:
                    continue
                cand = list(a["toks"])
                for k in diff:
                    cand[k] = "??"
                cov = a["cov"] + b["cov"]
                if count(path, cand) == cov:
                    groups = [g for k, g in enumerate(groups) if k not in (i, j)]
                    groups.append({"toks": cand, "cov": cov, "matches": cov,
                                   "off": a["off"]})
                    changed = True
                    break
            if changed:
                break
    return groups


def label_for(keys):
    vs = sorted({k[1].lstrip("v") for k in keys}, key=lambda v: [int(x) for x in v.split(".")])
    parts, start, prev = [], vs[0], vs[0]
    for v in vs[1:]:
        a = [int(x) for x in prev.split(".")]
        b = [int(x) for x in v.split(".")]
        if not (a[:2] == b[:2] and b[2] == a[2] + 1):
            parts.append(start if start == prev else f"{start}-{prev}")
            start = v
        prev = v
    parts.append(start if start == prev else f"{start}-{prev}")
    return ",".join(parts)


def main():
    recs = [r for r in json.load(open("lic_sites.json")) if not r.get("error") and r.get("count")]
    per = {}
    for r in recs:
        path = r["path"]
        data = open(path, "rb").read()
        groups = build_groups(data, path, r["sites"])
        groups = merge(groups, path)
        summed = sum(g["cov"] for g in groups)
        matched = sum(g["matches"] for g in groups)
        per[(r["repo"], r["tag"])] = {
            "path": path, "count": r["count"], "groups": groups,
            "ok": summed == r["count"] and matched == r["count"],
            "summed": summed, "matched": matched,
        }
    bad = {k: v for k, v in per.items() if not v["ok"]}
    print(f"versions: {len(per)}   pattern/coverage failures: {len(bad)}")
    for k, v in sorted(bad.items()):
        print(f"   BAD {k[1]}: sites={v['count']} coverage={v['summed']} matches={v['matched']}")
    if bad:
        print("\nrefusing to emit a table that does not account for every site exactly once")
        return 1

    sigs = defaultdict(list)
    for k, v in per.items():
        sigs[tuple(sorted(" ".join(g["toks"]) for g in v["groups"]))].append(k)

    assigned = {}
    table = []
    for sig, keys in sigs.items():
        counts = {per[k]["count"] for k in keys}
        if len(counts) != 1:
            print(f"   NOTE: label for {sorted(k[1] for k in keys)} spans site counts {counts}")
        n = per[keys[0]]["count"]
        label = label_for(keys)
        for k in keys:
            assigned[k] = label
        for g in per[keys[0]]["groups"]:
            table.append((label, n, " ".join(g["toks"]), g["off"]))

    def emit(problems):
        with open("table.sh", "w") as fh:
            for label, n, pat, off in table:
                fh.write(f'    "{label}|{n}|{pat}|{off}|{REPLACEMENT}"\n')
        json.dump([{"label": a, "sites": b, "pattern": c, "offset": d}
                   for a, b, c, d in table],
                  open("table.json", "w"), indent=1)
        print(f"\nwrote table.sh: {len(table)} patterns, {len(labels)} labels")
        for lab in sorted(labels, key=lambda l: [int(x) for x in re.findall(r"\d+", l)][:3]):
            print(f"   {lab:20s} sites={labels[lab][0][0]} patterns={len(labels[lab])}")
        for lab, n, pat, off in table:
            if pat.split()[off] != "84":
                print(f"   OFFSET BUG in {lab}: token {off} is {pat.split()[off]}, not 84")
                return 1
        return 0

    labels = defaultdict(list)
    for label, n, pat, off in table:
        labels[label].append((n, pat.split()))
    if SKIP_SIM:
        print(f"\nSKIP_SIM: {len(table)} patterns, {len(labels)} labels")
        return emit([])

    problems = []
    for k, v in per.items():
        want = assigned[k]
        wins = sorted(lab for lab, plist in labels.items()
                      if sum(count(v["path"], p) for _, p in plist) == plist[0][0] > 0)
        if wins != [want]:
            problems.append((k[1], want, wins))
    print(f"\nselection simulation: {len(problems)} problems")
    for p in problems:
        print(f"   {p[0]}: expected {p[1]}, selected {p[2]}")
    return emit(problems)


if __name__ == "__main__":
    sys.exit(main())
