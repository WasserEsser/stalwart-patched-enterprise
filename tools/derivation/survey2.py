"""Locate the Enterprise license signature checks in every collected binary.

Selection rule (in order):
  1. candidates are `call <f> ; test al, al ; <flag-safe>... ; jcc` sites whose
     fall-through builds *this version's own* LicenseError::Validation
     discriminant -- 3 up to 0.10.5, 4 from 0.10.6 on, per enum_index.json;
  2. every inlined copy of the check constructs the embedded key first, so the
     license site is the first candidate after each pubkey reference;
  3. the verify function is the target those anchored candidates share.

Writes lic_sites.json.
"""
import glob
from collections import Counter
import hashlib
import json
import os
import sys
from concurrent.futures import ProcessPoolExecutor

import detect as D

ENUM_INDEX = json.load(open("enum_index.json"))
WINDOW = 0x4000


def key_targets(data, secs):
    """vaddrs of the embedded key halves / full key."""
    out = set()
    for probe in (D.PUBKEY, D.PUBKEY[:16], D.PUBKEY[16:]):
        start = 0
        while True:
            o = data.find(probe, start)
            if o < 0:
                break
            start = o + 1
            for name, (va, off, sz) in secs.items():
                if off <= o < off + sz:
                    out.add(va + (o - off))
                    break
    return out


def one(path):
    name = os.path.basename(path)
    repo, tag = "stalwart", name
    for pre, r in (("mail-server-", "mail-server"), ("stalwart-", "stalwart")):
        if name.startswith(pre):
            repo, tag = r, name[len(pre):]
            break
    enum_idx = ENUM_INDEX.get(f"{repo}:{tag}", {}).get("index")
    try:
        data = open(path, "rb").read()
        secs = D.sections(path)
        tva, toff, tsize = secs[".text"]
        cands = D.find_sites(data, tva, toff, tsize, (enum_idx,)) if enum_idx is not None else []
        refs = D.pubkey_refs(data, tva, toff, tsize, key_targets(data, secs))

        votes = Counter()
        anchored = {}
        for r in refs:
            near = [c for c in cands if 0 <= c["call_va"] - r <= WINDOW]
            if not near:
                continue
            c = min(near, key=lambda c: c["call_va"] - r)
            votes[c["target"]] += 1
            anchored.setdefault(c["target"], set()).add(c["call_va"])
        main = votes.most_common(1)[0][0] if votes else None
        sites = [c for c in cands if c["target"] == main]

        out = []
        for s in sites:
            coff = s["call_file"]
            out.append({
                "test_va": s["test_va"],
                "test_file": s["test_file"],
                "call_va": s["call_va"],
                "branch_kind": s["branch_kind"],
                "disc": s["disc"],
                "anchored": s["call_va"] in anchored.get(main, set()),
                "before": data[coff - 13:coff].hex(" "),
                "test": data[s["test_file"]:s["test_file"] + 2].hex(" "),
                "branch": data[s["test_file"] + 2:s["test_file"] + 8].hex(" "),
            })
        runners = [t for t, n in votes.most_common() if t != main and n == votes[main]]
        return {
            "repo": repo, "tag": tag, "path": path,
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
            "enum_index": enum_idx,
            "verify": hex(main) if main else None,
            "refs": len(refs),
            "votes": {hex(k): v for k, v in votes.items()},
            "tie": [hex(t) for t in runners],
            "count": len(out),
            "anchored": sum(1 for s in out if s["anchored"]),
            "cand_groups": {hex(t): n for t, n in Counter(c["target"] for c in cands).most_common(4)},
            "sites": out,
        }
    except Exception as exc:                                   # noqa: BLE001
        return {"repo": repo, "tag": tag, "path": path, "error": f"{type(exc).__name__}: {exc}"}


if __name__ == "__main__":
    files = sorted(glob.glob("bins/*"))
    if len(sys.argv) > 1:
        files = [f for f in files if any(a in f for a in sys.argv[1:])]
    with ProcessPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(one, files))
    results.sort(key=lambda r: (r["repo"], [int(x) for x in r["tag"].lstrip("v").split(".")]))
    with open("lic_sites.json", "w") as fh:
        json.dump(results, fh, indent=1)
    for r in results:
        if r.get("error"):
            print(f"{r['repo']:12s} {r['tag']:9s} ERROR {r['error']}")
        else:
            flag = f"  TIE={r['tie']}" if r["tie"] else ""
            print(f"{r['repo']:12s} {r['tag']:9s} idx={r['enum_index']} count={r['count']:2d} "
                  f"anch={r['anchored']:2d}/{len(r['sites'])} refs={r['refs']:2d} "
                  f"verify={str(r['verify']):12s} votes={r['votes']} cands={r['cand_groups']}{flag}")
