"""Pull every Stalwart release image (amd64), extract the server binary, and
record the licence-check sites so a pattern table can be generated.

Writes results as JSON lines to binaries.jsonl and keeps the extracted binaries
under ./bins/<repo>-<tag>.
"""
import json
import os
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

import detect as D

REPO_BIN = {
    "stalwartlabs/stalwart": "/usr/local/bin/stalwart",
    "stalwartlabs/mail-server": "/usr/local/bin/stalwart-mail",
}

MAIL_SERVER = (
    [f"v0.9.{p}" for p in range(5)]
    + [f"v0.10.{p}" for p in range(8)]
    + ["v0.11.0", "v0.11.1", "v0.11.2", "v0.11.3", "v0.11.4", "v0.11.6", "v0.11.7", "v0.11.8"]
)
STALWART = (
    [f"v0.12.{p}" for p in range(6)]
    + [f"v0.13.{p}" for p in range(5)]
    + ["v0.14.0", "v0.14.1"]
    + [f"v0.15.{p}" for p in range(6)]
    + [f"v0.16.{p}" for p in range(24)]
)

JOBS = [
    ("stalwartlabs/mail-server", t, REPO_BIN["stalwartlabs/mail-server"]) for t in MAIL_SERVER
] + [
    ("stalwartlabs/stalwart", t, REPO_BIN["stalwartlabs/stalwart"]) for t in STALWART
]

OUT = os.path.abspath("binaries.jsonl")
BINS = os.path.abspath("bins")
os.makedirs(BINS, exist_ok=True)


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def one(job):
    repo, tag, binpath = job
    dest = os.path.join(BINS, f"{repo.split('/')[1]}-{tag}")
    rec = {"repo": repo, "tag": tag, "binary": binpath, "dest": dest}
    try:
        if not os.path.exists(dest):
            r = run(["docker", "pull", "-q", "--platform", "linux/amd64", f"{repo}:{tag}"])
            if r.returncode != 0:
                rec["error"] = "pull: " + r.stderr.strip()[-200:]
                return rec
            cid = run(["docker", "create", f"{repo}:{tag}"]).stdout.strip()
            if not cid:
                rec["error"] = "create failed"
                return rec
            try:
                r = run(["docker", "cp", f"{cid}:{binpath}", dest])
                if r.returncode != 0:
                    rec["error"] = "cp: " + r.stderr.strip()[-200:]
                    return rec
            finally:
                run(["docker", "rm", "-f", cid])
        import hashlib
        h = hashlib.sha256()
        with open(dest, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        rec["sha256"] = h.hexdigest()
        rec["size"] = os.path.getsize(dest)

        data = open(dest, "rb").read()
        secs = D.sections(dest)
        tva, toff, tsize = secs[".text"]
        rec["text"] = {"vaddr": tva, "off": toff, "size": tsize, "delta": tva - toff}
        h1 = data.find(D.PUBKEY[:16])
        h2 = data.find(D.PUBKEY[16:])
        rec["pubkey_offsets"] = [h1, h2]
        sites = D.find_sites(data, tva, toff, tsize)
        from collections import Counter
        groups = Counter(s["target"] for s in sites)
        rec["target_groups"] = {hex(k): v for k, v in groups.items()}
        main = groups.most_common(1)[0][0] if groups else None
        rec["main_target"] = hex(main) if main else None
        out = []
        for s in sites:
            if s["target"] != main:
                continue
            coff = s["call_file"]
            out.append({
                "test_va": s["test_va"],
                "call_va": s["call_va"],
                "branch_kind": s["branch_kind"],
                "before": data[coff - 16:coff].hex(" "),
                "at": data[coff:coff + 8].hex(" "),
                "branch": data[s["test_file"] + 2:s["test_file"] + 8].hex(" "),
            })
        rec["sites"] = out
        rec["count"] = len(out)
    except Exception as exc:                      # noqa: BLE001
        rec["error"] = f"{type(exc).__name__}: {exc}"
    return rec


with ThreadPoolExecutor(max_workers=6) as pool:
    for rec in pool.map(one, JOBS):
        line = json.dumps(rec, sort_keys=True)
        print(line, flush=True)
        with open(OUT, "a") as fh:
            fh.write(line + "\n")
        status = "ERR " + rec["error"] if rec.get("error") else f"count={rec.get('count')} pubkey={rec.get('pubkey_offsets')}"
        print(f"  {rec['repo'].split('/')[1]:12s} {rec['tag']:9s} {status}", file=sys.stderr, flush=True)
