"""For every collected Stalwart version, fetch its license.rs and work out the
discriminant index of LicenseError::Validation.

The variant order is NOT stable across the 0.9 -> 0.16 history: a field-carrying
DomainMismatch/HostnameMismatch variant sits at position 1 in 0.9/0.10 but at
position 2 from 0.11 on, which shifts Validation from 3 to 4.

Writes enum_index.json: {"<repo>:<tag>": {"index": n, "variants": [...]}}
"""
import json
import re
import urllib.error
import urllib.request

PATHS = [
    "crates/common/src/enterprise/license.rs",
    "crates/enterprise/src/license.rs",
]
REPO_OF = {"mail-server": "stalwartlabs/mail-server", "stalwart": "stalwartlabs/stalwart"}


def fetch(repo, tag, path):
    url = f"https://raw.githubusercontent.com/{repo}/{tag}/{path}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "curl/8"})
        with urllib.request.urlopen(req, timeout=30) as fh:
            return fh.read().decode("utf-8", "replace")
    except urllib.error.HTTPError:
        return None
    except Exception:
        return None


def variants_of(src):
    m = re.search(r"pub enum LicenseError\s*\{(.*?)\n\}", src, re.S)
    if not m:
        return None
    body = m.group(1)
    out = []
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("//") or line.startswith("#"):
            continue
        mm = re.match(r"([A-Z][A-Za-z0-9_]*)", line)
        if mm:
            out.append(mm.group(1))
    return out


recs = json.load(open("lic_sites.json"))
result = {}
for r in recs:
    if r.get("error"):
        continue
    repo, tag = REPO_OF[r["repo"]], r["tag"]
    vs = None
    for p in PATHS:
        src = fetch(repo, tag, p)
        if src:
            vs = variants_of(src)
            if vs:
                break
    if not vs:
        result[f"{r['repo']}:{tag}"] = {"index": None, "variants": None}
        print(f"{r['repo']:12s} {tag:9s} enum: NOT PARSED")
        continue
    index = vs.index("Validation") if "Validation" in vs else None
    result[f"{r['repo']}:{tag}"] = {"index": index, "variants": vs}
    print(f"{r['repo']:12s} {tag:9s} Validation index={index}  order={' > '.join(vs)}")

json.dump(result, open("enum_index.json", "w"), indent=1)
print("\nwrote enum_index.json")
