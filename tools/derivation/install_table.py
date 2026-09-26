"""Install the generated pattern table into patch.sh's PATTERNS_X86_64 array.

Replaces everything between the array's opening paren and its closing paren,
keeping the surrounding script intact.
"""
import re
import subprocess
import sys

import os

TARGET = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "patch.sh")

COMMENT = """# Pattern table: "versions|sites|pattern|offset|replacement"
#
# Derived from every published release binary (0.9.0 - 0.16.23: 64 builds across
# stalwartlabs/mail-server and stalwartlabs/stalwart), not written by hand.
#
#   versions    One or more version labels. A label covers a release when its
#               bytes are identical, so runs of releases collapse into ranges
#               ("0.16.14-0.16.23") or comma lists ("0.11.2-0.11.4,0.11.6").
#   sites       Total number of validator sites for that label. The sum of the
#               matches of the label's patterns (intact + already patched) must
#               equal this number; the script refuses to guess otherwise.
#   pattern     Hex bytes. `??` and a literal `0a` are wildcards. Each site is
#               `call <verify> ; test al, al ; jcc`, and the pattern carries the
#               argument setup before the call plus the first 8 bytes of the
#               fall-through. That trailing context matters: the licence check
#               and the sibling call that verifies with the same key share the
#               argument setup, so a pattern stopping at the branch matches
#               both.
#   offset      Index of the 0x84 byte of `test al, al` inside the pattern.
#   replacement 0x31, turning `test al, al` into `xor eax, eax`.
#
# The replacement forces the zero flag, so the following conditional jump takes
# the signature-valid path. The branch is deliberately NOT inverted: an inverted
# `je` would accept only *invalid* signatures and reject a genuine licence key.
#
# Sites are inlined copies of the Ed25519 signature check, all calling one
# verify routine, so the Ed25519 public key embedded in the binary separates
# them from the other Ed25519 users (DKIM, etc.) during derivation."""


def main():
    lines = [l.strip() for l in open("table.sh") if l.strip()]
    src = open(TARGET).read()
    m = re.search(r"^PATTERNS_X86_64=\(\n(.*?)\n\)$", src, re.S | re.M)
    if not m:
        print("could not find PATTERNS_X86_64 array", file=sys.stderr)
        return 1
    body = "\n".join([COMMENT] + lines)
    out = src[:m.start()] + "PATTERNS_X86_64=(\n" + body + "\n)" + src[m.end():]
    open(TARGET, "w").write(out)
    print(f"installed {len(lines)} patterns")
    r = subprocess.run(["bash", "-n", TARGET], capture_output=True, text=True)
    print("bash -n:", "ok" if r.returncode == 0 else r.stderr)
    return r.returncode


if __name__ == "__main__":
    sys.exit(main())
