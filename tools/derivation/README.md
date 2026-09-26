# Deriving the pattern table

`patch.sh` ships 102 patterns over 37 labels covering every Stalwart release from
0.9.0 to 0.16.23. They were not written by hand and should not be edited by
hand: this directory holds the tooling that produced them from the published
container images.

Work in a scratch directory (the reference binaries are ~100 MB each and are
gitignored), and run each stage from there.

## Pipeline

```
collect.py      every release image -> bins/<repo>-<tag>, binaries.jsonl
enum_survey.py  each tag's license.rs -> enum_index.json   (Validation index)
survey2.py      bins/ + enum_index.json -> lic_sites.json  (the sites)
gen_table.py    lic_sites.json -> table.sh, table.json     (patterns + ranges)
install_table.py  table.sh -> patch.sh's PATTERNS_X86_64
```

Then validate with the real script, from the repository root:

```
./patch.sh --dry-run <binary>     # one binary: label + site count
./verify_all.sh [bins-dir]        # every binary, serial
./sweep_parallel.sh 8 [bins-dir]  # every binary, parallel (grep-bound)
```

## Stage notes

**`collect.py`** pulls `stalwartlabs/stalwart` and `stalwartlabs/mail-server`
tags, extracts the server binary from each amd64 image and records its sha256,
size, ELF section table and embedded public-key offsets.

**`enum_survey.py`** fetches `crates/common/src/enterprise/license.rs` at every
tag and works out the discriminant index of `LicenseError::Validation`. This
must not be hardcoded: it is 3 for 0.9.0–0.10.5 and 4 from 0.10.6 on, because
`InvalidDomain` and `RenewalFailed` were inserted ahead of it.

**`detect.py`** (imported as a module, no CLI) implements the site detection
that everything else builds on:

- parse the ELF section headers for `.text`'s vaddr/file-offset delta;
- find the embedded Ed25519 public key and its RIP-relative references — these
  are what separate the licence sites from the other Ed25519 users (DKIM);
- a site is `call <verify> ; test al, al ; jcc`. `rel32` displacements are
  read **signed**: reading them unsigned silently loses the sites that live
  before the call target;
- the licence sites are the ones whose fall-through materialises the
  `LicenseError::Validation` discriminant, decoded by following the
  niche-encoded value (`movabs rax, 0x8000000000000000` then `lea r13, [rax+4]`,
  or `movabs rax, 0x8000000000000003` then `inc rax`) across a register rename;
- when the constant is set up far above the call (0.9.x keeps it 563 bytes
  back) a byte-scan look-back finds it by register;
- capstone prints small displacements in decimal (`[r14 + 3]`) and larger ones
  in hex — parse both.

**`survey2.py`** applies that detector per version and picks the licence family
by **pubkey anchoring**: the first Validation-discriminant site after each key
reference. "Largest family" is *wrong* — in 0.16.x an unrelated 8-site family
outnumbers the 4 licence sites, and in 0.9.4 a 4-site family does too. The
anchor window must be generous (0x4000); 0.9.x puts the verify call ~0x27FB
after the key construction.

**`gen_table.py`** turns the sites into `patch.sh` patterns and folds releases
with identical bytes into labels (ranges or comma lists). Two details matter:

- each pattern carries the argument setup before the call **and the first 8
  bytes of the fall-through**. The licence check and a sibling call that
  verifies with the same key share the argument setup, so a pattern that stops
  at the branch matches both, and the declared site count is then unreachable;
- `offset` is the index of the `84` of `test al, al`, computed **per pattern**:
  the context length and the branch form differ, and a global offset lands on a
  wildcard, which `patch.sh` rejects.

Coverage accounting is strict — identical patterns are grouped, each must match
exactly as many places as it has sites, and a merge by wildcarding is only
accepted when the merged pattern matches exactly the sum of its parts. The
script exits without writing anything otherwise.

Finally it simulates `patch.sh`'s own selection (sum of a label's matches ==
that label's declared `sites`) against all 64 binaries and reports any version
where a label other than its own would be selected, or two would tie.

`PREFIX`/`POST` are environment knobs (`PREFIX=16 POST=8` is the shipped
setting). Shorter prefixes fold more releases into one label but make the grep
search slower and eventually ambiguous: at `PREFIX=8` the 0.9.0-0.9.1 pattern
also matches inside 0.12.5/0.13.4/0.14.x and 0.13.4-0.14.1's inside 0.10.7,
which would make `patch.sh` refuse to patch those binaries.

## Why not patch `is_enterprise_edition()`

Bypassing the flag directly would leave the licence unparseable, so
configuration, retention, dashboards and account limits stay locked. The
signature check is patched instead, which makes a *parsed* licence exist. The
rewrite is `test al, al` -> `xor eax, eax` (forces ZF=1, the valid-signature
branch) and deliberately not a branch inversion: an inverted jump would accept
only invalid signatures and reject a genuine licence key.
