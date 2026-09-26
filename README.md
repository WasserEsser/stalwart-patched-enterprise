# Stalwart Enterprise license: swap the public key

Patches a Stalwart Mail Server binary so that it accepts Enterprise license keys
signed with **your own** Ed25519 key, instead of only those signed by the vendor.

Run this only against a server you operate.

## The idea

Stalwart ships an Ed25519 public key inside the binary and verifies its
Enterprise license key with it:

```rust
// crates/common/src/enterprise/license.rs
let public_key = UnparsedPublicKey::new(&ED25519, vec![118, 10, 182, 35, ...]);
public_key.verify(&key[..24 + domain_len], signature)
```

That key is a plain 32-byte constant. Nothing binds it to a key ID, a
fingerprint or a version, and the verification covers exactly

```
valid_from (u64 LE) || valid_to (u64 LE) || accounts (u32 LE) || domain_len (u32 LE) || domain
```

So the whole thing can be signed offline by anyone holding the matching private
key. Replacing those 32 bytes is therefore enough: the binary then validates a
license *you* signed, using its own untouched verifier. Nothing is bypassed — the
signature is genuinely checked, and a license signed with any other key is still
rejected.

## Why not patch the check itself

The obvious alternative is to break the `test al, al` after each call to the
verifier so the failure branch is never taken. That works, but it needs one
pattern per release (this repo used to carry 102 of them across 37 version
labels), re-derived whenever optimisation or inlining shifts, and it leaves the
licensing code path lying to itself.

The key is **the same 32 bytes in every release from 0.9.0 to 0.16.23**, on
x86-64 and aarch64, in both Docker Hub repos (`stalwartlabs/stalwart` and
`stalwartlabs/mail-server`). It always appears exactly twice — as two 16-byte
halves, one copy of each. Verified across all 65 reference binaries
(`./check-coverage.sh`, 23 seconds).

So one constant, not one table:

| | patch the check | swap the key |
|---|---|---|
| Changes per release | a re-derived pattern | none |
| Bytes modified | 1 per call site (1–4 sites) | 32, in `.rodata` |
| aarch64 | needs its own patterns | same two halves |
| License validity | bypassed, fields unverified | real signature, real fields |
| Failure mode upstream | silently matches nothing | loud: no key found (exit 7) |

## Requirements

`bash`, `openssl` (1.1.1+), `xxd`, `base64`, `grep` with `-P`, `dd`, `tr`, and
Docker for the image build. Nothing else — no Python, no build toolchain.

## Quick start

```sh
# 1. Create a key pair. The private key stays here; it is gitignored.
./generate-license.sh --pubkey-only
# -> 8a16557fa53bb5fd0f04f3e91625e2e939543241f0ae609f2541b8202bea1062

# 2. Build a patched image from the official one.
docker build \
  --build-arg LICENSE_PUBKEY="$(./generate-license.sh --pubkey-only)" \
  -t stalwart-patched .

# 3. Mint a license for it.
./generate-license.sh --domain example.com > license.key
```

Then start the patched image with that license (see `HOW_TO.md`). For the older
`stalwartlabs/mail-server` images, add the three extra build args documented at
the top of the `Dockerfile`.

## Usage

```
patch.sh --pubkey <hex|file> [--dry-run] [--quiet] <binary>
patch.sh --help
```

`patch.sh` finds the vendor key, verifies each candidate offset against the raw
bytes, and replaces the halves. It refuses to guess:

| exit | meaning |
|---|---|
| 0 | patched (or would be, with `--dry-run`) |
| 6 | already carries the key you supplied |
| 7 | no license public key found — not an Enterprise build, or the layout changed |
| 8 | only one of the two halves present — refuses to patch an unexpected state |
| 10 | read-back after writing did not match |

Both halves contain a `0x0a` byte, so it searches a newline-flattened copy and
re-checks every hit against the original file; a naive byte search would either
miss them or match the wrong place.

```
generate-license.sh --domain <domain> [--accounts N] [--days N] [--key FILE] ...
generate-license.sh --pubkey-only
generate-license.sh --help
```

The private key (`stalwart-license.key` by default, mode 600) is created on
first use and never leaves the machine. The license is a real base64 Ed25519
structure — payload, then a 64-byte signature — which the generator verifies
against its own public key before printing it.

## Verified

- **Runtime acceptance** (0.11.8, the layout whose key lives in a plain TOML
  config): the patched image logs
  `license key is valid, domain = "example.com", total = 1000, validFrom …,
  validTo …`, and the **official image rejects the identical license**. That
  control is what makes the result meaningful: the signature really is verified.
- **All 65 reference binaries** (every release 0.9.0–0.16.23 from both Docker
  Hub repos, plus the aarch64 build of 0.16.23) contain the key as exactly one
  copy of each half and patch cleanly: `./check-coverage.sh`.
- **Both build paths**: the `Dockerfile`, and `patch.sh` against an extracted
  binary.
- **Idempotency**: a second `patch.sh` run on a patched binary exits 6.
- `./.github/patch-check.sh <image> <binary> toml <original-image> <key>` runs
  the full acceptance plus rejection control; CI calls it on every PR.

## Version support

| Range | Status |
|---|---|
| 0.9.0 – 0.16.23 | supported, both Docker Hub repos, x86-64 and aarch64 |
| 0.3.0 – 0.8.5 | not applicable: no `license.rs`, no key to replace |

`0.12.0` and later keep the license key in the registry rather than a config
file, and set it through the admin API (the first admin account is created
interactively in recovery mode). For those versions the build and the swap are
verified, but acceptance cannot be asserted automatically — see `HOW_TO.md`.

## Layout

```
patch.sh                 replace the embedded public key
generate-license.sh      key pair + license generation (Ed25519 via openssl)
Dockerfile               official image -> patched image
check-coverage.sh        assert every reference binary is patchable
.github/patch-check.sh   verify a patched image (acceptance + rejection control)
.github/workflows/       CI: PR check, nightly newest/oldest tag per line
HOW_TO.md                step-by-step for a running server
```

## Caveats

- **Keep the private key.** It is not a key to anything of yours — it only
  authenticates licenses for binaries patched with its public key — but losing
  it means rebuilding the image from the official one with a new key pair.
- **Upstream can rotate the key.** Then `patch.sh` exits 7 instead of silently
  doing nothing. Fix: put the new 32 bytes in `VENDOR_HALF_A`/`VENDOR_HALF_B`.
- **License renewal** (`license.stalw.art`) fails and is expected to; issue a
  long-dated license (`--days`, default 10 years).
- **Versions 0.12.0+**: acceptance is verified structurally, not at runtime.
