# stalwart-patched-enterprise

Patches the Stalwart Mail Server binary so that Enterprise license keys are
accepted without a valid Ed25519 signature.

Same approach as [mattermost-patched-enterprise](https://github.com/WasserEsser/mattermost-patched-enterprise):
a byte-pattern table per version, applied by a dependency-light `patch.sh`,
plus a `Dockerfile` that builds a patched image from the official one.

**Not affiliated with Stalwart Labs. For research/personal use.** See the
[legal note](#legal-note) at the bottom.

---

## Supported versions

| Stalwart          | image                        | binary                          | config                          | sites |
|-------------------|------------------------------|---------------------------------|---------------------------------|-------|
| 0.16.x (tested 0.16.23) | `stalwartlabs/stalwart`   | `/usr/local/bin/stalwart`        | `/etc/stalwart/config.json`     | 4     |
| 0.11.x (tested 0.11.8)  | `stalwartlabs/mail-server`| `/usr/local/bin/stalwart-mail`   | `/opt/stalwart-mail/etc/config.toml` | 4 |

x86-64 only so far; `patch.sh --list` prints what is compiled in. ARM64
patterns have not been derived, so `patch.sh` exits 7 on aarch64 rather than
guessing.

Note that 0.11.x and 0.16.x are very different products by now: the older one
is `stalwartlabs/mail-server` with a single `stalwart-mail` binary, a TOML
config and runs as root, the newer one is `stalwartlabs/stalwart` with a
registry database, a JSON data-store document and runs as an unprivileged
user. The two share the license format and the embedded public key, but not
the code layout, so each has its own patterns.

## How the license check works

Stalwart validates Enterprise licenses **offline**. `crates/common/src/enterprise/license.rs`
(a `LicenseRef-SEL` file, not open source) does:

1. base64-decode the key,
2. parse it as `valid_from (u64 LE) | valid_to (u64 LE) | accounts (u32 LE) |
   domain_len (u32 LE) | domain | signature`,
3. reject bad parameters (`valid_from == 0`, `valid_to == 0`,
   `valid_from >= valid_to`, `accounts == 0`, empty domain),
4. **verify the signature** against a public key compiled into the binary,
5. reject the key when expired.

Then `LicenseKey::new()` additionally requires the key's domain to have the
same registrable domain (Public Suffix List reduced) as the server hostname.

The signature check is:

```rust
self.public_key
    .verify(&key[..(U64_LEN * 2) + (U32_LEN * 2) + domain_len], signature)
    .map_err(|_| LicenseError::Validation)?;
```

The verify returns a Rust `Result<(), _>` whose discriminant lands in `al`
(0 = `Ok`, i.e. the signature is valid), so the compiler emits

```
call <verify> ; test al, al ; je <signature-valid path>
```

and the **fall-through path materialises `LicenseError::Validation`**. That is
how each site is identified: the code that runs when the conditional is *not*
taken stores discriminant index `4`, and `LicenseError` is declared
`Expired, InvalidDomain, DomainMismatch, Parse, Validation, Decode, ...`.

The embedded public key (`LicenseValidator::new()`) is the same in both
versions:

```
76 0A B6 23 59 6F 0B 3C 9A 2F CD 7F 6B E5 37 68
48 36 8D 0E 61 DB 02 04 77 8F 9C 0A 98 D8 20 C2
```

It is stored as **two separate 16-byte `.rodata` constants**, not one
contiguous 32-byte blob, so `patch.sh` uses them only as a sanity anchor to
confirm the binary is an Enterprise build.

## The patch

`patch.sh` rewrites the **test** in front of the conditional:

```
84 C0   test al, al     ->     31 C0   xor eax, eax
```

`xor eax, eax` sets `ZF=1` unconditionally, so the `je` always takes the
signature-valid path: the check always succeeds, and `al` ends up holding
exactly the value it held in the original valid-signature case.

This is deliberately **not** a branch inversion (`74` -> `75`,
`0F 84` -> `0F 85`). Inverting accepts only *invalid* signatures and sends a
genuine signature down the `LicenseError::Validation` path — a patched binary
would reject a real license, which is a nasty surprise on a server that
already has one. Forcing the test accepts both.

Note that this **only** bypasses the signature. The key is still fully parsed
and enforced: it must be well-formed, must not be expired, and must be issued
for your own domain. `generate-license.sh` produces such a key.

### Stalwart 0.16.23 (x86-64, `stalwartlabs/stalwart`)

Four inlined copies of `LicenseKey::new`. The patched bytes:

| test byte    | encoding      | notes                                   |
|--------------|---------------|-----------------------------------------|
| `0x14b9af0`  | `84 C0 74 38` | short `je`                              |
| `0x2429be8`  | `84 C0 0F 84` | near `je`                               |
| `0x4842930`  | `84 C0 0F 84` | near `je`                               |
| `0x4843798`  | `84 C0 0F 84` | near `je`                               |

The binary contains **six** calls to the same Ed25519 verify routine. Two
never load the license public key and are unrelated (DKIM), so the patterns
anchor on the argument-loading sequence unique to the license sites:

```
BF 01 00 00 00 BA 20 00 00 00 48 89 DE        ; mov edi,1 ; mov edx,0x20 ; mov rsi,rbx
BF 01 00 00 00 BA 20 00 00 00 48 8B 74 24 38  ; mov edi,1 ; mov edx,0x20 ; mov rsi,[rsp+0x38]
```

Each pattern legitimately matches two sites (hence the `sites` column, which
is verified before anything is written).

### Stalwart Mail Server 0.11.8 (x86-64, `stalwartlabs/mail-server`)

Four inlined copies again, but the stack-slot encodings differ per inlining,
so three patterns are needed:

| test byte    | encoding         | notes                     |
|--------------|------------------|---------------------------|
| `0x1949286`  | `84 C0 0F 84`    | `mov rsi,[rsp+disp8]`     |
| `0x194d34b`  | `84 C0`, short `je` | `mov rsi,[rsp+0x20]`   |
| `0x272abd7`  | `84 C0 0F 84`    | `mov rsi,[rsp+disp32]`    |
| `0x2737004`  | `84 C0 0F 84`    | `mov rsi,[rsp+disp8]`     |

Four callers of the verify routine (`0x2cdb7a0`), all four of them license
sites — but the wildcarded patterns still pin `mov edx, 0x20` (the 32-byte
public key) and the `LicenseError::Validation` discriminant in the
fall-through, which is what makes them specific. One site branches with a
*short* `je` placed a couple of instructions later, so its pattern anchors on
the discriminant that the error path materialises instead.

Note on overlap: the 0.11.8 disp8 pattern is a suffix of the 0.16.23 disp8
pattern, so it also matches the two 0.16.23 disp8 sites. Version selection
compares each version's total match count against its own declared site count
(2 != 4), so only the correct version can ever be selected.

## Quick start

### Patch an extracted binary

```bash
./patch.sh /path/to/stalwart              # patch
./patch.sh --dry-run /path/to/stalwart    # show what would change
./patch.sh /path/to/stalwart              # re-run: exit 6, "already patched"
./patch.sh --list                         # supported versions
```

Exit codes: `0` ok, `6` already patched, `7` unsupported version, `10` patch
verification failed, `11`/`12` not ELF / unsupported arch.

### Build a patched image

```bash
# Stalwart 0.16.x
docker build -t stalwart-patched:latest .

# Stalwart Mail Server 0.11.x
docker build \
  --build-arg STALWART_IMAGE=stalwartlabs/mail-server:v0.11.8 \
  --build-arg STALWART_BINARY=/usr/local/bin/stalwart-mail \
  --build-arg STALWART_USER=root \
  -t stalwart-patched:0.11.8 .
```

The binary is replaced inside the official image. For 0.16.x the upstream
`cap_net_bind_service` file capability is reapplied (Docker `COPY` does not
carry file capabilities, and without it the unprivileged `stalwart` user
cannot bind ports 25/443/...); 0.11.x runs as root and needs nothing.

### Generate a license key

```bash
./generate-license.sh --domain example.com > license.key
./generate-license.sh --domain example.com --accounts 500 --days 3650
```

`--domain` must be the **registrable domain** of the Stalwart hostname: a key
issued for `example.com` is accepted by a server whose hostname is
`mail.example.com` (both sides are reduced with the Public Suffix List). A
hostname without a registrable domain (`localhost`, a bare IP) cannot be
matched and will fail with `InvalidDomain`/`DomainMismatch`.

The generated key format:

| offset | size | field        |
|--------|------|--------------|
| 0      | 8    | `valid_from` (unix seconds, LE) |
| 8      | 8    | `valid_to` (unix seconds, LE)   |
| 16     | 4    | `accounts` (LE)                 |
| 20     | 4    | `domain_len` (LE)               |
| 24     | n    | `domain` (UTF-8)                |
| 24+n   | m    | `signature` (never verified)    |

all base64-encoded (standard alphabet, no line breaks). The format is
identical in 0.11.x and 0.16.x.

### Applying the license

**0.11.x** — the key is a normal configuration value in the TOML file the
server already reads:

```toml
[server]
hostname = "mail.example.com"

[enterprise]
license-key = "<base64 key from generate-license.sh>"
```

At startup the server logs either
`Stalwart Enterprise Edition license key is valid, domain = ...` or a
`Failed to validate license key` build warning. Nothing else is involved.

**0.16.x** — *the file passed to `--config` is not the full configuration*. It
is the data-store settings document, which the server writes itself on first
run and which is parsed strictly as a tagged `DataStore` enum
(`crates/registry/src/schema/structs.rs`), e.g.:

```json
{"@type":"RocksDb","path":"/var/lib/stalwart/data"}
```

If the file is missing, Stalwart bootstraps from environment variables
(`STALWART_HOSTNAME`, `STALWART_PUBLIC_URL`, `STALWART_HTTPS_PORT`, ...) and
creates it. Everything else — including `enterprise.licenseKey` — lives in the
**registry** (the database) and is managed through the admin API/UI, which
uses HTTP basic auth (`api/v1/openapi.yml`).

So the license key is set as the `licenseKey` property of the `Enterprise`
singleton in the registry (`enterprise.licenseKey` in `config.rs`), not in
`config.json`. See [HOW_TO.md](HOW_TO.md).

## Verification status

### 0.11.8 — verified end to end

- `patch.sh` finds **4 sites**, rewrites 4 bytes, and a second run exits 6.
- A byte-level diff against the pristine binary shows **exactly four
  differing bytes** (`84` -> `31`) in the whole 64 MB file, all at the four
  licence sites.
- The license check is **verified at runtime**: the same config and the same
  generated key give opposite results on the pristine and patched binaries.

  ```
  pristine  0.11.8: WARN  Configuration build warning (config.build-warning)
                     details = "WARNING for \"enterprise.license-key\":
                     Failed to validate license key"

  patched   0.11.8: INFO  Server licensing event (server.licensing)
                     details = Stalwart Enterprise Edition license key is valid,
                     domain = "example.com", total = 1000,
                     validFrom = "..." , validTo = "..."
  ```
- The binary is the exact one running on the target server: the pulled image
  digest (`stalwartlabs/mail-server@sha256:a5ce0615...`) matches the image
  digest reported by that host.

### 0.16.23 — verified except license acceptance

- The four patched bytes are the `LicenseError::Validation` guard: the
  fall-through stores discriminant index `4`, and the other error paths in the
  same function store the indices matching `Expired` (0), `Parse` (3),
  `Decode` (5) and `InvalidParameters` (6).
- The two excluded verify call sites never load the license public key.
- A byte-level diff of the pristine and patched binary shows **exactly four
  differing bytes in the whole 105 MB file**, all at the four licence sites;
  the two unrelated ed25519 (DKIM) branches are byte-identical.
- The patched binary **boots and stays running** in the official image,
  identically to the pristine binary.
- **Not verified:** that a running patched 0.16.x server *accepts* a generated
  key. The key lives in the registry and needs an admin account, whose first
  user is created through interactive recovery mode. The 0.11.8 result above
  demonstrates the patch itself is correct; for 0.16.x confirm it manually once
  and look for `Stalwart Enterprise Edition license key is valid`.

### Both

- `generate-license.sh` output round-trips and is accepted by a patched
  0.11.8 server (pinned above).
- The whole chain — `docker build` (which runs `patch.sh` in the patcher
  stage) through to the server starting — is exercised by
  [.github/patch-check.sh](.github/patch-check.sh), which in `toml` mode also
  asserts the runtime license acceptance:

  ```bash
  docker build -t sw-test:local .
  bash .github/patch-check.sh sw-test:local      # 0.16.x, prints PATCH_OK

  docker build --build-arg STALWART_IMAGE=stalwartlabs/mail-server:v0.11.8 \
    --build-arg STALWART_BINARY=/usr/local/bin/stalwart-mail \
    --build-arg STALWART_USER=root -t sw-test:0118 .
  bash .github/patch-check.sh sw-test:0118 /usr/local/bin/stalwart-mail toml
  #   ... license key accepted at runtime (Enterprise Edition active)
  ```

- ARM64: no patterns derived, `patch.sh` exits 7 rather than guessing.

## Adding a new version

The patterns are version-specific. To add a version:

1. Extract the binary from the image
   (`docker create <image>` then `docker cp <id>:<binary> .`).
2. Locate the licence sites: find the two 16-byte public-key constants in
   `.rodata` (each appears exactly once), then the RIP-relative loads of them;
   from each load site follow forward to `call <verify> ; test al, al` and the
   conditional after it. A script that does this for 0.11.8 is a good template:
   resolve the displacement of every `E8` call in the surrounding region and
   keep the ones followed by `84 C0`, then classify each by the discriminant
   materialised on the fall-through path (index `4` = `Validation`).
3. Build the patterns from the argument-loading sequence (`mov edx, 0x20`
   plus the `mov rsi, ...` that loads the public key) and set `offset` to the
   `84` of the `test al, al`, `replacement` to `31`.
4. Add entries to `PATTERNS_X86_64` with the correct `sites` count and run
   `./patch.sh --dry-run` — it must report `4 site(s) total, 4 to patch`, and
   the same patterns must NOT match the other supported versions (or the
   version-selection step will refuse to patch).
5. If the version reads its key from a config file (0.11.x style), verify the
   runtime acceptance as well, with `patch-check.sh ... toml`.

## Pitfalls worth knowing

- **SELinux**: on Fedora, bind-mounting a patched binary into the container
  needs `:Z` (e.g. `-v /path/stalwart:/usr/local/bin/stalwart:ro,Z`).
  Without it the container dies with SIGSEGV (exit 139) and *no output at
  all*, which looks exactly like a bad patch. It is not.
- **`grep -P` and binary data**: a literal `0x0a` byte in a pattern is
  unmatchable (grep splits lines on it), so `patch.sh` wildcards it; without
  `LC_ALL=C` grep cannot match NUL-containing patterns at all; and a pattern
  that spans a `0x0a` byte cannot be matched in the raw file even with a
  wildcard, which is why both `patch.sh` and the checker search a
  newline-flattened copy. These are the reasons a pattern silently "isn't
  found". Note that GNU `sed` expanding `\x00`/`\xff` into real bytes silently
  corrupts a `[\x00-\xff]` character class — build such patterns literally.
- **`.text` has a +0x1000 vaddr/file-offset delta** in both binaries; `.rodata`
  is mapped 1:1. Mixing the two yields no matches.
- **Two ways to bypass, only one is right**: see [The patch](#the-patch).
  Inverting the branch works for a forged key but breaks a genuine one.

## Legal note

The `enterprise/` sources and the license mechanism are covered by the
Stalwart Enterprise License Agreement (`LICENSES/LicenseRef-SEL.txt`), whose
text explicitly prohibits tampering with the license validation. This
repository is published for interoperability research and personal
experimentation. If you use Stalwart Enterprise in production, buy a license.
