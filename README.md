# stalwart-patched-enterprise

Patches the Stalwart Mail Server binary so that Enterprise license keys are
accepted without a valid Ed25519 signature.

Same approach as [mattermost-patched-enterprise](https://github.com/WasserEsser/mattermost-patched-enterprise):
a byte-pattern table per version, applied by a dependency-light `patch.sh`,
plus a `Dockerfile` that builds a patched image from the official one.

**Not affiliated with Stalwart Labs. For research/personal use.** See the
[legal note](#legal-note) at the bottom.

---

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

`aws_lc_rs` returns a Rust `Result<(), _>` whose discriminant is tested
immediately afterwards, so the compiler emits `test al, al` + a conditional
jump. Inverting that jump makes the *failure* path fall into the "signature
valid" branch — i.e. any signature is accepted, exactly like the Mattermost
patch.

The embedded public key (`LicenseValidator::new()`) is:

```
76 0A B6 23 59 6F 0B 3C 9A 2F CD 7F 6B E5 37 68
48 36 8D 0E 61 DB 02 04 77 8F 9C 0A 98 D8 20 C2
```

It is stored as **two separate 16-byte `.rodata` constants**, not one
contiguous 32-byte blob, so `patch.sh` uses them only as a sanity anchor to
confirm the binary is an Enterprise build.

## The patch

Stalwart 0.16.23 (x86-64) contains **four** inlined copies of this validator
(`LicenseKey::new` is inlined into its call sites). All four must be patched:

| branch address | bytes        | notes                        |
|----------------|--------------|------------------------------|
| `0x14b9af2`    | `74 38`      | `je` -> `jne` (`75`)         |
| `0x2429beb`    | `0f 84 ...`  | `je` -> `jne` (`0f 85`)      |
| `0x4842932`    | `74 38`      | `je` -> `jne` (`75`)         |
| `0x484379b`    | `0f 84 ...`  | `je` -> `jne` (`0f 85`)      |

The binary contains **six** calls to the same Ed25519 verify routine. Two of
them never load the license public key and are unrelated (DKIM signature
verification); patching those would break mail verification, so the patterns
anchor on the argument-loading sequence that is unique to the license sites:

```
BF 01 00 00 00 BA 20 00 00 00 48 89 DE        ; mov edi,1 ; mov edx,0x20 ; mov rsi,rbx
BF 01 00 00 00 BA 20 00 00 00 48 8B 74 24 38  ; mov edi,1 ; mov edx,0x20 ; mov rsi,[rsp+0x38]
```

The call's relative displacement is wildcarded (`E8 ?? ?? ?? ??`) so the
patterns survive unrelated code shifts, and each pattern legitimately matches
two sites (hence the `sites` column in the table, which is verified before
anything is written).

Note that this **only** bypasses the signature. The key is still fully
parsed and enforced: it must be well-formed, must not be expired, and must be
issued for your own domain. `generate-license.sh` produces such a key.

## Quick start

### Patch an extracted binary

```bash
./patch.sh /path/to/stalwart          # patch
./patch.sh --dry-run /path/to/stalwart  # show what would change
./patch.sh /path/to/stalwart          # re-run: exit 6, "already patched"
./patch.sh --list                     # supported versions
```

Exit codes: `0` ok, `6` already patched, `7` unsupported version, `10` patch
verification failed, `11`/`12` not ELF / unsupported arch.

### Build a patched image

```bash
docker build -t stalwart-patched:latest .
docker build --build-arg STALWART_IMAGE_TAG=v0.16.23 -t stalwart-patched:0.16.23 .
```

The binary is replaced inside the official image; the upstream
`cap_net_bind_service` file capability is reapplied (Docker `COPY` does not
carry file capabilities, and without it the unprivileged `stalwart` user
cannot bind ports 25/443/...).

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

all base64-encoded (standard alphabet, no line breaks).

### Applying the license — important for 0.16.x

In Stalwart 0.16.x **the file passed to `--config` is not the full
configuration**. It is the data-store settings document, which the server
writes itself on first run and which is parsed strictly as a tagged
`DataStore` enum (`crates/registry/src/schema/structs.rs`), e.g.:

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

Be aware of what has and has not been checked for 0.16.23:

**Verified**

- The four branch bytes are the `LicenseError::Validation` guard: the
  fall-through stores discriminant index `4`, and `LicenseError` is declared
  `Expired, InvalidDomain, DomainMismatch, Parse, Validation, Decode, ...` —
  the other error paths in the same function store the indices matching
  `Expired` (0), `Parse` (3), `Decode` (5) and `InvalidParameters` (6).
- The two excluded verify call sites never load the license public key.
- `patch.sh` inverts exactly the four intended bytes (read back from disk),
  leaves the two DKIM sites untouched, and exits 6 on a second run.
- A byte-level diff of the pristine and patched binary shows **exactly four
  differing bytes in the whole 105 MB file**, all at the four license
  branches; the two unrelated ed25519 (DKIM) branches are byte-identical:

  ```
  $ cmp -l stalwart-0.16.23-x86_64 /tmp/stalwart-test
  21727987 164 165     # 0x14b9af2  74 -> 75
  37915628 204 205     # 0x2429beb  84 -> 85
  75766067 164 165     # 0x4842932  74 -> 75
  75769756 204 205     # 0x484379b  84 -> 85
  ```
- `generate-license.sh` output round-trips: correct little-endian fields,
  domain, and a non-expired validity window.
- The patched binary **boots and stays running** in the official image,
  identically to the pristine binary.
- The whole chain — `docker build` (which runs `patch.sh` in the patcher
  stage) through to the server starting — is exercised by
  [.github/patch-check.sh](.github/patch-check.sh), which passes for 0.16.23:

  ```bash
  docker build -t sw-test:local .
  bash .github/patch-check.sh sw-test:local   # prints PATCH_OK
  ```

**Not verified**

- That a running patched server *accepts* a generated key. The license is
  applied through the registry (see above), which needs an admin account;
  the first admin is created via recovery mode, which is not scriptable in a
  few commands. **Do this manually once** and confirm the log line
  `Stalwart Enterprise Edition license key is valid`
  (`log_license_details()`, called from `main.rs`).
- ARM64. No patterns have been derived, so `patch.sh` exits 7 on aarch64
  rather than guessing. `--list` prints `(none yet)`.

## Adding a new version

The patterns are version-specific. To add a version:

1. Extract the binary from the tag
   (`docker create <tag> /bin/true` then `docker cp <id>:/usr/local/bin/stalwart .`).
2. Find the four branch sites (the two anchor prefixes above, then the
   `84 C0 74` / `84 C0 0F 84` that follows the wildcarded call).
3. Add entries to `PATTERNS_X86_64` with the correct `sites` count.
4. `./patch.sh --dry-run` must report `4 site(s) total, 4 to patch`.

## Pitfalls worth knowing

- **SELinux**: on Fedora, bind-mounting a patched binary into the container
  needs `:Z` (e.g. `-v /path/stalwart:/usr/local/bin/stalwart:ro,Z`).
  Without it the container dies with SIGSEGV (exit 139) and *no output at
  all*, which looks exactly like a bad patch. It is not.
- **`grep -P` and binary data**: a literal `0x0a` byte in a pattern is
  unmatchable (grep splits lines on it), so `patch.sh` wildcards it; and
  without `LC_ALL=C` grep cannot match NUL-containing patterns at all. Both
  are handled, but they are the two reasons a pattern silently "isn't found".
- **`.text` has a +0x1000 vaddr/file-offset delta** in this binary
  (addr `0x13dc7c0`, offset `0x13db7c0`); mixing the two yields no matches.

## Legal note

The `enterprise/` sources and the license mechanism are covered by the
Stalwart Enterprise License Agreement (`LICENSES/LicenseRef-SEL.txt`), whose
text explicitly prohibits tampering with the license validation. This
repository is published for interoperability research and personal
experimentation. If you use Stalwart Enterprise in production, buy a license.
