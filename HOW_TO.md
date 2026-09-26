# HOW TO

Step-by-step for going from the official image to a running patched server
with a license of your own.

Everything below assumes `bash`, `docker` and `xxd` on the host. `:Z` on the
`-v` flags is SELinux relabelling (needed on Fedora/RHEL) and is harmless
elsewhere.

The two product lines differ a lot in how the license is applied, so pick the
section that matches your image:

| | 0.11.x | 0.16.x |
|---|---|---|
| image | `stalwartlabs/mail-server` | `stalwartlabs/stalwart` |
| binary | `/usr/local/bin/stalwart-mail` | `/usr/local/bin/stalwart` |
| runs as | root | `stalwart` (uid 2000), needs `cap_net_bind_service` |
| config | `/opt/stalwart-mail/etc/config.toml` (full TOML) | `/etc/stalwart/config.json` (data-store document only) |
| license key | `[enterprise] license-key` in the TOML | registry property, set via the admin API |
| data | `/opt/stalwart-mail/data` | `/var/lib/stalwart` |

---

## 1. Build the patched image

```bash
git clone <this repo> && cd stalwart-patched-enterprise

# 0.16.x
docker build --build-arg STALWART_IMAGE=stalwartlabs/stalwart:v0.16.23 \
  -t stalwart-patched:0.16.23 .

# 0.11.x
docker build \
  --build-arg STALWART_IMAGE=stalwartlabs/mail-server:v0.11.8 \
  --build-arg STALWART_BINARY=/usr/local/bin/stalwart-mail \
  --build-arg STALWART_USER=root \
  -t stalwart-patched:0.11.8 .
```

Pin a version explicitly — `latest` works but moves under you. Every release
from 0.9.0 to 0.16.23 is in the pattern table (`./patch.sh --list`), so a build
that fails with `Call not found!` (exit 7) means either a release newer than the
table or a pattern regression; check `./patch.sh --dry-run` against the
extracted binary before assuming the first.

## 2. Check the patch landed

```bash
CID=$(docker create stalwart-patched:0.11.8 /bin/true)
docker cp "$CID":/usr/local/bin/stalwart-mail ./stalwart-check   # .16: /usr/local/bin/stalwart
docker rm "$CID" >/dev/null
./patch.sh ./stalwart-check       # expect exit 6 (already patched)
```

Or let the checker do all of it, including booting the image:

```bash
bash .github/patch-check.sh stalwart-patched:0.11.8 /usr/local/bin/stalwart-mail toml
```

## 3. Generate a license key

Use the registrable domain of the hostname the server runs under:

```bash
./generate-license.sh --domain example.com --accounts 1000 > license.key
cat license.key
```

## 4. Start the server

**0.11.x** — write a TOML config containing the key and boot it:

```bash
mkdir -p ./data ./etc
cat > ./etc/config.toml <<EOF
[server]
hostname = "mail.example.com"

[storage]
data = "rocksdb"
fts = "rocksdb"
blob = "rocksdb"
lookup = "rocksdb"
directory = "internal"

[store."rocksdb"]
type = "rocksdb"
path = "/opt/stalwart-mail/data"
compression = "lz4"

[directory."internal"]
type = "internal"
store = "rocksdb"

[tracer."stdout"]
type = "stdout"
level = "info"
ansi = false
enable = true

[enterprise]
license-key = "$(cat license.key)"
EOF

docker run -d --name stalwart \
  -p 443:443 -p 25:25 -p 8080:8080 \
  -v "$PWD/etc/config.toml":/opt/stalwart-mail/etc/config.toml:ro,Z \
  -v "$PWD/data":/opt/stalwart-mail/data:Z \
  stalwart-patched:0.11.8

docker logs -f stalwart
```

That is the whole story for 0.11.x — the key is read straight from the config
file, so jump to step 5. (The upstream entrypoint still initialises
`/opt/stalwart-mail/etc/config.toml` for you if you would rather run it once
without a config and edit the generated file.)

**0.16.x** — the server needs `/var/lib/stalwart` and `/etc/stalwart`
writable, and on first run it bootstraps from `STALWART_HOSTNAME` and writes
its own `/etc/stalwart/config.json`:

```bash
mkdir -p ./data
sudo chown 2000:2000 ./data          # the container runs as uid 2000

docker run -d --name stalwart \
  -e STALWART_HOSTNAME=mail.example.com \
  -p 443:443 -p 25:25 -p 8080:8080 \
  -v "$PWD/data":/var/lib/stalwart:Z \
  -v stalwart-etc:/etc/stalwart \
  stalwart-patched:0.16.23
```

## 5. Apply the license key

**0.11.x** — already done in step 4: the key is the `license-key` value in the
`[enterprise]` table. No admin account, no API call.

**0.16.x** — **the license key does not go into `config.json`**. That file is
parsed strictly as the `DataStore` enum, so anything else is rejected with
`missing field \`@type\``. Settings — including `enterprise.licenseKey` — live
in the registry (the database) and are managed through the admin API/UI
(HTTP basic auth, `api/v1/openapi.yml`).

Because the first admin account is created through recovery mode, this part is
interactive:

1. Create/reset the admin account using the recovery-mode variables the
   binary supports:
   `STALWART_RECOVERY_MODE=1`, `STALWART_RECOVERY_ADMIN=<user>`,
   `STALWART_RECOVERY_MODE_PORT=<port>` (plus
   `STALWART_RECOVERY_MODE_LOG_LEVEL` if you want more output).
2. Sign in to the admin UI/API and set the `licenseKey` property on the
   `Enterprise` singleton (`enterprise` in the registry schema) to the string
   from `license.key`.
3. Restart the server.

## 6. Verify it took effect

Both versions log the outcome at startup. Success looks like:

```
0.11.x: INFO Server licensing event (server.licensing) details = Stalwart
        Enterprise Edition license key is valid, domain = "example.com",
        total = 1000, validFrom = "...", validTo = "..."

0.16.x: Stalwart Enterprise Edition license key is valid
```

Failure modes, and what they mean:

| log message | cause |
|---|---|
| `Failed to validate license key` | signature check still active — the patch did not apply |
| `License is expired` | `valid_to` in the past, or clock skew |
| `License issued to domain "x" does not match "y"` | key issued for a different registrable domain |
| `Invalid domain "..."` | hostname has no registrable domain (e.g. `localhost`, an IP) |
| `Invalid license key parameters` | `accounts == 0`, `valid_from >= valid_to`, empty domain |
| `Failed to decode license key` | not valid base64 (truncated paste) |

Once the success line appears, Enterprise features are gated by the
`is_enterprise_edition()` check, which returns true when an unexpired license
is present.

## 7. New Stalwart version

Every release through 0.16.23 is already covered, so this only comes up for a
release newer than the table. The site addresses move every time, so the
patterns must be re-derived — do not hand-edit existing rows:

```bash
TAG=v0.16.24                      # or a 0.11.x tag with the other image/binary
IMG=stalwartlabs/stalwart
BIN=/usr/local/bin/stalwart

CID=$(docker create "${IMG}:${TAG}" /bin/true)
docker cp "$CID":"$BIN" "./stalwart-${TAG#v}-x86_64"
docker rm "$CID" >/dev/null

./patch.sh --dry-run "./stalwart-${TAG#v}-x86_64"   # expect exit 7 (unknown version)
```

Then either re-run the derivation pipeline in `tools/derivation/` (it collects
the binaries, finds the sites, regenerates the whole table and validates its
selection against every binary), or extend `PATTERNS_X86_64` by hand:

1. Find the two 16-byte `.rodata` constants listed in the README — they are
   version-stable, and the code that loads them *is* the license validator.
2. Follow each load forward to `call <verify> ; test al, al` and the
   conditional after it. The fall-through path materialises
   `LicenseError::Validation`, which is how you tell a license site from an
   unrelated Ed25519 check (DKIM et al.). **That discriminant index is not
   constant**: it is 3 for 0.9.0–0.10.5 and 4 from 0.10.6 on, so read it from
   the release's own enum instead of assuming 4.
3. Anchor the pattern on the argument-loading sequence (`mov edx, 0x20` plus
   the `mov rsi, ...` that loads the public key), **and keep the first 8 bytes
   of the fall-through after the branch**. The licence check and a sibling call
   that verifies with the same key share the argument setup, so a pattern that
   stops at the branch matches both and the declared count becomes unreachable.
   Wildcard the call's relative displacement (`E8 ?? ?? ?? ??`); the
   `[rsp+disp8]` and `[rsp+disp32]` encodings need separate patterns.
4. Set `offset` to the index of the `84` of the `test al, al` **per pattern**
   (the context length and branch form differ) and `replacement` to `31`.
   Add a row with the correct `sites` count; `--dry-run` must report all of
   them before you trust it.
5. Make sure the new patterns do **not** match the other supported versions:
   version selection requires each version's total match count to equal its
   own declared `sites`, and refuses to patch if two versions both qualify.
   This is the check that catches a pattern that is one byte too loose.
6. If a wildcard byte in the pattern happens to be a real `0x0a` in the binary,
   write that token as `0a` rather than `??`: `patch.sh` searches the raw file
   for patterns without it (grep is line-based, so a wildcard cannot span a
   newline) and only searches the newline-flattened copy when the token is
   present. A pattern that needs the flattened copy but omits the token silently
   under-counts, which shows up as exit 7.

## Troubleshooting

**Container exits 139 (SIGSEGV) with no output.** Almost always SELinux: add
`:Z` to the bind mount of the binary (or of the config/data). It is not a bad
patch.

**`Call not found!` for a version that should work.** Check that the binary
really is the Enterprise build (`--features enterprise`, or `enterprise` in the
feature list, is in the upstream Dockerfile; the binary contains the string
`crates/common/src/enterprise/license.rs`). A community build has no license
code at all.

**Key rejected as expired straight away.** `valid_from` must be <= now;
`generate-license.sh` defaults it to now − 1h. Check the container clock.

**0.16.x: `missing field \`@type\`` on startup.** You put settings into the
file passed to `--config`. That file must be only a data-store document
(`{"@type":"RocksDb",...}`); everything else belongs in the registry.
