# HOW TO

Step-by-step for going from the official image to a running patched server
with a license of your own.

Everything below assumes `bash`, `docker` and `xxd` on the host. `:Z` on the
`-v` flags is SELinux relabelling (needed on Fedora/RHEL) and is harmless
elsewhere.

---

## 1. Build the patched image

```bash
git clone <this repo> && cd stalwart-patched-enterprise
docker build -t stalwart-patched:latest .
```

Pin a version explicitly (recommended):

```bash
docker build --build-arg STALWART_IMAGE_TAG=v0.16.23 -t stalwart-patched:0.16.23 .
```

If the build fails with `Call not found!` (exit 7), the tag is a version whose
patterns are not in the table yet — see step 6.

## 2. Check the patch landed

```bash
CID=$(docker create stalwart-patched:latest /bin/true)
docker cp "$CID":/usr/local/bin/stalwart ./stalwart-patched-check
docker rm "$CID" >/dev/null
./patch.sh ./stalwart-patched-check     # expect exit 6 (already patched)
```

## 3. Generate a license key

Use the registrable domain of the hostname the server will run under:

```bash
./generate-license.sh --domain example.com --accounts 1000 > license.key
cat license.key
```

## 4. Start the server

The server needs the data directory and `/etc/stalwart` writable. On first run
Stalwart bootstraps from `STALWART_HOSTNAME` and writes its own
`/etc/stalwart/config.json` (the data-store document):

```bash
mkdir -p ./data
sudo chown 2000:2000 ./data          # the container runs as uid 2000

docker run -d --name stalwart \
  -e STALWART_HOSTNAME=mail.example.com \
  -p 443:443 -p 25:25 -p 8080:8080 \
  -v "$PWD/data":/var/lib/stalwart:Z \
  -v stalwart-etc:/etc/stalwart \
  stalwart-patched:latest

docker logs -f stalwart
```

## 5. Apply the license key

In 0.16.x **the license key does not go into `config.json`**. That file is
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

The license state is logged at startup by `log_license_details()` (called from
`crates/main/src/main.rs`). A working patch with a valid-for-this-domain key
prints:

```
Stalwart Enterprise Edition license key is valid
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

Once the success line appears, Enterprise features are gated by
`Server::is_enterprise_edition()`, which returns true when an unexpired
license is present.

## 7. New Stalwart version

The four branch sites move, so the patterns must be re-derived:

```bash
TAG=v0.16.24
CID=$(docker create "stalwartlabs/stalwart:${TAG}" /bin/true)
docker cp "$CID":/usr/local/bin/stalwart "./stalwart-${TAG#v}-x86_64"
docker rm "$CID" >/dev/null

./patch.sh --dry-run "./stalwart-${TAG#v}-x86_64"   # expect exit 7 (unknown version)
```

Then locate the sites and extend `PATTERNS_X86_64`:

1. Find the two 16-byte `.rodata` constants listed in the README — they are
   version-stable, and the code that loads them *is* the license validator.
2. The `call` immediately before `test al, al` / `je` in each copy is the
   Ed25519 verify. Ignore copies that never load the license key (DKIM).
3. Record the two anchor prefixes (`mov edi,1; mov edx,0x20; mov rsi,rbx` and
   the `[rsp+0x38]` variant) and the branch bytes that follow the wildcarded
   call.
4. Add a row with the correct `sites` count; `--dry-run` must report all of
   them before you trust it.

## Troubleshooting

**Container exits 139 (SIGSEGV) with no output.** Almost always SELinux: add
`:Z` to the bind mount of the binary. It is not a bad patch.

**`Call not found!` for a version that should work.** Check the binary really
is the Enterprise build (`--features enterprise` is in the upstream Dockerfile;
the binary contains `crates/common/src/enterprise/license.rs`). A community
build has no license code at all.

**Key rejected as expired straight away.** `valid_from` must be <= now;
`generate-license.sh` defaults it to now − 1h. Check the container clock.
