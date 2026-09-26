# Stalwart Enterprise licence patch

Stalwart binaries verify Enterprise licence keys against an Ed25519 public key
compiled into them. `patch.sh` replaces that key with one whose private key is
in `generate-license.sh`, so licences from that script are accepted. The
signature check itself is untouched, and a licence signed by anyone else is
still rejected.

## How to run

```sh
# 1. patched image (add the build args from the Dockerfile for 0.9.x - 0.11.x)
docker build -t stalwart-patched .

# 2. licence
./generate-license.sh --domain example.com > license.key

# 3. hand it to the server
#    0.9.x - 0.11.x: [enterprise] license-key = "..." in config.toml
#    0.12.x and later: Administration -> Enterprise, or the admin API
docker logs <container> 2>&1 | grep -i licens
#    -> Server licensing event ... license key is valid, domain = "example.com"
```

To patch a binary directly instead of building an image:

```sh
./patch.sh ./stalwart-mail            # in place
./patch.sh --dry-run ./stalwart-mail  # report offsets, change nothing
```

`--domain` must be the registrable domain of the server hostname
(`example.com` for `mail.example.com`); later versions reject a mismatch.
`--accounts` (default 1000) and `--days` (default 3650) are optional.

## Supported versions

| Range | Status |
|---|---|
| 0.9.0 – 0.16.23 | supported, both Docker Hub repos, x86-64 and aarch64 |
| 0.3.0 – 0.8.5 | not applicable: no `license.rs`, so no key to replace |

The key is identical in every supported build and appears exactly once as two
16-byte halves, which is why no per-version patterns are needed.
`./check-coverage.sh` checks that property over every reference binary.

## Files

```
patch.sh               replaces the embedded public key
generate-license.sh    generates a licence key (Ed25519, openssl)
Dockerfile             official image -> patched image
check-coverage.sh      asserts every reference binary is patchable
.github/patch-check.sh verifies a patched image
```

Notes: the key pair is in this repository, so it is not secret - it
only signs licences for binaries patched with its public key. Licence renewal
against `license.stalw.art` fails, which is expected; `--days` defaults to 10
years. On 0.12.x and later, acceptance cannot be asserted automatically, so
`patch-check.sh` verifies those builds structurally.
