# How to run a patched Stalwart

Step by step, for a server you operate. Patched binaries are for your own
deployment; do not redistribute them.

## 1. Create your key pair

```sh
cd ~/dev/stalwart-patched-enterprise
./generate-license.sh --pubkey-only
```

This creates `stalwart-license.key` (mode 600) on first use and prints the
matching 32-byte public key as hex:

```
Creating a new Ed25519 key pair in stalwart-license.key
8a16557fa53bb5fd0f04f3e91625e2e939543241f0ae609f2541b8202bea1062
```

Back the private key up somewhere safe — a password manager entry is enough.
Treat it as sensitive, not as critical: it only signs licenses for binaries
patched with its public key. `*.key` is gitignored; keep it that way.

## 2. Build the patched image

Stalwart 0.12.x and later (`stalwartlabs/stalwart`):

```sh
docker build \
  --build-arg LICENSE_PUBKEY="$(./generate-license.sh --pubkey-only)" \
  -t stalwart-patched:0.16.23 .
```

Stalwart 0.9.x – 0.11.x (`stalwartlabs/mail-server`; different repo, binary
name and user):

```sh
docker build \
  --build-arg LICENSE_PUBKEY="$(./generate-license.sh --pubkey-only)" \
  --build-arg STALWART_IMAGE=stalwartlabs/mail-server:v0.11.8 \
  --build-arg STALWART_BINARY=/usr/local/bin/stalwart-mail \
  --build-arg STALWART_USER=root \
  -t stalwart-patched:0.11.8 .
```

The build fails loudly if `LICENSE_PUBKEY` is missing, and `patch.sh` fails the
build with exit 7 if the image has no license public key (a community build, or
a future layout change) — it never produces a silently unpatched image.

To patch a binary outside Docker:

```sh
./patch.sh --pubkey "$(./generate-license.sh --pubkey-only)" ./stalwart-mail
./patch.sh --pubkey "$(./generate-license.sh --pubkey-only)" --dry-run ./stalwart-mail
```

## 3. Mint a license

```sh
./generate-license.sh --domain example.com              # 1000 accounts, 10 years
./generate-license.sh --domain example.com --accounts 50 --days 3650 > license.key
```

The domain is checked by the server, so it has to be right:

- 0.11.x and later compare it against the configured hostname and reject a
  mismatch, so use the **registrable** domain: `example.com` for the host
  `mail.example.com`.
- Use `--from` only if you need a specific start timestamp; a future start is
  treated as not-yet-valid, and `--accounts 0` is rejected outright.

Keep the printed key; it is what the server will be given.

## 4. Give it to the server

**0.9.x – 0.11.x** — the key lives in the TOML config:

```toml
[server]
hostname = "example.com"

[enterprise]
license-key = "Cga4agAAAAAaF4R9AAAAAOgDAAALAAAAZXhhbXBsZS5jb20..."
```

Restart the container, then check:

```sh
docker logs <container> 2>&1 | grep -i licens
```

Expected:

```
INFO Server licensing event details = Stalwart Enterprise Edition license key
is valid, domain = "example.com", total = 1000, validFrom = "...", validTo = "..."
```

`Failed to validate license key` means the binary does not carry the public key
that signed the license — check that you built the image with the public key
from the same key pair used to mint it:

```sh
docker create --name tmp <image> /bin/true
docker cp tmp:/usr/local/bin/stalwart-mail /tmp/check
./patch.sh --pubkey "$(./generate-license.sh --pubkey-only)" /tmp/check   # exit 6 = match
```

**0.12.x and later** — the key is stored in the registry, not the config file,
and is set through the admin API. On first start the server prints a
recovery-mode URL and one-time secret to the log; open it, create the admin
account, then set the license in the UI under Administration → Enterprise, or
via the API with that account's credentials. `--config`/`config.json` is not
where this value lives, so editing it there has no effect.

## 5. Upgrading to a new Stalwart release

Nothing to re-derive. Rebuild against the new image with the same public key:

```sh
docker build --build-arg LICENSE_PUBKEY="$(./generate-license.sh --pubkey-only)" \
  --build-arg STALWART_IMAGE=stalwartlabs/stalwart:v0.17.0 -t stalwart-patched:0.17.0 .
```

Your existing `stalwart-license.key` keeps working, because the key pair did not
change. To confirm a released image is patchable at all:

```sh
./check-coverage.sh            # all reference binaries in ~/.hermes/cache/scratch/bins
./patch.sh --pubkey "$(./generate-license.sh --pubkey-only)" --dry-run ./new-binary
```

## 6. If a build stops patching (exit 7)

Exit 7 means the vendor's key was not found — almost always because upstream
rotated it. Get the new key:

```sh
./generate-license.sh --pubkey-only        # your public key stays as it is
```

Find the vendor's new 32 bytes in the release source
(`crates/common/src/enterprise/license.rs`, the `vec![...]` passed to
`UnparsedPublicKey::new(&ED25519, ...)`), then update `VENDOR_HALF_A` and
`VENDOR_HALF_B` at the top of `patch.sh` — the first and second 16 bytes of that
vector, lower-case hex. `./check-coverage.sh` should then report every binary
patchable again, and you re-patch the binary with **your** key as before.

## 7. Full verification of a patched image

```sh
# 0.11.x: real signed license, boot, assert acceptance, and assert that the
# official image rejects the same license
./.github/patch-check.sh stalwart-patched:0.11.8 /usr/local/bin/stalwart-mail \
    toml stalwartlabs/mail-server:v0.11.8 stalwart-license.key

# 0.16.x: vendor key must be gone and the server must still boot
./.github/patch-check.sh stalwart-patched:0.16.23 /usr/local/bin/stalwart json
```

Success prints `PATCH_OK: <image>`.
