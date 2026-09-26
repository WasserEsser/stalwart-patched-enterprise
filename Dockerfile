# Builds a patched Stalwart image from the official one.
#
# Default (Stalwart 0.16.x):
#   docker build \
#     --build-arg LICENSE_PUBKEY="$(./generate-license.sh --pubkey-only)" \
#     -t stalwart-patched .
#
# Stalwart Mail Server 0.11.x (different repo, binary name, user and layout):
#   docker build \
#     --build-arg LICENSE_PUBKEY="$(./generate-license.sh --pubkey-only)" \
#     --build-arg STALWART_IMAGE=stalwartlabs/mail-server:v0.11.8 \
#     --build-arg STALWART_BINARY=/usr/local/bin/stalwart-mail \
#     --build-arg STALWART_USER=root \
#     -t stalwart-patched:0.11.8 .
#
# The build args describe the upstream image and the public key to trust;
# patch.sh itself works on either binary and on any release from 0.9.0 on,
# because the key it replaces is the same in all of them.

ARG STALWART_IMAGE=stalwartlabs/stalwart:latest
ARG STALWART_BINARY=/usr/local/bin/stalwart
ARG LICENSE_PUBKEY

FROM ${STALWART_IMAGE} AS original

# Patcher stage: a container just big enough to run patch.sh against the
# binary extracted from the official image.
FROM alpine:latest AS patcher
RUN apk add --no-cache bash xxd grep gawk util-linux file coreutils

ARG STALWART_BINARY=/usr/local/bin/stalwart
ARG LICENSE_PUBKEY

COPY --from=original ${STALWART_BINARY} /stalwart

COPY patch.sh /tmp/patch.sh
RUN test -n "$LICENSE_PUBKEY" || { echo "error: the LICENSE_PUBKEY build-arg is required; get yours with ./generate-license.sh --pubkey-only" >&2; exit 1; }
RUN chmod +x /tmp/patch.sh && /tmp/patch.sh --quiet --pubkey "$LICENSE_PUBKEY" /stalwart

# Final image: the official image with only the binary replaced.
FROM ${STALWART_IMAGE}

ARG STALWART_BINARY=/usr/local/bin/stalwart
ARG STALWART_USER=stalwart

USER root
COPY --from=patcher /stalwart ${STALWART_BINARY}

# The official 0.16.x image sets cap_net_bind_service on the binary (see its
# Dockerfile) so the unprivileged stalwart user can bind 25/443/... . COPY does
# not carry file capabilities, so they have to be reapplied or the server
# cannot start. The 0.11.x image runs as root and needs no capability, so the
# step is skipped for it.
RUN if [ "$STALWART_USER" != "root" ]; then \
        setcap 'cap_net_bind_service=+ep' ${STALWART_BINARY}; \
    fi

USER ${STALWART_USER}
