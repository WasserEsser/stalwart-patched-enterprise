ARG STALWART_IMAGE_TAG=latest
FROM stalwartlabs/stalwart:${STALWART_IMAGE_TAG} AS original

# Patcher stage: a container just big enough to run patch.sh against the
# binary extracted from the official image.
FROM alpine:latest AS patcher
RUN apk add --no-cache bash xxd grep gawk util-linux file coreutils

COPY --from=original /usr/local/bin/stalwart /stalwart

COPY patch.sh /tmp/patch.sh
RUN chmod +x /tmp/patch.sh && /tmp/patch.sh --quiet /stalwart

# Final image: the official image with only the binary replaced.
FROM stalwartlabs/stalwart:${STALWART_IMAGE_TAG}

COPY --from=patcher --chown=2000:2000 /stalwart /usr/local/bin/stalwart

# The upstream image sets cap_net_bind_service on the binary (see its Dockerfile)
# so the unprivileged stalwart user can bind 25/443/... . COPY does not carry
# file capabilities, so they have to be reapplied or the server cannot start.
USER root
RUN setcap 'cap_net_bind_service=+ep' /usr/local/bin/stalwart
USER stalwart
