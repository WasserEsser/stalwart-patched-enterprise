# Patched Stalwart image built from the official one.
#
#   docker build -t stalwart-patched .                # 0.12.x+
#
#   docker build --build-arg STALWART_IMAGE=stalwartlabs/mail-server:v0.11.8 \
#     --build-arg STALWART_BINARY=/usr/local/bin/stalwart-mail \
#     --build-arg STALWART_USER=root -t stalwart-patched:0.11.8 .   # 0.9.x-0.11.x

ARG STALWART_IMAGE=stalwartlabs/stalwart:latest
ARG STALWART_BINARY=/usr/local/bin/stalwart

FROM ${STALWART_IMAGE} AS original

FROM alpine:latest AS patcher
RUN apk add --no-cache bash xxd grep coreutils

ARG STALWART_BINARY=/usr/local/bin/stalwart

COPY --from=original ${STALWART_BINARY} /stalwart
COPY patch.sh /tmp/patch.sh
RUN chmod +x /tmp/patch.sh && /tmp/patch.sh --quiet /stalwart

FROM ${STALWART_IMAGE}

ARG STALWART_BINARY=/usr/local/bin/stalwart
ARG STALWART_USER=stalwart

USER root
COPY --from=patcher /stalwart ${STALWART_BINARY}

# COPY does not carry file capabilities, and the official image grants the
# unprivileged user cap_net_bind_service so it can bind 25/443.
RUN if [ "$STALWART_USER" != "root" ]; then \
        setcap 'cap_net_bind_service=+ep' ${STALWART_BINARY}; \
    fi

USER ${STALWART_USER}
