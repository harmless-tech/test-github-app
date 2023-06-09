# syntax=docker/dockerfile:1.4
FROM rust:alpine as builder
ARG TARGETARCH
ARG BUILD_PROFILE=release
ARG CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse

WORKDIR /app-build
RUN mkdir -p /app-bin

RUN --mount=type=cache,target=/etc/apk/cache,sharing=locked \
    apk update && apk add alpine-sdk perl

RUN --mount=type=cache,target=$CARGO_HOME/registry,sharing=locked --mount=type=cache,target=/prebuilt,sharing=locked <<EOT
    set -e
    export CFLAGS=-mno-outline-atomics
    export PATH=$PATH:/prebuilt/bin
    cargo install cargo-prebuilt --profile=quick-build --root=/prebuilt
    cargo prebuilt --path=/prebuilt/bin cargo-auditable
EOT

COPY Cargo.toml .
COPY Cargo.lock .
COPY src src

RUN --mount=type=cache,target=/app-build/target,sharing=locked --mount=type=cache,target=$CARGO_HOME/registry,sharing=locked --mount=type=cache,target=/prebuilt,sharing=locked <<EOT
    set -e
    export ARCH="$(uname -m)"
    if [ $BUILD_PROFILE == 'dev' ]; then BUILD_DIR=debug; else BUILD_DIR=$BUILD_PROFILE; fi
    export PATH=$PATH:/prebuilt/bin
    cargo auditable build --profile="$BUILD_PROFILE" --target=$ARCH-unknown-linux-musl
    mv target/$ARCH-unknown-linux-musl/$BUILD_DIR/test-github-app /app-bin/
EOT

FROM scratch

COPY --from=builder /app-bin/test-github-app /

EXPOSE 3000
ENTRYPOINT ["/test-github-app"]
