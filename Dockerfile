# syntax=docker/dockerfile:1

# ---- build: cross-compile a static musl binary with cargo-zigbuild ----------
# Runs on the native build platform; zig cross-compiles, so no qemu.
# No Rust version here: rust-toolchain.toml is the source of truth. Don't switch
# to an un-suffixed `rust:1.x` tag — it resolves to trixie (silent Debian bump).
FROM --platform=$BUILDPLATFORM rust:bookworm AS build

# cmake: aws-lc-sys. curl: fetches zig.
# xz: unpacks zig. No git: `.git` is excluded, so GIT_VERSION arrives as an arg.
RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake curl xz-utils \
    && rm -rf /var/lib/apt/lists/*

# Zig 0.14.1 avoids the libc++-19 bindgen requirement that 0.15+ introduces.
ARG ZIG_VERSION=0.14.1
# >= 0.23.0 filters out the `--fix-cortex-a53-843419` linker flag Rust 1.98
# passes on aarch64, which zig rejects (rust-cross/cargo-zigbuild#452).
ARG ZIGBUILD_VERSION=0.23.0
RUN cargo install cargo-zigbuild --version "${ZIGBUILD_VERSION}" --locked
RUN set -eux; \
    case "$(uname -m)" in \
      x86_64) zarch=x86_64 ;; \
      aarch64) zarch=aarch64 ;; \
      *) echo "unsupported build arch $(uname -m)" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://ziglang.org/download/${ZIG_VERSION}/zig-${zarch}-linux-${ZIG_VERSION}.tar.xz" \
      | tar -xJ -C /opt; \
    ln -s "/opt/zig-${zarch}-linux-${ZIG_VERSION}/zig" /usr/local/bin/zig

WORKDIR /app

# Install the pinned toolchain in a layer keyed on rust-toolchain.toml alone, so
# source edits don't re-download it.
COPY rust-toolchain.toml .
RUN cargo --version

COPY . .

# The workflow passes `git describe` as GIT_VERSION; an arg-less build yields a
# working image labelled `dev`.
ARG TARGETARCH
ARG GIT_VERSION=dev
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target,sharing=locked \
    set -eux; \
    case "$TARGETARCH" in \
      amd64) target=x86_64-unknown-linux-musl ;; \
      arm64) target=aarch64-unknown-linux-musl ;; \
      *) echo "unsupported target arch $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    rustup target add "$target"; \
    GIT_VERSION="${GIT_VERSION}" cargo zigbuild --release --target "$target"; \
    install -Dm755 "target/${target}/release/noadd" /out/noadd

# ---- runtime: minimal static image (CA certs + tzdata, no shell) ------------
# Not :nonroot: binding DNS on port 53 needs root (or extra capabilities).
FROM gcr.io/distroless/static-debian12
COPY --from=build /out/noadd /noadd

VOLUME /data

# Run from /data so the default DB path (noadd.sqlite3, or a legacy noadd.db)
# lands in the volume without --db-path.
WORKDIR /data

EXPOSE 53/udp
EXPOSE 53/tcp
EXPOSE 8080

# The app defaults HTTP to loopback; ENV rather than an ENTRYPOINT arg keeps it
# overridable with `-e NOADD_HTTP_ADDR=...`.
ENV NOADD_HTTP_ADDR=0.0.0.0:8080

ENTRYPOINT ["/noadd", "--dns-addr", "0.0.0.0:53"]
