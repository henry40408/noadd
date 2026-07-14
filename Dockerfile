# syntax=docker/dockerfile:1

# ---- build: cross-compile a static musl binary with cargo-zigbuild ----------
# The builder is pinned to the native build platform; zig cross-compiles to the
# target arch's musl triple, so no qemu emulation is needed — an arm64 image
# builds at the host's native speed.
FROM --platform=$BUILDPLATFORM rust:1.96-bookworm AS build

# aws-lc-sys (the rustls/aws-lc-rs crypto backend) compiles its C sources through
# CMake; the SQLite (C) and mimalloc (C) deps are built by zig cc. curl fetches
# zig and is also invoked by build.rs to download the built-in filter lists; xz
# unpacks zig. git lets build.rs stamp the version via `git describe`.
RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake curl xz-utils \
    && rm -rf /var/lib/apt/lists/*

# Zig 0.14.1 avoids the libc++-19 bindgen requirement that 0.15+ introduces.
ARG ZIG_VERSION=0.14.1
ARG ZIGBUILD_VERSION=0.22.3
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
COPY . .

# Map Docker's TARGETARCH onto the Rust musl triple and build. `rustup target
# add` runs after the source (and rust-toolchain.toml) is in place, so it
# resolves against the pinned toolchain rather than the base image's default.
# build.rs reads GIT_VERSION (a literal "dev" is treated as unset, so it falls
# back to `git describe` against the copied .git).
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
# distroless/static (not :nonroot) keeps the root runtime user the previous
# distroless/cc image defaulted to — noadd binds DNS on port 53, which a
# non-root user cannot do without extra capabilities.
FROM gcr.io/distroless/static-debian12
COPY --from=build /out/noadd /noadd

VOLUME /data

# Run from /data so the default DB path cascade (noadd.sqlite3, falling back to
# a legacy noadd.db) resolves inside the mounted volume without an explicit
# --db-path. Existing deployments carrying /data/noadd.db keep working; fresh
# ones create /data/noadd.sqlite3.
WORKDIR /data

EXPOSE 53/udp
EXPOSE 53/tcp
EXPOSE 8080

ENTRYPOINT ["/noadd", "--dns-addr", "0.0.0.0:53", "--http-addr", "0.0.0.0:8080"]
