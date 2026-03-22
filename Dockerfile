# Stage 1: Chef - prepare recipe (runs on build platform)
FROM --platform=$BUILDPLATFORM rust:1.94-bookworm AS chef
RUN cargo install cargo-chef
WORKDIR /app

# Stage 2: Planner - create recipe.json
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# Stage 3: Builder - cross-compile for target platform
FROM chef AS builder

# Target platform args (set by docker buildx)
ARG TARGETPLATFORM

# Install cross-compilation toolchain based on target
RUN case "$TARGETPLATFORM" in \
        "linux/arm64") \
            apt-get update && apt-get install -y gcc-aarch64-linux-gnu && \
            rustup target add aarch64-unknown-linux-gnu \
            ;; \
        "linux/amd64") \
            # Native build, no extra toolchain needed \
            ;; \
    esac

# Configure cargo for cross-compilation
RUN mkdir -p .cargo && \
    case "$TARGETPLATFORM" in \
        "linux/arm64") \
            echo '[target.aarch64-unknown-linux-gnu]' >> .cargo/config.toml && \
            echo 'linker = "aarch64-linux-gnu-gcc"' >> .cargo/config.toml \
            ;; \
    esac

# Set the Rust target based on platform
RUN case "$TARGETPLATFORM" in \
        "linux/arm64") echo "aarch64-unknown-linux-gnu" > /tmp/rust_target ;; \
        "linux/amd64") echo "x86_64-unknown-linux-gnu" > /tmp/rust_target ;; \
        *) echo "x86_64-unknown-linux-gnu" > /tmp/rust_target ;; \
    esac

COPY --from=planner /app/recipe.json recipe.json

# Cook dependencies with target
RUN RUST_TARGET=$(cat /tmp/rust_target) && \
    cargo chef cook --release --recipe-path recipe.json --target $RUST_TARGET

COPY . .

# Build the application
RUN RUST_TARGET=$(cat /tmp/rust_target) && \
    cargo build --release --target $RUST_TARGET && \
    cp target/$RUST_TARGET/release/noadd /app/noadd

# Stage 4: Runtime
FROM gcr.io/distroless/cc-debian12

COPY --from=builder /app/noadd /noadd

VOLUME /data

EXPOSE 53/udp
EXPOSE 53/tcp
EXPOSE 3000

ENTRYPOINT ["/noadd", "--db-path", "/data/noadd.db", "--dns-addr", "0.0.0.0:53", "--http-addr", "0.0.0.0:3000"]
