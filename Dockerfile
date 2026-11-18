# syntax=docker/dockerfile:1

# ---- build: cross-compile a static Go binary --------------------------------
# Runs on the native build platform; Go cross-compiles to the target with
# CGO off, so no qemu and no C toolchain.
# No Go version tag: the image's Go is used when it is at least go.mod's
# `toolchain` line; otherwise GOTOOLCHAIN=auto fetches that line (auto only
# moves up). Keep the `bookworm` suffix: a bare tag resolves to trixie, a
# silent Debian bump.
FROM --platform=$BUILDPLATFORM golang:bookworm AS build

WORKDIR /app

# The official image sets GOTOOLCHAIN=local, which ignores go.mod's toolchain
# line. Fetch a newer toolchain in a layer keyed on go.mod/go.sum alone, so
# source edits do not re-download it.
ENV GOTOOLCHAIN=auto
COPY go.mod go.sum ./
RUN go version

COPY . .

# `vendor/` ships in the repository, so the build needs no network. The
# workflow passes `git describe` as GIT_VERSION; an arg-less build yields a
# working image labelled `dev`.
ARG TARGETOS
ARG TARGETARCH
ARG GIT_VERSION=dev
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" \
    go build -mod=vendor -trimpath \
      -ldflags "-s -w -X github.com/henry40408/noadd/internal/version.version=${GIT_VERSION}" \
      -o /out/noadd ./cmd/noadd

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
