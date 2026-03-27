# noadd

[![CI](https://github.com/henry40408/noadd/actions/workflows/ci.yml/badge.svg)](https://github.com/henry40408/noadd/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/henry40408/noadd)](LICENSE.txt)
[![Rust](https://img.shields.io/badge/rust-2024_edition-blue.svg)](https://www.rust-lang.org/)
[![Docker](https://img.shields.io/badge/docker-ghcr.io-blue.svg)](https://ghcr.io/henry40408/noadd)
[![Casual Maintenance Intended](https://casuallymaintained.tech/badge.svg)](https://casuallymaintained.tech/)

A self-hosted DNS ad-blocker with DNS-over-HTTPS support, built in Rust.

Blocks ads and trackers at the DNS level using community-maintained filter lists. Ships as a single binary with an embedded web admin UI.

## Features

- **Plain DNS** (UDP + TCP, port 53) and **DNS-over-HTTPS** (RFC 8484)
- **Filter engine** with HashMap + reverse domain trie for fast domain matching
- **Built-in filter lists** — EasyList, Peter Lowe's, Steven Black, URLhaus, OISD, and more
- **Admin web UI** — dashboard with live stats, query log, filter list management, custom rules
- **DoH token auth** — restrict DoH access with user-defined URL tokens (`/dns-query/my-token`)
- **TLS support** — optional built-in HTTPS via `--tls-cert`/`--tls-key`
- **SQLite storage** — config, query logs, and stats in a single file
- **Hot-swap filters** — update lists without restarting, zero query interruption

## Quick Start

```bash
cargo build --release

# Start with default settings (DNS on 0.0.0.0:53, HTTP on 0.0.0.0:3000)
sudo ./target/release/noadd

# Or use custom ports (no root needed)
./target/release/noadd --dns-addr 127.0.0.1:5353 --http-addr 127.0.0.1:3000
```

Open `http://127.0.0.1:3000` to set up your admin password and access the dashboard.

## Usage

```
noadd [OPTIONS]

Options:
      --db-path <DB_PATH>      Path to SQLite database [default: noadd.db]
      --dns-addr <DNS_ADDR>    DNS listener address (UDP + TCP) [default: 0.0.0.0:53]
      --http-addr <HTTP_ADDR>  HTTP/DoH listener address [default: 0.0.0.0:3000]
      --tls-cert <TLS_CERT>    TLS certificate file (enables HTTPS)
      --tls-key <TLS_KEY>      TLS private key file
  -h, --help                   Print help
```

## Testing DNS

```bash
# Plain DNS
dig @127.0.0.1 -p 5353 example.com A

# DNS-over-HTTPS (with token)
doggo example.com A @https://127.0.0.1:3000/dns-query/my-token

# Verify ad blocking
dig @127.0.0.1 -p 5353 ads.google.com A
# Expected: 0.0.0.0
```

## TLS Setup

```bash
# Generate local certs with mkcert
mkcert -install
mkcert -cert-file cert.pem -key-file key.pem localhost 127.0.0.1

# Start with TLS
./target/release/noadd \
  --dns-addr 127.0.0.1:5353 \
  --http-addr 127.0.0.1:3443 \
  --tls-cert cert.pem \
  --tls-key key.pem
```

## Development

```bash
# Run tests
cargo nextest run

# Check formatting + lints
cargo fmt --check
cargo clippy -- -D warnings

# Run in dev mode
RUST_LOG=noadd=debug cargo run -- --dns-addr 127.0.0.1:5353 --http-addr 127.0.0.1:3000
```

## License

MIT
