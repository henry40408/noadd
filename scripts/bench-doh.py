#!/usr/bin/env python3
"""Latency + throughput benchmark for a locally-running noadd DoH endpoint.

Uses raw DNS wire-format queries over a keep-alive HTTPS connection so the
timing reflects server latency rather than tool overhead. Measures three
separate paths:

  * cache-hit   — repeated (domain, type) queries; exercises filter check +
                  cache fetch + TTL-decrement + ID patch. Warm-up populates
                  the cache before timing starts.
  * blocked     — known-blocked domains; exercises filter check + synthesised
                  0.0.0.0 answer (no cache, no upstream).
  * parallel    — same cache-hit queries across N worker threads, each on
                  its own connection. Reports aggregate QPS.

Usage:
  scripts/bench-doh.py --token iphone
  scripts/bench-doh.py --token iphone --iters 1000 --workers 16
"""

import argparse
import concurrent.futures as cf
import http.client
import secrets
import ssl
import statistics
import struct
import sys
import time
from urllib.parse import urlparse


QTYPE = {
    "A": 1,
    "AAAA": 28,
    "MX": 15,
    "TXT": 16,
    "NS": 2,
    "SOA": 6,
    "CNAME": 5,
    "CAA": 257,
}

DOMAINS = [
    "example.com", "cloudflare.com", "github.com",
    "wikipedia.org", "mozilla.org", "rust-lang.org",
    "apple.com", "kernel.org", "archlinux.org",
    "debian.org", "gnu.org", "ietf.org", "bbc.co.uk",
]

BLOCKED = [
    "ads.google.com",
    "pagead2.googlesyndication.com",
    "ad.doubleclick.net",
    "googleads.g.doubleclick.net",
    "adservice.google.com",
]


def encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        b = label.encode("ascii")
        if not b:
            continue
        out += bytes([len(b)]) + b
    return out + b"\x00"


def build_query(domain: str, qtype: str, qid: int = 0x1234) -> bytes:
    # Header: id, flags=0x0100 (RD=1), qdcount=1, ancount/nscount/arcount=0.
    header = struct.pack("!HHHHHH", qid & 0xFFFF, 0x0100, 1, 0, 0, 0)
    question = encode_name(domain) + struct.pack("!HH", QTYPE[qtype], 1)
    return header + question


def rcode(response_bytes: bytes) -> int:
    return response_bytes[3] & 0x0F if len(response_bytes) >= 4 else -1


def new_conn(host, port, ctx):
    return http.client.HTTPSConnection(host, port, context=ctx, timeout=10)


def send_once(conn, path: str, body: bytes):
    """Returns (elapsed_seconds, rcode)."""
    t0 = time.perf_counter()
    conn.request(
        "POST",
        path,
        body=body,
        headers={
            "Content-Type": "application/dns-message",
            "Accept": "application/dns-message",
        },
    )
    resp = conn.getresponse()
    data = resp.read()
    elapsed = time.perf_counter() - t0
    if resp.status != 200:
        raise RuntimeError(f"HTTP {resp.status}: {data[:80]!r}")
    return elapsed, rcode(data)


def run_serial(make_conn, path, pairs, iters):
    conn = make_conn()
    samples = []
    rcodes = {}
    for i in range(iters):
        d, t = pairs[i % len(pairs)]
        body = build_query(d, t, qid=i)
        try:
            el, rc = send_once(conn, path, body)
            samples.append(el)
            rcodes[rc] = rcodes.get(rc, 0) + 1
        except (http.client.HTTPException, ConnectionError, OSError):
            conn.close()
            conn = make_conn()
    conn.close()
    return samples, rcodes


def run_parallel(make_conn, path, pairs, iters, workers):
    per = max(1, iters // workers)

    def worker(wid):
        conn = make_conn()
        local_samples = []
        local_rcodes = {}
        start = wid * per
        for j in range(per):
            d, t = pairs[(start + j) % len(pairs)]
            body = build_query(d, t, qid=start + j)
            try:
                el, rc = send_once(conn, path, body)
                local_samples.append(el)
                local_rcodes[rc] = local_rcodes.get(rc, 0) + 1
            except (http.client.HTTPException, ConnectionError, OSError):
                conn.close()
                conn = make_conn()
        conn.close()
        return local_samples, local_rcodes

    t0 = time.perf_counter()
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        results = list(ex.map(worker, range(workers)))
    elapsed = time.perf_counter() - t0

    samples = [s for r, _ in results for s in r]
    merged_rc = {}
    for _, rc in results:
        for k, v in rc.items():
            merged_rc[k] = merged_rc.get(k, 0) + v
    qps = len(samples) / elapsed if elapsed > 0 else 0.0
    return samples, merged_rc, elapsed, qps


def run_stampede(make_conn, path, base_domains, total, workers):
    """Cold-miss flood: each worker issues unique random-subdomain queries.

    Every query is guaranteed to miss the cache (the subdomain has never been
    seen), so every request flows through the inflight-coalescing map. Used
    to surface contention on that map under concurrent load.
    """
    per = max(1, total // workers)

    def worker(wid):
        conn = make_conn()
        local_samples = []
        local_rcodes = {}
        for j in range(per):
            # 16 hex chars of randomness; collision-free across worker runs.
            label = secrets.token_hex(8)
            domain = f"{label}.{base_domains[(wid + j) % len(base_domains)]}"
            body = build_query(domain, "A", qid=(wid * per + j) & 0xFFFF)
            try:
                el, rc = send_once(conn, path, body)
                local_samples.append(el)
                local_rcodes[rc] = local_rcodes.get(rc, 0) + 1
            except (http.client.HTTPException, ConnectionError, OSError):
                conn.close()
                conn = make_conn()
        conn.close()
        return local_samples, local_rcodes

    t0 = time.perf_counter()
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        results = list(ex.map(worker, range(workers)))
    elapsed = time.perf_counter() - t0

    samples = [s for r, _ in results for s in r]
    merged_rc = {}
    for _, rc in results:
        for k, v in rc.items():
            merged_rc[k] = merged_rc.get(k, 0) + v
    qps = len(samples) / elapsed if elapsed > 0 else 0.0
    return samples, merged_rc, elapsed, qps


def percentile(sorted_samples, p):
    if not sorted_samples:
        return None
    n = len(sorted_samples)
    idx = min(n - 1, int(round(p / 100 * (n - 1))))
    return sorted_samples[idx]


def fmt_ms(v):
    return "n/a" if v is None else f"{v * 1000:7.2f}ms"


def summarise(label, samples, rcodes):
    rc_str = ""
    if rcodes:
        # Anything non-zero is interesting; 0=NoError, 3=NXDomain, 5=Refused.
        named = {0: "NoError", 3: "NXDomain", 5: "Refused"}
        rc_str = "  rcodes=" + ",".join(
            f"{named.get(k, k)}={v}" for k, v in sorted(rcodes.items())
        )
    if not samples:
        print(f"  {label:12s} n=   0  (no successful samples){rc_str}")
        return
    s = sorted(samples)
    print(
        f"  {label:12s} n={len(s):4d}  "
        f"min={fmt_ms(s[0])}  "
        f"p50={fmt_ms(percentile(s, 50))}  "
        f"p95={fmt_ms(percentile(s, 95))}  "
        f"p99={fmt_ms(percentile(s, 99))}  "
        f"max={fmt_ms(s[-1])}  "
        f"mean={fmt_ms(statistics.mean(samples))}"
        f"{rc_str}"
    )


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--url", default="https://localhost:3443/dns-query")
    ap.add_argument("--token")
    ap.add_argument("--iters", type=int, default=500,
                    help="Iterations per phase (default: %(default)s)")
    ap.add_argument("--workers", type=int, default=8,
                    help="Parallel workers (default: %(default)s)")
    ap.add_argument("--stampede-iters", type=int, default=0,
                    help="If >0, run a cold-miss stampede phase with this "
                         "many unique random-subdomain queries spread across "
                         "--stampede-workers. Each query forces an inflight "
                         "map insert/remove, surfacing contention on that map.")
    ap.add_argument("--stampede-workers", type=int, default=64,
                    help="Workers for stampede phase (default: %(default)s). "
                         "Higher than --workers to push the map past the "
                         "DashMap default shard count of 32.")
    ap.add_argument("--insecure", action="store_true",
                    help="Skip TLS verification (for untrusted self-signed certs)")
    args = ap.parse_args()

    u = args.url.rstrip("/")
    if args.token:
        u = f"{u}/{args.token}"
    parsed = urlparse(u)
    host = parsed.hostname
    port = parsed.port or 443
    path = parsed.path or "/"

    ctx = ssl._create_unverified_context() if args.insecure else ssl.create_default_context()
    make = lambda: new_conn(host, port, ctx)

    pairs = [(d, t) for d in DOMAINS for t in QTYPE]
    blocked_pairs = [(d, "A") for d in BLOCKED]

    print(f"Target : {u}")
    print(f"Warmup : {len(pairs)} cache-populating queries + {len(blocked_pairs)} blocked")
    print(f"Phase  : {args.iters} queries each (serial keep-alive, then {args.workers}-way parallel)")
    print()

    # Probe once so the user sees a clear error rather than mixed noise.
    try:
        conn = make()
        send_once(conn, path, build_query("example.com", "A"))
        conn.close()
    except Exception as e:
        print(f"probe failed: {e}", file=sys.stderr)
        sys.exit(2)

    # Warm + filter: drop (domain, qtype) pairs that don't return NoError so
    # the timing phase isn't polluted by upstream-bound SERVFAIL/NXDomain
    # responses (those never enter the cache). Run twice so a one-shot upstream
    # hiccup doesn't permanently exclude an otherwise-cacheable pair.
    print("Warming cache + filtering non-cacheable pairs...", flush=True)
    conn = make()
    surviving = []
    dropped = []
    for d, t in pairs:
        rcs = set()
        for _ in range(2):
            try:
                _, rc = send_once(conn, path, build_query(d, t))
                rcs.add(rc)
            except (http.client.HTTPException, ConnectionError, OSError):
                conn.close()
                conn = make()
        if 0 in rcs:
            surviving.append((d, t))
        else:
            dropped.append((d, t, sorted(rcs)))
    conn.close()
    if dropped:
        print(f"  dropped {len(dropped)}/{len(pairs)} non-cacheable pairs:")
        for d, t, rcs in dropped:
            print(f"    {d:24s} {t:5s}  rcodes={rcs}")
    pairs = surviving
    print(f"  using {len(pairs)} cache-hit pairs")
    run_serial(make, path, blocked_pairs, len(blocked_pairs))

    print("\nSerial (single connection, keep-alive):")
    hit, rc = run_serial(make, path, pairs, args.iters)
    summarise("cache-hit", hit, rc)
    blk, rc = run_serial(make, path, blocked_pairs, args.iters)
    summarise("blocked", blk, rc)

    print(f"\nParallel ({args.workers} workers, each on its own keep-alive connection):")
    hit, rc, elapsed, qps = run_parallel(make, path, pairs, args.iters, args.workers)
    summarise("cache-hit", hit, rc)
    print(f"  {'':12s}   elapsed={elapsed * 1000:.0f}ms  aggregate-qps={qps:.0f}")
    blk, rc, elapsed, qps = run_parallel(make, path, blocked_pairs, args.iters, args.workers)
    summarise("blocked", blk, rc)
    print(f"  {'':12s}   elapsed={elapsed * 1000:.0f}ms  aggregate-qps={qps:.0f}")

    if args.stampede_iters > 0:
        # Use only the surviving cacheable domains as bases — a known-bad
        # domain would just SERVFAIL and never reach the inflight path.
        bases = sorted({d for d, _ in pairs}) or DOMAINS
        print(
            f"\nCold-miss stampede ({args.stampede_workers} workers, "
            f"{args.stampede_iters} unique queries total):"
        )
        smp, rc, elapsed, qps = run_stampede(
            make, path, bases, args.stampede_iters, args.stampede_workers
        )
        summarise("cold-miss", smp, rc)
        print(f"  {'':12s}   elapsed={elapsed * 1000:.0f}ms  aggregate-qps={qps:.0f}")


if __name__ == "__main__":
    main()
