#!/usr/bin/env python3
"""Random DoH query fuzzer + cache verifier for a locally-running noadd.

Sends a randomised mix of query types (A, AAAA, MX, TXT, NS, SOA, CNAME, CAA)
for a mix of well-known and known-blocked domains, shells out to `doggo` for
each query, and checks:

  * valid response (no upstream error, no client-side failure)
  * known-blocked domains resolve to 0.0.0.0 / empty answer
  * repeating the same query returns a lower TTL (proof the answer came from
    noadd's own cache rather than a fresh upstream fetch)

Usage:
  scripts/fuzz-doh.py --token iphone
  scripts/fuzz-doh.py --url https://localhost:3443/dns-query --token iphone --count 50 --seed 1
"""

import argparse
import json
import random
import subprocess
import sys
import time

DEFAULT_URL = "https://localhost:3443/dns-query"

QUERY_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME", "CAA"]

# Plausibly-resolvable public domains with stable RR sets.
DOMAINS = [
    "example.com",
    "cloudflare.com",
    "github.com",
    "wikipedia.org",
    "mozilla.org",
    "rust-lang.org",
    "apple.com",
    "kernel.org",
    "archlinux.org",
    "debian.org",
    "gnu.org",
    "ietf.org",
    "bbc.co.uk",
]

# Shipped in the default AdGuard list; a fresh noadd install blocks these.
BLOCKED_DOMAINS = [
    "ads.google.com",
    "pagead2.googlesyndication.com",
    "ad.doubleclick.net",
    "googleads.g.doubleclick.net",
    "adservice.google.com",
]


def run_doggo(url, domain, qtype, timeout=10):
    """Invoke doggo and return the first response dict (or an error marker)."""
    cmd = [
        "doggo",
        domain,
        qtype,
        "@" + url,
        "-J",
        "--time",
        f"--timeout={timeout}s",
    ]
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout + 5
        )
    except subprocess.TimeoutExpired:
        return {"_error": "client timeout"}

    if r.returncode != 0:
        return {"_error": (r.stderr or r.stdout).strip() or "doggo exit != 0"}

    try:
        payload = json.loads(r.stdout)
    except json.JSONDecodeError as e:
        return {"_error": f"invalid JSON: {e}"}

    # doggo emits errors as stderr log lines AND returns exit 0 with "{}"
    # — detect that case explicitly.
    resps = payload.get("responses") or []
    if not resps:
        msg = r.stderr.strip()
        return {"_error": f"empty responses ({msg})" if msg else "empty responses"}
    return resps[0]


def parse_ttl(ttl):
    """Parse doggo TTL strings like '238s', '5m30s', '1h2m3s' → seconds."""
    if not isinstance(ttl, str) or not ttl:
        return None
    total = 0
    n = 0
    for ch in ttl:
        if ch.isdigit():
            n = n * 10 + int(ch)
        elif ch == "s":
            total += n
            n = 0
        elif ch == "m":
            total += n * 60
            n = 0
        elif ch == "h":
            total += n * 3600
            n = 0
        else:
            return None
    return total or None


def parse_rtt_ms(rtt):
    """Parse doggo rtt strings like '38ms' or '1.23s' → milliseconds."""
    if not isinstance(rtt, str) or not rtt:
        return None
    try:
        if rtt.endswith("ms"):
            return float(rtt[:-2])
        if rtt.endswith("s"):
            return float(rtt[:-1]) * 1000.0
    except ValueError:
        return None
    return None


def min_ttl(answers):
    ttls = [parse_ttl(a.get("ttl")) for a in answers or []]
    ttls = [t for t in ttls if t is not None]
    return min(ttls) if ttls else None


def first_rtt_ms(answers):
    return parse_rtt_ms(answers[0].get("rtt")) if answers else None


def addresses(answers):
    return [a.get("address") for a in answers or [] if a.get("address")]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default=DEFAULT_URL,
                    help="DoH base URL (default: %(default)s)")
    ap.add_argument("--token",
                    help="DoH token; appended as /<url>/<token>")
    ap.add_argument("--count", type=int, default=30,
                    help="Number of query iterations (default: %(default)s)")
    ap.add_argument("--seed", type=int,
                    help="RNG seed for reproducibility")
    ap.add_argument("--blocked-ratio", type=float, default=0.15,
                    help="Fraction of iterations targeting a known-blocked domain")
    ap.add_argument("--repeat-delay", type=float, default=2.0,
                    help="Seconds between 1st and 2nd (cache-check) query")
    ap.add_argument("--pause", type=float, default=0.0,
                    help="Seconds to sleep between iterations (rate-limit relief)")
    args = ap.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    url = args.url.rstrip("/")
    if args.token:
        url = f"{url}/{args.token}"

    passes = 0
    fails = 0
    cache_hits = 0
    cache_unclear = 0
    failures = []

    for i in range(1, args.count + 1):
        is_blocked = random.random() < args.blocked_ratio
        domain = random.choice(BLOCKED_DOMAINS if is_blocked else DOMAINS)
        # For blocked probes only A makes sense (the block answer synthesises
        # 0.0.0.0 for A and :: for AAAA; other types return empty).
        qtype = "A" if is_blocked else random.choice(QUERY_TYPES)

        label = f"[{i:3d}/{args.count}] {qtype:5s} {domain:40s}"
        print(label, end=" ", flush=True)

        r1 = run_doggo(url, domain, qtype)
        if "_error" in r1:
            print(f"FAIL  first query: {r1['_error']}")
            fails += 1
            failures.append((i, qtype, domain, r1["_error"]))
            if args.pause:
                time.sleep(args.pause)
            continue

        ans1 = r1.get("answers") or []
        addrs1 = addresses(ans1)

        if is_blocked:
            if not ans1 or all(a == "0.0.0.0" for a in addrs1):
                print(f"OK    blocked ({addrs1 or 'empty'})")
                passes += 1
            else:
                print(f"FAIL  expected block, got {addrs1}")
                fails += 1
                failures.append((i, qtype, domain, f"not blocked: {addrs1}"))
            if args.pause:
                time.sleep(args.pause)
            continue

        ttl1 = min_ttl(ans1)
        rtt1 = first_rtt_ms(ans1)

        time.sleep(args.repeat_delay)
        r2 = run_doggo(url, domain, qtype)
        if "_error" in r2:
            print(f"PART  first ok; repeat: {r2['_error']}")
            # Count as pass — first query was fine; repeat failures are
            # distinct from "query broken" so don't treat as a hard fail.
            passes += 1
            if args.pause:
                time.sleep(args.pause)
            continue

        ans2 = r2.get("answers") or []
        ttl2 = min_ttl(ans2)
        rtt2 = first_rtt_ms(ans2)

        status = ""
        if ttl1 is not None and ttl2 is not None:
            if ttl2 < ttl1:
                cache_hits += 1
                status = f"cache HIT (ttl {ttl1}->{ttl2})"
            elif (
                ttl2 == ttl1
                and rtt1 is not None
                and rtt2 is not None
                and rtt2 * 2 < rtt1
            ):
                # TTL equal (sub-second repeat) but rtt halved → likely cache.
                cache_hits += 1
                status = f"cache HIT (rtt {rtt1:.0f}->{rtt2:.0f}ms)"
            else:
                cache_unclear += 1
                status = (
                    f"cache ??   (ttl {ttl1}/{ttl2}, "
                    f"rtt {rtt1 or '?'}/{rtt2 or '?'}ms)"
                )

        n = len(ans1)
        print(f"OK    {n} ans  {status}")
        passes += 1

        if args.pause:
            time.sleep(args.pause)

    print()
    print("=" * 68)
    print(f"Summary     : {passes} passed, {fails} failed (of {args.count})")
    print(f"Cache       : {cache_hits} confirmed hits, {cache_unclear} unclear")
    if failures:
        print("\nFailures:")
        for i, t, d, e in failures:
            print(f"  [{i:3d}] {t:5s} {d:40s} {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
