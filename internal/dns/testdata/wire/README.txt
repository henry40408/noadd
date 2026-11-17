DNS wire fixtures from the Rust image ghcr.io/henry40408/noadd:0.41.1 (one file per case).

Each NNN_name.json:
  name, note, settings (the settings PUT before the case), steps[].
  step: transport (udp|tcp), request (hex, what the client sent), response (hex of what Rust answered,
        null = no answer), upstream ({request, response, proto} hex of the exchange the Rust forwarder
        had with the fake upstream; null = answered without asking upstream: blocked, synthesized or
        cache hit), sleep_before_s (wait before sending, for TTL decrement), upstream_calls.
Replay: a Go fake upstream (miekg server) answers with upstream.response; compare the Go output to
`response` after normalising the ID, and compare TTLs (cache cases: patched TTL = original - elapsed,
min 1). miekg and hickory compress names differently: compare parsed messages + TTL byte offsets,
not raw bytes, except for the synthesized cases (block / NOTIMP / BADVERS / SERVFAIL).
The fake upstream (fakes.py in $CLAUDE_JOB_DIR/tmp/noadd-capture) always answers the way the table in
that script says; it truncates UDP answers above the client's EDNS size (1232 for Rust's own queries).
Block rules for the block_* cases: ads.example.com (block), @@||ok.ads.example.com^ (allow).

Observed behaviour worth pinning (Step 9 / 12):
  * truncate_huge_* : an upstream UDP answer with TC=1 is NOT retried over TCP; Rust logs
    "response was truncated; TCP already tried or no other transport available" and answers SERVFAIL.
  * truncate_udp_noedns / edns512 / edns100: Rust's TC=1 answer keeps header+question (+OPT when the
    client sent one). truncate_tcp_* are not truncated.
  * garbage_*: a malformed UDP packet is answered with a bare 12-byte SERVFAIL header, not dropped.
  * servfail_upstream_unreachable waits for the forward timeout (~5 s) and answers a synthesized SERVFAIL.
  * dnssec_*: Rust always asks upstream with DO; non-DO clients get RRSIG stripped and AD cleared.
Coverage vs section 1.2: opcode/NOTIMP, BADVERS (v1, v255, DO), block modes x A/AAAA/MX/TXT x EDNS,
custom_ip with each address unset, RD unset, CD/AD request flags, upper-case names, allow-over-block,
cache (TTL patched, case-insensitive key, EDNS/DO profiles, negative NXDOMAIN, SERVFAIL not cached,
multi-TTL CNAME), truncation (UDP sizes, TCP), DNSSEC on/off x DO. Not covered: rate limiting,
single-flight, stale serving (need load or a slow upstream; Go covers them with its own tests).
