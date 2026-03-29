# DNS Cache: Respect Upstream TTL

## Problem

The DNS cache uses a hardcoded 300-second TTL for all entries (`src/cache.rs:22`), ignoring the TTL values returned by upstream DNS servers. This causes:

1. Short-TTL records (e.g., Cloudflare-managed domains with TTL=60s) to be served stale for up to 5 minutes
2. Long-TTL records (e.g., TTL=86400s) to be evicted and re-queried unnecessarily

## Design

Use moka's per-entry expiry (`Expiry` trait) to cache each DNS response for its actual upstream TTL. No floor or ceiling on TTL values.

### Changes

#### 1. `src/cache.rs`

- Change cache value type from `Vec<u8>` to `CacheValue { bytes: Vec<u8>, ttl: Duration }`
- Implement `moka::Expiry<CacheKey, CacheValue>` that returns `value.ttl` from `expire_after_create`
- Replace `time_to_live(300s)` with `expire_after(DnsCacheExpiry)`
- Update `insert()` signature to accept a `Duration` parameter for TTL
- Keep `max_capacity` and `invalidate_all()` unchanged

#### 2. `src/dns/handler.rs`

- After receiving upstream response, parse it and extract the minimum TTL from answer records
- Pass the extracted TTL to `cache.insert()`
- Reuse the `extract_min_ttl` logic (currently in `doh.rs`) by moving it to a shared location
- For responses with no answer records (e.g., NXDOMAIN), use a default TTL from the SOA minimum or 300 seconds

#### 3. `src/dns/doh.rs`

- Move `extract_min_ttl` to `src/dns/handler.rs` (or a shared util) and import it
- No other changes needed; DoH `Cache-Control` header already uses this function

### TTL Extraction Logic

```
min_ttl = min(answer_records.map(|r| r.ttl()))
if no answers: use SOA minimum field, or fallback to 300s
```

### Testing

- Unit test: `Expiry` implementation returns correct duration
- Unit test: `extract_min_ttl` handles various DNS responses (with answers, no answers, NXDOMAIN)
- Integration test: cached entry expires after its TTL (use a short TTL like 1s)
