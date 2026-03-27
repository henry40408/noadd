# Upstream DNS Strategy

## Overview

Add configurable upstream DNS server selection strategies to noadd. Users can choose between Sequential, Round Robin, and Lowest Latency strategies via the Admin UI at runtime.

## Strategies

### Sequential (default)

Current behavior. Try servers in configured order; return first success.

### Round Robin

Rotate through servers using an atomic counter. Each query starts from the next server in the list. On failure, try remaining servers in rotation order.

### Lowest Latency

Select the server with the lowest Exponential Moving Average (EMA) latency. On failure, try remaining servers in ascending EMA order.

**EMA tracking:**
- Alpha = 0.3 (weight for new observations)
- Updated on every successful query response
- Updated by periodic background probing (every 60 seconds)
- Initial EMA for all servers: 0.0 (no data yet; treated as lowest priority until first measurement)
- Background probing only runs when strategy is `lowest-latency`

**Failover:** On failure, try remaining servers sorted by EMA latency (lowest first).

## Architecture

### UpstreamStrategy enum

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UpstreamStrategy {
    Sequential,
    RoundRobin,
    LowestLatency,
}
```

Stored in DB as setting `upstream_strategy` with values: `sequential`, `round-robin`, `lowest-latency`.

### UpstreamForwarder changes

New fields:
- `strategy: ArcSwap<UpstreamStrategy>` — runtime-switchable via API
- `rr_counter: AtomicUsize` — round-robin index
- `latencies: Arc<Mutex<HashMap<String, f64>>>` — EMA latency per server (milliseconds)

The `forward()` method determines server try-order based on current strategy:
- `Sequential` — `config.servers` order (unchanged)
- `RoundRobin` — start from `rr_counter % len`, wrap around
- `LowestLatency` — sort by EMA ascending

After each successful query, update the responding server's EMA:
```
new_ema = alpha * observed_ms + (1 - alpha) * old_ema
```

New public methods:
- `set_strategy(&self, strategy: UpstreamStrategy)` — swaps strategy via ArcSwap
- `strategy(&self) -> UpstreamStrategy` — reads current strategy
- `latencies(&self) -> HashMap<String, f64>` — returns current EMA snapshot
- `update_latency(&self, server: &str, ms: f64)` — updates EMA for a server
- `probe_all(&self)` — health-check all servers and update EMA with results

### Background probing task (main.rs)

A new `tokio::spawn` task:
- Runs every 60 seconds
- Checks if current strategy is `lowest-latency`; skips if not
- Calls `forwarder.probe_all()` which sends a minimal DNS query to each server and updates EMA with observed latency

### Settings API changes

`get_settings`: add `upstream_strategy` to the known keys list.

`put_settings`: when `upstream_strategy` is updated, call `forwarder.set_strategy()` to apply immediately.

### New API endpoint

`GET /api/upstream/latency` (requires auth):
- Returns JSON array: `[{"server": "1.1.1.1:53", "ema_ms": 12.5, "preferred": true}, ...]`
- `preferred` is true for the server with the lowest EMA
- Returns empty array if no EMA data is available

### Admin UI changes

Settings page, Upstream DNS card:
- Add a `<select>` dropdown for strategy selection (Sequential / Round Robin / Lowest Latency)
- Below the dropdown, when strategy is `lowest-latency`, show a table of servers with their current EMA latency
- Mark the preferred (lowest EMA) server
- Auto-save strategy on dropdown change (same pattern as DoH policy dropdown)

## Testing

### Unit tests
- Server ordering for each strategy (Sequential, RoundRobin, LowestLatency)
- EMA calculation correctness
- Strategy switching via `set_strategy`

### Integration tests
- API: read/write `upstream_strategy` setting
- API: `GET /api/upstream/latency` returns expected format
- Round-robin counter increments across queries
