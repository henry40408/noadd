# Upstream DNS Strategy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add configurable upstream DNS selection strategies (Sequential, Round Robin, Lowest Latency) switchable at runtime via Admin UI.

**Architecture:** Add `UpstreamStrategy` enum and strategy-aware state (RR counter, EMA latencies) to `UpstreamForwarder`. The `forward()` method orders servers based on the active strategy. A background task probes all servers periodically to update EMA data. The Admin UI exposes a dropdown to switch strategies and displays EMA latency data.

**Tech Stack:** Rust, axum, arc-swap, tokio, serde, vanilla JS Web Components

---

### File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `src/upstream/strategy.rs` | Create | `UpstreamStrategy` enum with serde |
| `src/upstream/mod.rs` | Modify | Export `strategy` module |
| `src/upstream/forwarder.rs` | Modify | Add strategy, RR counter, EMA latencies; rewrite `forward()` |
| `src/admin/api.rs` | Modify | Add `/api/upstream/latency` endpoint; wire strategy change in `put_settings` |
| `src/main.rs` | Modify | Load strategy from DB on startup; add background probe task |
| `admin-ui/dist/index.html` | Modify | Add strategy dropdown and EMA display to Settings page |
| `tests/upstream_test.rs` | Modify | Add strategy ordering, EMA, and round-robin tests |
| `tests/admin_api_test.rs` | Modify | Add latency endpoint and strategy setting tests |

---

### Task 1: UpstreamStrategy enum

**Files:**
- Create: `src/upstream/strategy.rs`
- Modify: `src/upstream/mod.rs`

- [ ] **Step 1: Create the strategy enum**

Create `src/upstream/strategy.rs`:

```rust
use serde::{Deserialize, Serialize};

/// Upstream DNS server selection strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UpstreamStrategy {
    Sequential,
    RoundRobin,
    LowestLatency,
}

impl Default for UpstreamStrategy {
    fn default() -> Self {
        Self::Sequential
    }
}

impl std::fmt::Display for UpstreamStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sequential => write!(f, "sequential"),
            Self::RoundRobin => write!(f, "round-robin"),
            Self::LowestLatency => write!(f, "lowest-latency"),
        }
    }
}

impl std::str::FromStr for UpstreamStrategy {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "sequential" => Ok(Self::Sequential),
            "round-robin" => Ok(Self::RoundRobin),
            "lowest-latency" => Ok(Self::LowestLatency),
            other => Err(format!("unknown strategy: {other}")),
        }
    }
}
```

- [ ] **Step 2: Export the module**

In `src/upstream/mod.rs`, replace the entire contents with:

```rust
pub mod forwarder;
pub mod strategy;
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo check`
Expected: success

- [ ] **Step 4: Commit**

```bash
git add src/upstream/strategy.rs src/upstream/mod.rs
git commit -m "feat: add UpstreamStrategy enum"
```

---

### Task 2: Extend UpstreamForwarder with strategy support

**Files:**
- Modify: `src/upstream/forwarder.rs`

- [ ] **Step 1: Write unit tests for server ordering**

Add to the bottom of `src/upstream/forwarder.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn make_forwarder(strategy: UpstreamStrategy) -> UpstreamForwarder {
        let config = UpstreamConfig {
            servers: vec!["a:53".into(), "b:53".into(), "c:53".into()],
            timeout_ms: 1000,
        };
        let mut f = UpstreamForwarder::new(config);
        f.set_strategy(strategy);
        f
    }

    #[test]
    fn test_sequential_order() {
        let f = make_forwarder(UpstreamStrategy::Sequential);
        let order = f.server_order();
        assert_eq!(order, vec!["a:53", "b:53", "c:53"]);
    }

    #[test]
    fn test_round_robin_rotates() {
        let f = make_forwarder(UpstreamStrategy::RoundRobin);
        let order1 = f.server_order();
        assert_eq!(order1, vec!["a:53", "b:53", "c:53"]);

        // Simulate incrementing the counter (as forward() would)
        f.rr_counter.fetch_add(1, Ordering::Relaxed);
        let order2 = f.server_order();
        assert_eq!(order2, vec!["b:53", "c:53", "a:53"]);

        f.rr_counter.fetch_add(1, Ordering::Relaxed);
        let order3 = f.server_order();
        assert_eq!(order3, vec!["c:53", "a:53", "b:53"]);
    }

    #[test]
    fn test_lowest_latency_order() {
        let f = make_forwarder(UpstreamStrategy::LowestLatency);

        // Set EMA values: b is fastest, then c, then a
        {
            let mut lat = f.latencies.lock().unwrap();
            lat.insert("a:53".into(), 50.0);
            lat.insert("b:53".into(), 10.0);
            lat.insert("c:53".into(), 30.0);
        }

        let order = f.server_order();
        assert_eq!(order, vec!["b:53", "c:53", "a:53"]);
    }

    #[test]
    fn test_lowest_latency_no_data_uses_config_order() {
        let f = make_forwarder(UpstreamStrategy::LowestLatency);
        // No EMA data at all — should fall back to config order
        let order = f.server_order();
        assert_eq!(order, vec!["a:53", "b:53", "c:53"]);
    }

    #[test]
    fn test_ema_update() {
        let f = make_forwarder(UpstreamStrategy::LowestLatency);

        // First observation: EMA starts at observed value (no prior data)
        f.update_latency("a:53", 100.0);
        {
            let lat = f.latencies.lock().unwrap();
            assert!((lat["a:53"] - 100.0).abs() < 0.001);
        }

        // Second observation: EMA = 0.3 * 40 + 0.7 * 100 = 82.0
        f.update_latency("a:53", 40.0);
        {
            let lat = f.latencies.lock().unwrap();
            assert!((lat["a:53"] - 82.0).abs() < 0.001);
        }
    }

    #[test]
    fn test_set_strategy() {
        let f = make_forwarder(UpstreamStrategy::Sequential);
        assert_eq!(f.strategy(), UpstreamStrategy::Sequential);

        f.set_strategy(UpstreamStrategy::RoundRobin);
        assert_eq!(f.strategy(), UpstreamStrategy::RoundRobin);

        f.set_strategy(UpstreamStrategy::LowestLatency);
        assert_eq!(f.strategy(), UpstreamStrategy::LowestLatency);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo nextest run -p noadd forwarder::tests`
Expected: FAIL — methods `set_strategy`, `server_order`, `update_latency`, `strategy`, and field `rr_counter`, `latencies` do not exist

- [ ] **Step 3: Implement the forwarder changes**

Replace the entire contents of `src/upstream/forwarder.rs` with:

```rust
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use thiserror::Error;
use tokio::net::UdpSocket;

use super::strategy::UpstreamStrategy;

/// EMA smoothing factor. 0.3 means 30% weight for new observations.
const EMA_ALPHA: f64 = 0.3;

/// Configuration for upstream DNS servers.
#[derive(Debug, Clone)]
pub struct UpstreamConfig {
    /// Upstream server addresses in "IP:port" format.
    pub servers: Vec<String>,
    /// Timeout in milliseconds for each upstream attempt.
    pub timeout_ms: u64,
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        Self {
            servers: vec![
                "1.1.1.1:53".into(),
                "9.9.9.9:53".into(),
                "194.242.2.2:53".into(),
            ],
            timeout_ms: 2000,
        }
    }
}

/// Errors that can occur during DNS forwarding.
#[derive(Debug, Error)]
pub enum ForwardError {
    #[error("all upstreams failed")]
    AllFailed,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Forwards DNS queries to upstream servers with configurable strategy.
pub struct UpstreamForwarder {
    config: UpstreamConfig,
    strategy: ArcSwap<UpstreamStrategy>,
    rr_counter: AtomicUsize,
    latencies: Mutex<HashMap<String, f64>>,
}

impl UpstreamForwarder {
    /// Create a new forwarder with the given configuration.
    pub fn new(config: UpstreamConfig) -> Self {
        Self {
            config,
            strategy: ArcSwap::from_pointee(UpstreamStrategy::default()),
            rr_counter: AtomicUsize::new(0),
            latencies: Mutex::new(HashMap::new()),
        }
    }

    /// Get the current strategy.
    pub fn strategy(&self) -> UpstreamStrategy {
        **self.strategy.load()
    }

    /// Set the active strategy.
    pub fn set_strategy(&self, strategy: UpstreamStrategy) {
        self.strategy.store(std::sync::Arc::new(strategy));
    }

    /// Return the server try-order for the current strategy.
    pub fn server_order(&self) -> Vec<String> {
        let servers = &self.config.servers;
        let len = servers.len();
        if len == 0 {
            return vec![];
        }

        match self.strategy() {
            UpstreamStrategy::Sequential => servers.clone(),
            UpstreamStrategy::RoundRobin => {
                let idx = self.rr_counter.load(Ordering::Relaxed) % len;
                let mut order = Vec::with_capacity(len);
                for i in 0..len {
                    order.push(servers[(idx + i) % len].clone());
                }
                order
            }
            UpstreamStrategy::LowestLatency => {
                let lat = self.latencies.lock().unwrap();
                if lat.is_empty() {
                    return servers.clone();
                }
                let mut sorted: Vec<String> = servers.clone();
                sorted.sort_by(|a, b| {
                    let la = lat.get(a).copied().unwrap_or(f64::MAX);
                    let lb = lat.get(b).copied().unwrap_or(f64::MAX);
                    la.partial_cmp(&lb).unwrap_or(std::cmp::Ordering::Equal)
                });
                sorted
            }
        }
    }

    /// Update the EMA latency for a server.
    pub fn update_latency(&self, server: &str, ms: f64) {
        let mut lat = self.latencies.lock().unwrap();
        let ema = lat.entry(server.to_string()).or_insert(ms);
        if (*ema - ms).abs() < f64::EPSILON && *ema == ms {
            // First observation, already set by or_insert
        } else {
            *ema = EMA_ALPHA * ms + (1.0 - EMA_ALPHA) * *ema;
        }
    }

    /// Get a snapshot of current EMA latencies.
    pub fn latencies(&self) -> HashMap<String, f64> {
        self.latencies.lock().unwrap().clone()
    }

    /// Forward a DNS query using the current strategy.
    ///
    /// Returns `(response_bytes, upstream_address)` on success.
    pub async fn forward(&self, query_bytes: &[u8]) -> Result<(Vec<u8>, String), ForwardError> {
        let timeout = Duration::from_millis(self.config.timeout_ms);
        let servers = self.server_order();

        // For round-robin, increment counter after determining order
        if self.strategy() == UpstreamStrategy::RoundRobin {
            self.rr_counter.fetch_add(1, Ordering::Relaxed);
        }

        for server in &servers {
            let start = std::time::Instant::now();
            match self.try_forward(server, query_bytes, timeout).await {
                Ok(response) => {
                    let ms = start.elapsed().as_secs_f64() * 1000.0;
                    self.update_latency(server, ms);
                    return Ok((response, server.clone()));
                }
                Err(_) => continue,
            }
        }

        Err(ForwardError::AllFailed)
    }

    /// Attempt to forward a query to a single upstream server.
    async fn try_forward(
        &self,
        server: &str,
        query_bytes: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, ForwardError> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(server).await?;
        socket.send(query_bytes).await?;

        let mut buf = vec![0u8; 4096];
        let len = tokio::time::timeout(timeout, socket.recv(&mut buf))
            .await
            .map_err(|_| ForwardError::AllFailed)??;

        Ok(buf[..len].to_vec())
    }

    /// Health check all configured upstream servers.
    /// Returns a list of (server, status, latency_ms).
    pub async fn health_check(&self) -> Vec<(String, bool, u64)> {
        let query: [u8; 17] = [
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01,
        ];

        let timeout = Duration::from_millis(self.config.timeout_ms);
        let mut results = Vec::new();

        for server in &self.config.servers {
            let start = std::time::Instant::now();
            let ok = self.try_forward(server, &query, timeout).await.is_ok();
            let ms = start.elapsed().as_millis() as u64;
            results.push((server.clone(), ok, ms));
        }

        results
    }

    /// Probe all servers and update EMA latencies. Used by background task.
    pub async fn probe_all(&self) {
        let query: [u8; 17] = [
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01,
        ];

        let timeout = Duration::from_millis(self.config.timeout_ms);

        for server in &self.config.servers {
            let start = std::time::Instant::now();
            if self.try_forward(server, &query, timeout).await.is_ok() {
                let ms = start.elapsed().as_secs_f64() * 1000.0;
                self.update_latency(server, ms);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_forwarder(strategy: UpstreamStrategy) -> UpstreamForwarder {
        let config = UpstreamConfig {
            servers: vec!["a:53".into(), "b:53".into(), "c:53".into()],
            timeout_ms: 1000,
        };
        let mut f = UpstreamForwarder::new(config);
        f.set_strategy(strategy);
        f
    }

    #[test]
    fn test_sequential_order() {
        let f = make_forwarder(UpstreamStrategy::Sequential);
        let order = f.server_order();
        assert_eq!(order, vec!["a:53", "b:53", "c:53"]);
    }

    #[test]
    fn test_round_robin_rotates() {
        let f = make_forwarder(UpstreamStrategy::RoundRobin);
        let order1 = f.server_order();
        assert_eq!(order1, vec!["a:53", "b:53", "c:53"]);

        f.rr_counter.fetch_add(1, Ordering::Relaxed);
        let order2 = f.server_order();
        assert_eq!(order2, vec!["b:53", "c:53", "a:53"]);

        f.rr_counter.fetch_add(1, Ordering::Relaxed);
        let order3 = f.server_order();
        assert_eq!(order3, vec!["c:53", "a:53", "b:53"]);
    }

    #[test]
    fn test_lowest_latency_order() {
        let f = make_forwarder(UpstreamStrategy::LowestLatency);

        {
            let mut lat = f.latencies.lock().unwrap();
            lat.insert("a:53".into(), 50.0);
            lat.insert("b:53".into(), 10.0);
            lat.insert("c:53".into(), 30.0);
        }

        let order = f.server_order();
        assert_eq!(order, vec!["b:53", "c:53", "a:53"]);
    }

    #[test]
    fn test_lowest_latency_no_data_uses_config_order() {
        let f = make_forwarder(UpstreamStrategy::LowestLatency);
        let order = f.server_order();
        assert_eq!(order, vec!["a:53", "b:53", "c:53"]);
    }

    #[test]
    fn test_ema_update() {
        let f = make_forwarder(UpstreamStrategy::LowestLatency);

        f.update_latency("a:53", 100.0);
        {
            let lat = f.latencies.lock().unwrap();
            assert!((lat["a:53"] - 100.0).abs() < 0.001);
        }

        // EMA = 0.3 * 40 + 0.7 * 100 = 82.0
        f.update_latency("a:53", 40.0);
        {
            let lat = f.latencies.lock().unwrap();
            assert!((lat["a:53"] - 82.0).abs() < 0.001);
        }
    }

    #[test]
    fn test_set_strategy() {
        let f = make_forwarder(UpstreamStrategy::Sequential);
        assert_eq!(f.strategy(), UpstreamStrategy::Sequential);

        f.set_strategy(UpstreamStrategy::RoundRobin);
        assert_eq!(f.strategy(), UpstreamStrategy::RoundRobin);

        f.set_strategy(UpstreamStrategy::LowestLatency);
        assert_eq!(f.strategy(), UpstreamStrategy::LowestLatency);
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo nextest run -p noadd forwarder::tests`
Expected: all 6 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/upstream/forwarder.rs
git commit -m "feat: add strategy support to UpstreamForwarder"
```

---

### Task 3: Settings API and latency endpoint

**Files:**
- Modify: `src/admin/api.rs`

- [ ] **Step 1: Add `upstream_strategy` to known settings keys**

In `get_settings`, add `"upstream_strategy"` to the `keys` array:

```rust
    let keys = [
        "upstream_servers",
        "upstream_strategy",
        "log_retention_days",
        "doh_access_policy",
        "public_url",
    ];
```

- [ ] **Step 2: Wire strategy change in `put_settings`**

After the existing `for (key, value)` loop in `put_settings`, add:

```rust
    // Apply strategy change immediately if present
    if let Some(strategy_str) = body.settings.get("upstream_strategy") {
        if let Ok(strategy) = strategy_str.parse::<crate::upstream::strategy::UpstreamStrategy>() {
            state.forwarder.set_strategy(strategy);
        }
    }
```

- [ ] **Step 3: Add the latency endpoint handler**

Add after the `upstream_health` function:

```rust
async fn upstream_latency(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Vec<serde_json::Value>>, StatusCode> {
    require_auth(&state, &jar)?;
    let latencies = state.forwarder.latencies();
    let strategy = state.forwarder.strategy();

    // Find the preferred server (lowest EMA)
    let preferred = if strategy == crate::upstream::strategy::UpstreamStrategy::LowestLatency {
        latencies
            .iter()
            .min_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(k, _)| k.clone())
    } else {
        None
    };

    let json: Vec<serde_json::Value> = latencies
        .iter()
        .map(|(server, ema)| {
            serde_json::json!({
                "server": server,
                "ema_ms": (*ema * 10.0).round() / 10.0,
                "preferred": preferred.as_ref() == Some(server),
            })
        })
        .collect();
    Ok(Json(json))
}
```

- [ ] **Step 4: Register the route**

Add after the `.route("/api/upstream/health", ...)` line:

```rust
        .route("/api/upstream/latency", get(upstream_latency))
```

- [ ] **Step 5: Verify it compiles**

Run: `cargo check`
Expected: success

- [ ] **Step 6: Commit**

```bash
git add src/admin/api.rs
git commit -m "feat: add upstream strategy setting and latency endpoint"
```

---

### Task 4: Load strategy on startup and add background probe task

**Files:**
- Modify: `src/main.rs`

- [ ] **Step 1: Load strategy from DB after creating forwarder**

After the line `let forwarder = Arc::new(UpstreamForwarder::new(UpstreamConfig::default()));`, add:

```rust
    // Load upstream strategy from DB
    if let Ok(Some(strategy_str)) = db.get_setting("upstream_strategy").await {
        if let Ok(strategy) = strategy_str.parse::<noadd::upstream::strategy::UpstreamStrategy>() {
            forwarder.set_strategy(strategy);
            tracing::info!(%strategy_str, "loaded upstream strategy from DB");
        }
    }
```

- [ ] **Step 2: Add background probe task**

Add after the log pruning task (after the `// 16. Background log pruning` block), before the `// 17. Serve HTTP` section:

```rust
    // 17. Background upstream latency probe (every 60s, only for lowest-latency strategy)
    let probe_forwarder = forwarder.clone();
    let mut shutdown_rx = shutdown_tx.subscribe();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        interval.tick().await; // skip first immediate tick
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if probe_forwarder.strategy()
                        == noadd::upstream::strategy::UpstreamStrategy::LowestLatency
                    {
                        probe_forwarder.probe_all().await;
                        tracing::debug!("upstream latency probe complete");
                    }
                }
                _ = shutdown_rx.recv() => break,
            }
        }
    });
```

- [ ] **Step 3: Update the section comment numbers**

Renumber `// 17. Serve HTTP` to `// 18. Serve HTTP` and `// 18. Cleanup` to `// 19. Cleanup`.

- [ ] **Step 4: Verify it compiles**

Run: `cargo check`
Expected: success

- [ ] **Step 5: Commit**

```bash
git add src/main.rs
git commit -m "feat: load strategy from DB and add background latency probe"
```

---

### Task 5: Integration tests

**Files:**
- Modify: `tests/admin_api_test.rs`

- [ ] **Step 1: Add test for strategy setting round-trip**

Add at the end of `tests/admin_api_test.rs`:

```rust
#[tokio::test]
async fn test_upstream_strategy_setting() {
    let (app, token) = setup().await;

    // Set strategy to round-robin
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/settings")
                .header("content-type", "application/json")
                .header("cookie", format!("session={token}"))
                .body(Body::from(r#"{"upstream_strategy":"round-robin"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Read it back
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/settings")
                .header("cookie", format!("session={token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["settings"]["upstream_strategy"], "round-robin");
}
```

- [ ] **Step 2: Add test for latency endpoint**

Add at the end of `tests/admin_api_test.rs`:

```rust
#[tokio::test]
async fn test_upstream_latency_endpoint() {
    let (app, token) = setup().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/upstream/latency")
                .header("cookie", format!("session={token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json.is_array());
}
```

- [ ] **Step 3: Run new tests**

Run: `cargo nextest run -p noadd test_upstream_strategy_setting test_upstream_latency_endpoint`
Expected: PASS

- [ ] **Step 4: Run full test suite**

Run: `cargo nextest run`
Expected: all tests PASS

- [ ] **Step 5: Commit**

```bash
git add tests/admin_api_test.rs
git commit -m "test: add upstream strategy and latency endpoint tests"
```

---

### Task 6: Admin UI — strategy dropdown and EMA display

**Files:**
- Modify: `admin-ui/dist/index.html`

- [ ] **Step 1: Add strategy dropdown to Upstream DNS card**

In the SettingsPage `connectedCallback`, find the Upstream DNS card div that contains the `#s-upstream` input. After the `<div id="upstream-health" ...></div>` line, add:

```html
        <div class="card-title" style="margin-top:16px">Strategy</div>
        <p style="color:var(--text-secondary);font-size:0.85rem;margin-bottom:8px">
          How upstream servers are selected for each DNS query.
        </p>
        <div class="input-row">
          <select id="s-strategy">
            <option value="sequential">Sequential (try in order)</option>
            <option value="round-robin">Round Robin (rotate)</option>
            <option value="lowest-latency">Lowest Latency (fastest first)</option>
          </select>
        </div>
        <div id="ema-latency" style="margin-top:12px"></div>
```

- [ ] **Step 2: Add strategy auto-save handler**

After the `this.querySelector('#s-doh-policy').onchange` handler, add:

```javascript
    this.querySelector('#s-strategy').onchange = async (e) => {
      await api.put('/api/settings', { upstream_strategy: e.target.value });
      this.loadEma();
    };
```

- [ ] **Step 3: Include strategy in save-settings payload**

In the `#save-settings` onclick handler, add `upstream_strategy` to the settings object:

```javascript
      const settings = {
        upstream_servers: this.querySelector('#s-upstream').value,
        upstream_strategy: this.querySelector('#s-strategy').value,
        log_retention_days: this.querySelector('#s-retention').value,
        doh_access_policy: this.querySelector('#s-doh-policy').value,
        public_url: this.querySelector('#s-public-url').value,
      };
```

- [ ] **Step 4: Load strategy value and EMA data**

In the `load()` method, after `this.querySelector('#s-doh-policy').value = s.doh_access_policy || 'allow';`, add:

```javascript
      this.querySelector('#s-strategy').value = s.upstream_strategy || 'sequential';
      this.loadEma();
```

- [ ] **Step 5: Add loadEma method**

Add a new method to the SettingsPage class, after the `loadTokens()` method:

```javascript
  async loadEma() {
    const el = this.querySelector('#ema-latency');
    const strategy = this.querySelector('#s-strategy').value;
    if (strategy !== 'lowest-latency') {
      el.innerHTML = '';
      return;
    }
    try {
      const data = await api.get('/api/upstream/latency');
      if (!data || !data.length) {
        el.innerHTML = '<p style="color:var(--text-dim);font-size:0.85rem">No latency data yet. Data will appear after queries are processed.</p>';
        return;
      }
      let html = '<table><thead><tr><th>Server</th><th>EMA Latency</th><th></th></tr></thead><tbody>';
      for (const d of data) {
        const badge = d.preferred ? ' <span class="badge badge-allowed">preferred</span>' : '';
        html += `<tr><td style="font-family:var(--font-mono)">${esc(d.server)}</td><td>${d.ema_ms.toFixed(1)}ms</td><td>${badge}</td></tr>`;
      }
      html += '</tbody></table>';
      el.innerHTML = html;
    } catch (e) {
      el.innerHTML = '';
    }
  }
```

- [ ] **Step 6: Verify it compiles and renders**

Run: `cargo check`
Expected: success (the HTML is compiled into the binary via `include_dir!`)

- [ ] **Step 7: Commit**

```bash
git add admin-ui/dist/index.html
git commit -m "feat: add strategy dropdown and EMA display to admin UI"
```

---

### Task 7: Final verification

- [ ] **Step 1: Run full test suite**

Run: `cargo nextest run`
Expected: all tests PASS

- [ ] **Step 2: Verify clippy passes**

Run: `cargo clippy -- -D warnings`
Expected: no warnings

- [ ] **Step 3: Fix any issues found**

Address any compilation errors, test failures, or clippy warnings.

- [ ] **Step 4: Final commit if any fixes were needed**

```bash
git add -u
git commit -m "fix: address clippy warnings and test issues"
```
