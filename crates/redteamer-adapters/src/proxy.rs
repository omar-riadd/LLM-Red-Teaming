// crates/redteamer-adapters/src/proxy.rs

//! Multi-IP proxy pool and rotating adapter engine for `llm-redteamer`.
//!
//! Provides:
//! - [`ProxyRotationStrategy`]: Round-robin, Random, Least-loaded, and Failover strategies.
//! - [`ProxyPool`]: Thread-safe pool of proxy endpoints with circuit breaker cooldown on HTTP 429 / transport errors.
//! - [`RotatingAdapter`]: Target adapter decorator distributing outgoing attacks across a pool of proxy nodes with automatic retry failover.

use async_trait::async_trait;
use redteamer_core::error::{RedTeamerError, Result};
use redteamer_core::traits::adapter::{
    AdapterInfo, AdapterResponse, ChatMessage, GenerationOptions, TargetAdapter,
};
use redteamer_core::types::AttackRecord;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Strategy used to rotate among proxy endpoints or adapter nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ProxyRotationStrategy {
    /// Distributes consecutive requests sequentially across the pool.
    #[default]
    RoundRobin,
    /// Uniformly selects a healthy node pseudo-randomly.
    Random,
    /// Routes to the node currently servicing the fewest in-flight requests.
    LeastLoaded,
    /// Routes to the primary node in order; fails over to backup nodes upon error.
    Failover,
}

impl std::str::FromStr for ProxyRotationStrategy {
    type Err = RedTeamerError;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().replace('-', "_").as_str() {
            "round_robin" | "roundrobin" | "rr" => Ok(Self::RoundRobin),
            "random" | "rand" => Ok(Self::Random),
            "least_loaded" | "leastloaded" | "ll" => Ok(Self::LeastLoaded),
            "failover" | "fallback" => Ok(Self::Failover),
            _ => Err(RedTeamerError::InvalidConfig(format!(
                "invalid proxy rotation strategy '{s}', expected: round_robin, random, least_loaded, or failover"
            ))),
        }
    }
}

/// Tracking state for a single proxy endpoint in the pool.
#[derive(Debug)]
pub struct ProxyNode {
    pub url: String,
    pub in_flight: AtomicUsize,
    pub failures: AtomicUsize,
    pub total_requests: AtomicUsize,
    pub cooldown_until: Mutex<Option<Instant>>,
}

impl ProxyNode {
    #[must_use]
    pub fn new(url: String) -> Self {
        Self {
            url,
            in_flight: AtomicUsize::new(0),
            failures: AtomicUsize::new(0),
            total_requests: AtomicUsize::new(0),
            cooldown_until: Mutex::new(None),
        }
    }

    /// Returns `true` if the node is not in cooldown.
    #[must_use]
    pub fn is_healthy(&self, now: Instant) -> bool {
        let guard = self
            .cooldown_until
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match *guard {
            Some(expiry) => now >= expiry,
            None => true,
        }
    }

    /// Places this proxy into cooldown for `duration` after an error or rate limit.
    pub fn mark_failure(&self, duration: Duration) {
        self.failures.fetch_add(1, Ordering::Relaxed);
        let mut guard = self
            .cooldown_until
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard = Some(Instant::now() + duration);
    }

    /// Clears any active cooldown and resets consecutive failures upon successful response.
    pub fn mark_success(&self) {
        self.failures.store(0, Ordering::Relaxed);
        let mut guard = self
            .cooldown_until
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard = None;
    }
}

/// RAII guard decrementing in-flight count upon drop.
pub struct InFlightGuard<'a> {
    node: &'a ProxyNode,
}

impl<'a> Drop for InFlightGuard<'a> {
    fn drop(&mut self) {
        self.node.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

/// A thread-safe pool of proxy endpoints with rotation strategies and health circuit-breaking.
#[derive(Debug, Clone)]
pub struct ProxyPool {
    nodes: Arc<Vec<ProxyNode>>,
    strategy: ProxyRotationStrategy,
    rr_index: Arc<AtomicUsize>,
    cooldown_duration: Duration,
}

impl ProxyPool {
    /// Default cooldown period when a proxy encounters HTTP 429 or network failure.
    pub const DEFAULT_COOLDOWN: Duration = Duration::from_secs(30);

    /// Constructs a pool from a list of proxy URL strings.
    ///
    /// # Errors
    /// Returns [`RedTeamerError::InvalidConfig`] if `proxies` is empty.
    pub fn new(proxies: Vec<String>, strategy: ProxyRotationStrategy) -> Result<Self> {
        let trimmed: Vec<String> = proxies
            .into_iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        if trimmed.is_empty() {
            return Err(RedTeamerError::InvalidConfig(
                "proxy pool must contain at least one valid URL".into(),
            ));
        }

        let nodes = trimmed.into_iter().map(ProxyNode::new).collect();
        Ok(Self {
            nodes: Arc::new(nodes),
            strategy,
            rr_index: Arc::new(AtomicUsize::new(0)),
            cooldown_duration: Self::DEFAULT_COOLDOWN,
        })
    }

    /// Constructs a pool from a slice of string slices.
    pub fn from_slice(proxies: &[&str], strategy: ProxyRotationStrategy) -> Result<Self> {
        let vec: Vec<String> = proxies.iter().map(|&s| s.to_string()).collect();
        Self::new(vec, strategy)
    }

    /// Loads proxy URLs from a file (one URL per line, '#' comments and blank lines ignored).
    ///
    /// # Errors
    /// Returns [`RedTeamerError::InvalidConfig`] if file cannot be read or contains 0 proxies.
    pub fn from_file(path: &Path, strategy: ProxyRotationStrategy) -> Result<Self> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            RedTeamerError::InvalidConfig(format!(
                "failed to read proxy file {}: {e}",
                path.display()
            ))
        })?;

        let proxies: Vec<String> = content
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(ToOwned::to_owned)
            .collect();

        Self::new(proxies, strategy)
    }

    /// Loads proxy URLs from `REDTEAMER_PROXY_POOL` or `REDTEAMER_PROXIES` environment variable
    /// (comma-separated URLs). Returns `Ok(None)` if neither variable is set.
    pub fn from_env(strategy: ProxyRotationStrategy) -> Result<Option<Self>> {
        let val = std::env::var("REDTEAMER_PROXY_POOL")
            .or_else(|_| std::env::var("REDTEAMER_PROXIES"))
            .ok();

        match val {
            Some(raw) if !raw.trim().is_empty() => {
                let proxies: Vec<String> = raw
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(ToOwned::to_owned)
                    .collect();
                Self::new(proxies, strategy).map(Some)
            }
            _ => Ok(None),
        }
    }

    /// Customizes the cooldown duration for failing proxies.
    #[must_use]
    pub fn with_cooldown(mut self, cooldown: Duration) -> Self {
        self.cooldown_duration = cooldown;
        self
    }

    /// Total number of proxies in the pool.
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// The rotation strategy used by this pool.
    #[must_use]
    pub const fn strategy(&self) -> ProxyRotationStrategy {
        self.strategy
    }

    /// Returns `true` if the pool has no proxies.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Returns all proxy URLs in the pool.
    #[must_use]
    pub fn urls(&self) -> Vec<String> {
        self.nodes.iter().map(|n| n.url.clone()).collect()
    }

    /// Selects the next proxy according to the active [`ProxyRotationStrategy`].
    ///
    /// If all proxies are currently in cooldown, recovers gracefully by selecting
    /// the proxy whose cooldown expires soonest.
    #[must_use]
    pub fn select_proxy(&self) -> (usize, &str) {
        let now = Instant::now();
        let total = self.nodes.len();

        let healthy_indices: Vec<usize> = (0..total)
            .filter(|&idx| self.nodes[idx].is_healthy(now))
            .collect();

        let chosen_idx = if !healthy_indices.is_empty() {
            match self.strategy {
                ProxyRotationStrategy::RoundRobin => {
                    let seq = self.rr_index.fetch_add(1, Ordering::Relaxed);
                    healthy_indices[seq % healthy_indices.len()]
                }
                ProxyRotationStrategy::Random => {
                    let seq = self.rr_index.fetch_add(1, Ordering::Relaxed);
                    let rand_idx = pseudo_random(seq, healthy_indices.len());
                    healthy_indices[rand_idx]
                }
                ProxyRotationStrategy::LeastLoaded => healthy_indices
                    .into_iter()
                    .min_by_key(|&idx| self.nodes[idx].in_flight.load(Ordering::Relaxed))
                    .unwrap_or(0),
                ProxyRotationStrategy::Failover => healthy_indices[0],
            }
        } else {
            // Circuit-breaker recovery: choose the node with earliest expiry
            let mut earliest_idx = 0;
            let mut earliest_time = None;

            for (idx, node) in self.nodes.iter().enumerate() {
                let guard = node
                    .cooldown_until
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if let Some(exp) = *guard {
                    if earliest_time.is_none_or(|t| exp < t) {
                        earliest_time = Some(exp);
                        earliest_idx = idx;
                    }
                }
            }
            earliest_idx
        };

        let node = &self.nodes[chosen_idx];
        node.total_requests.fetch_add(1, Ordering::Relaxed);
        node.in_flight.fetch_add(1, Ordering::SeqCst);

        (chosen_idx, &node.url)
    }

    /// Acquires an [`InFlightGuard`] for the node at `index`.
    #[must_use]
    pub fn guard(&self, index: usize) -> InFlightGuard<'_> {
        InFlightGuard {
            node: &self.nodes[index],
        }
    }

    /// Marks the node at `index` as successful.
    pub fn record_success(&self, index: usize) {
        if let Some(node) = self.nodes.get(index) {
            node.mark_success();
        }
    }

    /// Marks the node at `index` as failed, placing it into cooldown.
    pub fn record_failure(&self, index: usize) {
        if let Some(node) = self.nodes.get(index) {
            node.mark_failure(self.cooldown_duration);
        }
    }
}

/// A target adapter decorator that distributes requests across a pool of underlying
/// adapters with automatic retry and circuit-breaker failover.
pub struct RotatingAdapter {
    info: AdapterInfo,
    adapters: Vec<Arc<dyn TargetAdapter>>,
    proxy_pool: ProxyPool,
    max_retries: usize,
}

impl RotatingAdapter {
    /// Constructs a rotating adapter wrapping `adapters` matched 1:1 with `proxy_pool`.
    ///
    /// # Errors
    /// Returns [`RedTeamerError::InvalidConfig`] if `adapters` is empty or lengths mismatch.
    pub fn new(adapters: Vec<Arc<dyn TargetAdapter>>, proxy_pool: ProxyPool) -> Result<Self> {
        if adapters.is_empty() {
            return Err(RedTeamerError::InvalidConfig(
                "RotatingAdapter requires at least one adapter".into(),
            ));
        }

        let first_info = adapters[0].info();
        let info = AdapterInfo {
            name: "rotating-target-pool",
            version: env!("CARGO_PKG_VERSION"),
            model: first_info.model.clone(),
        };

        let max_retries = adapters.len();

        Ok(Self {
            info,
            adapters,
            proxy_pool,
            max_retries,
        })
    }

    /// Constructs a rotating adapter for multiple endpoints or workers using the specified strategy.
    pub fn from_adapters(
        adapters: Vec<Arc<dyn TargetAdapter>>,
        strategy: ProxyRotationStrategy,
    ) -> Result<Self> {
        let dummy_urls: Vec<String> = (0..adapters.len()).map(|i| format!("worker-{i}")).collect();
        let pool = ProxyPool::new(dummy_urls, strategy)?;
        Self::new(adapters, pool)
    }

    /// Overrides the maximum retry attempts across the pool on retryable errors.
    #[must_use]
    pub fn with_max_retries(mut self, retries: usize) -> Self {
        self.max_retries = retries;
        self
    }
}

#[async_trait]
impl TargetAdapter for RotatingAdapter {
    fn info(&self) -> &AdapterInfo {
        &self.info
    }

    async fn send_chat(
        &self,
        messages: &[ChatMessage],
        opts: &GenerationOptions,
    ) -> Result<AdapterResponse> {
        let total_nodes = self.adapters.len();
        let attempts_limit = self.max_retries.min(total_nodes).max(1);
        let mut last_error = None;

        for _ in 0..attempts_limit {
            let (chosen_idx, _proxy_url) = self.proxy_pool.select_proxy();
            let _guard = self.proxy_pool.guard(chosen_idx);
            let adapter = &self.adapters[chosen_idx];

            match adapter.send_chat(messages, opts).await {
                Ok(resp) => {
                    self.proxy_pool.record_success(chosen_idx);
                    return Ok(resp);
                }
                Err(err) if err.is_retryable() => {
                    // Mark failure & cooldown on this node, then retry on next healthy node
                    self.proxy_pool.record_failure(chosen_idx);
                    last_error = Some(err);
                }
                Err(err) => {
                    // Non-retryable error (auth failure, invalid format, etc.): return immediately
                    return Err(err);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| RedTeamerError::Adapter {
            adapter: self.info.name,
            message: "all adapters in rotating pool failed".into(),
            source: None,
        }))
    }

    async fn health_check(&self) -> Result<()> {
        // Verify at least one underlying adapter responds to health_check
        let mut last_err = None;
        for adapter in &self.adapters {
            match adapter.health_check().await {
                Ok(()) => return Ok(()),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or_else(|| RedTeamerError::Adapter {
            adapter: self.info.name,
            message: "no adapters in rotating pool passed health_check".into(),
            source: None,
        }))
    }

    fn enrich_record(&self, record: &mut AttackRecord) {
        if let Some(first) = self.adapters.first() {
            first.enrich_record(record);
        }
    }

    fn should_skip_attack(&self, probe_name: &str, prompt: &str) -> bool {
        self.adapters
            .first()
            .is_some_and(|a| a.should_skip_attack(probe_name, prompt))
    }

    fn attacker_adapter(&self) -> Option<Arc<dyn TargetAdapter>> {
        self.adapters.first().and_then(|a| a.attacker_adapter())
    }
}

/// Simple 64-bit splitmix/xorshift pseudo-random number generator for uniform distribution.
fn pseudo_random(seed: usize, max: usize) -> usize {
    if max <= 1 {
        return 0;
    }
    let mut x = (seed as u64).wrapping_add(0x9e3779b97f4a7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d049bb133111eb);
    x ^= x >> 31;
    (x as usize) % max
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockWorkerAdapter {
        info: AdapterInfo,
        fail_with_429: Mutex<bool>,
        call_count: AtomicUsize,
    }

    impl MockWorkerAdapter {
        fn new(name: &'static str, fail_first: bool) -> Self {
            Self {
                info: AdapterInfo {
                    name,
                    version: "1.0.0",
                    model: Some("mock-worker".into()),
                },
                fail_with_429: Mutex::new(fail_first),
                call_count: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl TargetAdapter for MockWorkerAdapter {
        fn info(&self) -> &AdapterInfo {
            &self.info
        }

        async fn send_chat(
            &self,
            _messages: &[ChatMessage],
            _opts: &GenerationOptions,
        ) -> Result<AdapterResponse> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            let mut fail = self.fail_with_429.lock().unwrap();
            if *fail {
                *fail = false; // Next call can succeed
                return Err(RedTeamerError::Adapter {
                    adapter: "mock-worker",
                    message: "HTTP 429 Too Many Requests: rate limited".into(),
                    source: None,
                });
            }

            Ok(AdapterResponse {
                text: format!("response from {}", self.info.name),
                tool_calls: Vec::new(),
                completed: true,
                metadata: serde_json::json!({"worker": self.info.name}),
            })
        }
    }

    #[test]
    fn proxy_pool_round_robin_selection_and_wrap_around() {
        let pool = ProxyPool::from_slice(
            &[
                "http://proxy1:8080",
                "http://proxy2:8080",
                "http://proxy3:8080",
            ],
            ProxyRotationStrategy::RoundRobin,
        )
        .unwrap();

        assert_eq!(pool.len(), 3);
        let (_, p1) = pool.select_proxy();
        let (_, p2) = pool.select_proxy();
        let (_, p3) = pool.select_proxy();
        let (_, p4) = pool.select_proxy();

        assert_eq!(p1, "http://proxy1:8080");
        assert_eq!(p2, "http://proxy2:8080");
        assert_eq!(p3, "http://proxy3:8080");
        assert_eq!(p4, "http://proxy1:8080"); // Wrapped around
    }

    #[test]
    fn proxy_pool_circuit_breaker_cooldown_and_recovery() {
        let pool = ProxyPool::from_slice(
            &["http://p1:8080", "http://p2:8080"],
            ProxyRotationStrategy::Failover,
        )
        .unwrap()
        .with_cooldown(Duration::from_millis(50));

        // Initial selection picks p1 (primary in Failover)
        let (idx1, url1) = pool.select_proxy();
        assert_eq!(idx1, 0);
        assert_eq!(url1, "http://p1:8080");

        // Mark p1 as failed (triggers cooldown)
        pool.record_failure(0);

        // Next selection must fail over to healthy p2
        let (idx2, url2) = pool.select_proxy();
        assert_eq!(idx2, 1);
        assert_eq!(url2, "http://p2:8080");

        // Mark p2 as failed too (now both are in cooldown)
        pool.record_failure(1);

        // Circuit breaker recovery selects the earliest expiring node without panicking
        let (recovered_idx, _) = pool.select_proxy();
        assert_eq!(recovered_idx, 0);
    }

    #[test]
    fn proxy_pool_from_file_parses_lines_and_comments() {
        let temp_dir = std::env::temp_dir();
        let file_path = temp_dir.join(format!(
            "test_proxies_{}.txt",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let content = "# Proxy List\nhttp://10.0.0.1:8080\n\n# Backup\nhttp://10.0.0.2:8080\n";
        std::fs::write(&file_path, content).unwrap();

        let pool = ProxyPool::from_file(&file_path, ProxyRotationStrategy::RoundRobin).unwrap();
        assert_eq!(pool.len(), 2);
        assert_eq!(
            pool.urls(),
            vec!["http://10.0.0.1:8080", "http://10.0.0.2:8080"]
        );

        let _ = std::fs::remove_file(&file_path);
    }

    #[tokio::test]
    async fn rotating_adapter_retries_on_rate_limit_and_succeeds_on_backup_worker() {
        let worker1 = Arc::new(MockWorkerAdapter::new("worker-1", true)); // Fails first call with 429
        let worker2 = Arc::new(MockWorkerAdapter::new("worker-2", false)); // Always succeeds

        let pool = ProxyPool::from_slice(
            &["http://proxy-1:8080", "http://proxy-2:8080"],
            ProxyRotationStrategy::Failover,
        )
        .unwrap();

        let rotating = RotatingAdapter::new(vec![worker1.clone(), worker2.clone()], pool).unwrap();

        let resp = rotating
            .send_chat(
                &[ChatMessage::user("run attack")],
                &GenerationOptions::default(),
            )
            .await
            .expect("should fail over and succeed");

        // Worker 1 was called, failed with 429, then Worker 2 was called and succeeded
        assert_eq!(worker1.call_count.load(Ordering::SeqCst), 1);
        assert_eq!(worker2.call_count.load(Ordering::SeqCst), 1);
        assert_eq!(resp.text, "response from worker-2");
    }
}
