// crates/redteamer-orchestrator/src/scan.rs

use redteamer_core::error::RedTeamerError;
use redteamer_core::error::Result;
use redteamer_core::traits::adapter::TargetAdapter;
use redteamer_core::traits::detector::Detector;
use redteamer_core::traits::probe::Probe;
use redteamer_core::types::AttackRecord;
use std::sync::Arc;
use tokio::task::JoinSet;
use uuid::Uuid;

/// Default per-probe concurrency when the caller does not specify one.
pub const DEFAULT_CONCURRENCY: usize = 8;

/// Fully-resolved configuration for one scan campaign.
#[derive(Clone)]
pub struct ScanConfig {
    /// Ties every emitted [`AttackRecord`] to this campaign.
    pub session_id: Uuid,
    pub target: Arc<dyn TargetAdapter>,
    pub probes: Vec<Arc<dyn Probe>>,
    pub detectors: Vec<Arc<dyn Detector>>,
    pub concurrency: usize,
    pub(crate) progress_callback: Option<Arc<dyn Fn(usize) + Send + Sync>>,
}

impl std::fmt::Debug for ScanConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Trait-object fields are not Debug; report composition shape only.
        f.debug_struct("ScanConfig")
            .field("session_id", &self.session_id)
            .field("target", &self.target.info().name)
            .field("probe_count", &self.probes.len())
            .field("detector_count", &self.detectors.len())
            .field("concurrency", &self.concurrency)
            .finish()
    }
}

impl ScanConfig {
    /// Executes all probes concurrently and collects their records.
    ///
    /// Each probe runs in its own tokio task; probe-level fatal errors are
    /// reported via [`ScanReport::failed_probes`] while successful records
    /// are aggregated into [`ScanReport::records`].
    pub async fn execute(self) -> ScanReport {
        let detectors: Arc<[Arc<dyn Detector>]> = Arc::from(self.detectors.clone());
        let mut tasks = JoinSet::new();

        for probe in self.probes {
            let session_id = self.session_id;
            let target = Arc::clone(&self.target);
            let concurrency = self.concurrency;
            let detectors = Arc::clone(&detectors);

            tasks.spawn(async move { probe.run(session_id, target, concurrency, detectors).await });
        }

        let mut report =
            ScanReport::new(self.session_id, self.target.info().model.clone());

        while let Some(joined) = tasks.join_next().await {
            match joined {
                Ok(Ok(records)) => {
                    report.records.extend(records);
                    if let Some(cb) = &self.progress_callback {
                        cb(report.records.len());
                    }
                }
                Ok(Err(err)) => report.failed_probes.push(err.to_string()),
                // Probe task panicked or was cancelled.
                Err(join_err) => report.failed_probes.push(format!("task failure: {join_err}")),
            }
        }

        report
    }

    /// Moves this config onto the tokio runtime as a background task.
    ///
    /// Returns the [`JoinHandle`](tokio::task::JoinHandle) so callers can
    /// fire-and-forget long scans or await them for the final report.
    #[must_use]
    pub fn spawn(self) -> tokio::task::JoinHandle<ScanReport> {
        tokio::spawn(self.execute())
    }
}

/// Result of a completed scan.
#[derive(Debug, Clone)]
pub struct ScanReport {
    pub session_id: Uuid,
    #[allow(dead_code)] // consumed by reporters in Phase 1, Week 3
    pub target_model: Option<String>,
    pub records: Vec<AttackRecord>,
    /// Human-readable descriptions of probes that failed fatally.
    pub failed_probes: Vec<String>,
}

impl ScanReport {
    fn new(session_id: Uuid, target_model: Option<String>) -> Self {
        Self {
            session_id,
            target_model,
            records: Vec::new(),
            failed_probes: Vec::new(),
        }
    }

    /// Number of attempts whose rolled-up verdict is `Vulnerable`.
    #[must_use]
    pub fn vulnerable_count(&self) -> usize {
        self.records.iter().filter(|r| r.verdict.is_vulnerable()).count()
    }
}

/// Builder for [`ScanConfig`] with fluent registration of plugins.
///
/// ```no_run
/// # use std::sync::Arc;
/// # async fn example() -> redteamer_core::error::Result<()> {
/// # let adapter: Arc<dyn redteamer_core::traits::TargetAdapter> = todo!();
/// # let probe: Arc<dyn redteamer_core::traits::Probe> = todo!();
/// let handle = redteamer_orchestrator::ScanBuilder::new()
///     .target(adapter)
///     .probe(probe)
///     .concurrency(16)
///     .build()?
///     .spawn(); // fire-and-forget; await the JoinHandle to collect results
/// let _report = handle.await.expect("scan task panicked");
/// # Ok(())
/// # }
/// ```
#[derive(Default)]
pub struct ScanBuilder {
    target: Option<Arc<dyn TargetAdapter>>,
    probes: Vec<Arc<dyn Probe>>,
    detectors: Vec<Arc<dyn Detector>>,
    concurrency: Option<usize>,
    session_id: Option<Uuid>,
    progress_callback: Option<Arc<dyn Fn(usize) + Send + Sync>>,
}

impl ScanBuilder {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            target: None,
            probes: Vec::new(),
            detectors: Vec::new(),
            concurrency: None,
            session_id: None,
            progress_callback: None,
        }
    }

    /// Registers the target adapter (required).
    #[must_use]
    pub fn target(mut self, target: Arc<dyn TargetAdapter>) -> Self {
        self.target = Some(target);
        self
    }

    /// Registers one probe (repeatable).
    #[must_use]
    pub fn probe(mut self, probe: Arc<dyn Probe>) -> Self {
        self.probes.push(probe);
        self
    }

    /// Registers several probes at once.
    #[must_use]
    pub fn probes(mut self, probes: impl IntoIterator<Item = Arc<dyn Probe>>) -> Self {
        self.probes.extend(probes);
        self
    }

    /// Registers one detector (repeatable).
    #[must_use]
    pub fn detector(mut self, detector: Arc<dyn Detector>) -> Self {
        self.detectors.push(detector);
        self
    }

    /// Overrides the default per-probe concurrency hint.
    #[must_use]
    pub const fn concurrency(mut self, concurrency: usize) -> Self {
        self.concurrency = Some(concurrency);
        self
    }

    /// Pins a specific session id instead of generating a fresh UUID.
    #[must_use]
    pub const fn session_id(mut self, session_id: Uuid) -> Self {
        self.session_id = Some(session_id);
        self
    }

    /// Registers a callback fired after each probe completes, with the running total record count.
    #[must_use]
    pub fn on_record_progress(mut self, callback: impl Fn(usize) + Send + Sync + 'static) -> Self {
        self.progress_callback = Some(Arc::new(callback));
        self
    }

    /// Validates and freezes the configuration.
    ///
    /// # Errors
    /// Returns [`RedTeamerError::InvalidConfig`] if no target was set.
    pub fn build(self) -> Result<ScanConfig> {
        Ok(ScanConfig {
            session_id: self.session_id.unwrap_or_else(Uuid::new_v4),
            target: self.target.ok_or_else(|| {
                RedTeamerError::InvalidConfig("scan requires a target adapter".into())
            })?,
            probes: self.probes,
            detectors: self.detectors,
            concurrency: self
                .concurrency
                .filter(|c| *c > 0)
                .unwrap_or(DEFAULT_CONCURRENCY),
            progress_callback: self.progress_callback,
        })
    }
}
