// crates/redteamer-orchestrator/src/scan.rs

use async_trait::async_trait;
use redteamer_core::error::RedTeamerError;
use redteamer_core::error::Result;
use redteamer_core::traits::adapter::{
    AdapterInfo, AdapterResponse, ChatMessage, GenerationOptions, TargetAdapter,
};
use redteamer_core::traits::detector::Detector;
use redteamer_core::traits::probe::Probe;
use redteamer_core::types::{AttackRecord, Verdict};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use uuid::Uuid;

/// Default campaign-wide concurrency when the caller does not specify one.
pub const DEFAULT_CONCURRENCY: usize = 8;

type RecordCallback = Arc<dyn Fn(&AttackRecord) + Send + Sync>;

/// Internal adapter wrapper enforcing a single campaign-wide concurrency cap
/// across all active probes, firing progress updates after every completed request,
/// streaming finalized records via `on_record_complete`, and skipping resumed keys.
struct ThrottledAdapter {
    inner: Arc<dyn TargetAdapter>,
    attacker: Option<Arc<dyn TargetAdapter>>,
    semaphore: Arc<Semaphore>,
    completed_requests: Arc<std::sync::Mutex<usize>>,
    progress_callback: Option<Arc<dyn Fn(usize) + Send + Sync>>,
    record_callback: Option<RecordCallback>,
    emitted_ids: Arc<std::sync::Mutex<HashSet<Uuid>>>,
    completed_keys: Arc<HashSet<(String, String)>>,
}

#[async_trait]
impl TargetAdapter for ThrottledAdapter {
    fn info(&self) -> &AdapterInfo {
        self.inner.info()
    }

    async fn send_chat(
        &self,
        messages: &[ChatMessage],
        opts: &GenerationOptions,
    ) -> Result<AdapterResponse> {
        let _permit = self
            .semaphore
            .acquire()
            .await
            .expect("campaign semaphore is never closed");
        let res = self.inner.send_chat(messages, opts).await;
        {
            let mut guard = self
                .completed_requests
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *guard += 1;
            if let Some(cb) = &self.progress_callback {
                cb(*guard);
            }
        }
        res
    }

    async fn health_check(&self) -> Result<()> {
        self.inner.health_check().await
    }

    fn enrich_record(&self, record: &mut AttackRecord) {
        self.inner.enrich_record(record);
        let is_new = self
            .emitted_ids
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(record.id);
        if is_new {
            if let Some(cb) = &self.record_callback {
                cb(record);
            }
        }
    }

    fn should_skip_attack(&self, probe_name: &str, prompt: &str) -> bool {
        self.completed_keys
            .contains(&(probe_name.to_owned(), prompt.to_owned()))
            || self.inner.should_skip_attack(probe_name, prompt)
    }

    fn attacker_adapter(&self) -> Option<Arc<dyn TargetAdapter>> {
        self.attacker
            .clone()
            .or_else(|| self.inner.attacker_adapter())
    }
}

/// Fully-resolved configuration for one scan campaign.
#[derive(Clone)]
pub struct ScanConfig {
    /// Ties every emitted [`AttackRecord`] to this campaign.
    pub session_id: Uuid,
    pub target: Arc<dyn TargetAdapter>,
    pub attacker: Option<Arc<dyn TargetAdapter>>,
    pub probes: Vec<Arc<dyn Probe>>,
    pub detectors: Vec<Arc<dyn Detector>>,
    pub concurrency: usize,
    pub resume_records: Vec<AttackRecord>,
    pub(crate) progress_callback: Option<Arc<dyn Fn(usize) + Send + Sync>>,
    pub(crate) record_callback: Option<RecordCallback>,
}

impl std::fmt::Debug for ScanConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Trait-object fields are not Debug; report composition shape only.
        f.debug_struct("ScanConfig")
            .field("session_id", &self.session_id)
            .field("target", &self.target.info().name)
            .field("has_attacker", &self.attacker.is_some())
            .field("probe_count", &self.probes.len())
            .field("detector_count", &self.detectors.len())
            .field("concurrency", &self.concurrency)
            .field("resume_records", &self.resume_records.len())
            .finish()
    }
}

impl ScanConfig {
    /// Executes all probes concurrently and collects their records.
    ///
    /// Each probe runs in its own tokio task while sharing a single
    /// campaign-wide concurrency semaphore; probe-level fatal errors are
    /// reported via [`ScanReport::failed_probes`] while successful records
    /// are aggregated and deterministically sorted into [`ScanReport::records`].
    pub async fn execute(self) -> ScanReport {
        let kept_resume: Vec<AttackRecord> = self
            .resume_records
            .into_iter()
            .filter(|r| r.verdict != Verdict::Error)
            .collect();
        let completed_keys: Arc<HashSet<(String, String)>> = Arc::new(
            kept_resume
                .iter()
                .map(|r| (r.probe_name.clone(), r.prompt.clone()))
                .collect(),
        );
        let emitted_ids: Arc<std::sync::Mutex<HashSet<Uuid>>> = Arc::new(std::sync::Mutex::new(
            kept_resume.iter().map(|r| r.id).collect(),
        ));

        let detectors: Arc<[Arc<dyn Detector>]> = Arc::from(self.detectors.clone());
        let completed_requests = Arc::new(std::sync::Mutex::new(kept_resume.len()));
        let throttled_target: Arc<dyn TargetAdapter> = Arc::new(ThrottledAdapter {
            inner: Arc::clone(&self.target),
            attacker: self.attacker.clone(),
            semaphore: Arc::new(Semaphore::new(self.concurrency.max(1))),
            completed_requests: Arc::clone(&completed_requests),
            progress_callback: self.progress_callback.clone(),
            record_callback: self.record_callback.clone(),
            emitted_ids: Arc::clone(&emitted_ids),
            completed_keys,
        });
        let mut tasks = JoinSet::new();

        for probe in self.probes {
            let session_id = self.session_id;
            let target = Arc::clone(&throttled_target);
            let concurrency = self.concurrency;
            let detectors = Arc::clone(&detectors);

            tasks.spawn(async move { probe.run(session_id, target, concurrency, detectors).await });
        }

        let mut report = ScanReport::new(self.session_id, self.target.info().model.clone());
        report.records.extend(kept_resume);

        while let Some(joined) = tasks.join_next().await {
            match joined {
                Ok(Ok(records)) => {
                    if let Some(cb) = &self.record_callback {
                        let mut guard = emitted_ids
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        for rec in &records {
                            if guard.insert(rec.id) {
                                cb(rec);
                            }
                        }
                    }
                    report.records.extend(records);
                    let req_count = *completed_requests
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    if req_count == 0 {
                        if let Some(cb) = &self.progress_callback {
                            cb(report.records.len());
                        }
                    }
                }
                Ok(Err(err)) => report.failed_probes.push(err.to_string()),
                // Probe task panicked or was cancelled.
                Err(join_err) => report
                    .failed_probes
                    .push(format!("task failure: {join_err}")),
            }
        }

        // Deterministic ordering across concurrent runs (G4).
        report.records.sort_by(|a, b| {
            a.probe_name
                .cmp(&b.probe_name)
                .then_with(|| {
                    a.mutation_type
                        .to_string()
                        .cmp(&b.mutation_type.to_string())
                })
                .then_with(|| a.prompt.cmp(&b.prompt))
        });

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
        self.records
            .iter()
            .filter(|r| r.verdict.is_vulnerable())
            .count()
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
    attacker: Option<Arc<dyn TargetAdapter>>,
    probes: Vec<Arc<dyn Probe>>,
    detectors: Vec<Arc<dyn Detector>>,
    concurrency: Option<usize>,
    session_id: Option<Uuid>,
    resume_records: Vec<AttackRecord>,
    progress_callback: Option<Arc<dyn Fn(usize) + Send + Sync>>,
    record_callback: Option<RecordCallback>,
}

impl ScanBuilder {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            target: None,
            attacker: None,
            probes: Vec::new(),
            detectors: Vec::new(),
            concurrency: None,
            session_id: None,
            resume_records: Vec::new(),
            progress_callback: None,
            record_callback: None,
        }
    }

    /// Registers the target adapter (required).
    #[must_use]
    pub fn target(mut self, target: Arc<dyn TargetAdapter>) -> Self {
        self.target = Some(target);
        self
    }

    /// Registers an optional secondary attacker adapter for adaptive multi-turn evaluations.
    #[must_use]
    pub fn attacker(mut self, attacker: Arc<dyn TargetAdapter>) -> Self {
        self.attacker = Some(attacker);
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

    /// Supplies already-completed [`AttackRecord`]s from a prior checkpoint so
    /// matching `(probe_name, prompt)` pairs are skipped and merged into the final report.
    #[must_use]
    pub fn resume_records(mut self, records: Vec<AttackRecord>) -> Self {
        self.resume_records = records;
        self
    }

    /// Registers a callback fired after each completed request, with the running total request count.
    #[must_use]
    pub fn on_record_progress(mut self, callback: impl Fn(usize) + Send + Sync + 'static) -> Self {
        self.progress_callback = Some(Arc::new(callback));
        self
    }

    /// Registers a callback fired immediately as each [`AttackRecord`] is finalized,
    /// enabling live JSONL streaming to disk before the campaign finishes.
    #[must_use]
    pub fn on_record_complete(
        mut self,
        callback: impl Fn(&AttackRecord) + Send + Sync + 'static,
    ) -> Self {
        self.record_callback = Some(Arc::new(callback));
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
            attacker: self.attacker,
            probes: self.probes,
            detectors: self.detectors,
            concurrency: self
                .concurrency
                .filter(|c| *c > 0)
                .unwrap_or(DEFAULT_CONCURRENCY),
            resume_records: self.resume_records,
            progress_callback: self.progress_callback,
            record_callback: self.record_callback,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use redteamer_core::types::{OwaspCategory, Verdict};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    struct ConcurrencyTrackingAdapter {
        in_flight: AtomicUsize,
        max_in_flight: AtomicUsize,
    }

    impl ConcurrencyTrackingAdapter {
        fn new() -> Self {
            Self {
                in_flight: AtomicUsize::new(0),
                max_in_flight: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl TargetAdapter for ConcurrencyTrackingAdapter {
        fn info(&self) -> &AdapterInfo {
            static INFO: AdapterInfo = AdapterInfo {
                name: "tracking",
                version: "0.0.0",
                model: None,
            };
            &INFO
        }

        async fn send_chat(
            &self,
            _messages: &[ChatMessage],
            _opts: &GenerationOptions,
        ) -> Result<AdapterResponse> {
            let cur = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_in_flight.fetch_max(cur, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(25)).await;
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            Ok(AdapterResponse {
                text: "ok".into(),
                tool_calls: Vec::new(),
                completed: true,
                metadata: serde_json::json!({}),
            })
        }
    }

    struct MultiRequestProbe {
        name: String,
        prompts: Vec<String>,
    }

    #[async_trait]
    impl Probe for MultiRequestProbe {
        fn name(&self) -> &str {
            &self.name
        }

        fn description(&self) -> &str {
            "test probe"
        }

        fn category(&self) -> Vec<OwaspCategory> {
            vec![OwaspCategory::PromptInjection]
        }

        async fn run(
            &self,
            session_id: Uuid,
            target: Arc<dyn TargetAdapter>,
            _concurrency: usize,
            _detectors: Arc<[Arc<dyn Detector>]>,
        ) -> Result<Vec<AttackRecord>> {
            let mut set = JoinSet::new();
            for p in &self.prompts {
                if target.should_skip_attack(&self.name, p) {
                    continue;
                }
                let p = p.clone();
                let name = self.name.clone();
                let target = Arc::clone(&target);
                set.spawn(async move {
                    let mut rec = AttackRecord::new(session_id, name, &p);
                    rec.response = Some(target.send(&p).await.unwrap().text);
                    rec.verdict = Verdict::Resistant;
                    target.enrich_record(&mut rec);
                    rec
                });
            }
            let mut out = Vec::new();
            while let Some(joined) = set.join_next().await {
                out.push(joined.unwrap());
            }
            Ok(out)
        }
    }

    #[tokio::test]
    async fn concurrency_is_globally_capped_across_probes() {
        let adapter = Arc::new(ConcurrencyTrackingAdapter::new());
        let probes: Vec<Arc<dyn Probe>> = (0..4)
            .map(|i| {
                Arc::new(MultiRequestProbe {
                    name: format!("probe_{i}"),
                    prompts: vec!["p3".into(), "p1".into(), "p2".into()],
                }) as Arc<dyn Probe>
            })
            .collect();

        let report = ScanBuilder::new()
            .target(adapter.clone())
            .probes(probes)
            .concurrency(2)
            .build()
            .unwrap()
            .execute()
            .await;

        assert_eq!(report.records.len(), 12);
        let peak = adapter.max_in_flight.load(Ordering::SeqCst);
        assert!(peak <= 2, "expected global concurrency <= 2, got {peak}");
    }

    #[tokio::test]
    async fn progress_callback_fires_per_request_and_records_sort_deterministically() {
        let adapter = Arc::new(ConcurrencyTrackingAdapter::new());
        let progress_events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let events_clone = Arc::clone(&progress_events);

        let probes: Vec<Arc<dyn Probe>> = vec![
            Arc::new(MultiRequestProbe {
                name: "probe_b".into(),
                prompts: vec!["z_prompt".into(), "a_prompt".into()],
            }),
            Arc::new(MultiRequestProbe {
                name: "probe_a".into(),
                prompts: vec!["m_prompt".into(), "b_prompt".into()],
            }),
        ];

        let report = ScanBuilder::new()
            .target(adapter)
            .probes(probes)
            .concurrency(2)
            .on_record_progress(move |count| {
                events_clone.lock().unwrap().push(count);
            })
            .build()
            .unwrap()
            .execute()
            .await;

        let events = progress_events.lock().unwrap().clone();
        assert_eq!(events.len(), 4, "progress must fire once per request");
        assert_eq!(events, vec![1, 2, 3, 4]);

        let keys: Vec<(&str, &str)> = report
            .records
            .iter()
            .map(|r| (r.probe_name.as_str(), r.prompt.as_str()))
            .collect();
        assert_eq!(
            keys,
            vec![
                ("probe_a", "b_prompt"),
                ("probe_a", "m_prompt"),
                ("probe_b", "a_prompt"),
                ("probe_b", "z_prompt"),
            ]
        );
    }

    #[tokio::test]
    async fn on_record_complete_streams_records_and_resume_skips_completed_attacks() {
        let session_id = Uuid::new_v4();
        let mut prior_completed = AttackRecord::new(session_id, "probe_a", "p1");
        prior_completed.verdict = Verdict::Resistant;
        prior_completed.response = Some("prior ok".into());

        let mut prior_errored = AttackRecord::new(session_id, "probe_a", "p2");
        prior_errored.verdict = Verdict::Error;

        let streamed = Arc::new(std::sync::Mutex::new(Vec::new()));
        let streamed_clone = Arc::clone(&streamed);

        let probe = Arc::new(MultiRequestProbe {
            name: "probe_a".into(),
            prompts: vec!["p1".into(), "p2".into(), "p3".into()],
        });

        let report = ScanBuilder::new()
            .session_id(session_id)
            .target(Arc::new(ConcurrencyTrackingAdapter::new()))
            .probe(probe)
            .resume_records(vec![prior_completed, prior_errored])
            .on_record_complete(move |rec| {
                streamed_clone.lock().unwrap().push(rec.prompt.clone());
            })
            .build()
            .unwrap()
            .execute()
            .await;

        // Final report has all 3 records (p1 from checkpoint + p2 & p3 freshly executed).
        assert_eq!(report.records.len(), 3);
        let p1 = report.records.iter().find(|r| r.prompt == "p1").unwrap();
        assert_eq!(p1.response.as_deref(), Some("prior ok"));

        // Only p2 (which previously errored) and p3 (new) were executed and streamed.
        let mut streamed_prompts = streamed.lock().unwrap().clone();
        streamed_prompts.sort();
        assert_eq!(streamed_prompts, vec!["p2".to_owned(), "p3".to_owned()]);
    }
}
