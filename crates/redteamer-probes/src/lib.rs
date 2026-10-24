// crates/redteamer-probes/src/lib.rs

//! Built-in probe library, organized by OWASP LLM Top 10 category.
//!
//! Probes self-register into a compile-time registry via [`inventory`];
//! embedders get the full library with one `use`, and downstream crates can
//! enumerate everything with [`all_probes`] — no manual wiring.

pub mod llm01;
pub mod llm02;
pub mod llm06;
pub mod llm07;
pub mod llm10;

use redteamer_core::error::Result;
use redteamer_core::traits::adapter::TargetAdapter;
use redteamer_core::traits::detector::Detector;
use redteamer_core::traits::probe::Probe;
use redteamer_core::types::{AttackRecord, MutationType, Verdict};
use redteamer_detectors::DetectorPipeline;
use redteamer_payload::ProbeTemplate;
use std::sync::Arc;
use uuid::Uuid;

/// Compile-time registration entry collected by `inventory`.
///
/// Each registered probe exposes a static name plus a zero-arg constructor,
/// so the registry stays a flat table of function pointers — no dynamic
/// linking, no runtime reflection.
pub struct ProbeConstructor {
    /// Stable probe identifier (matches [`Probe::name`]).
    pub name: &'static str,
    /// Instantiates a fresh, independent probe instance.
    pub constructor: fn() -> Box<dyn Probe>,
}

inventory::collect!(ProbeConstructor);

/// Registers a probe type that implements `const NAME: &'static str`,
/// `fn new() -> Self`, and the [`Probe`] trait.
///
/// ```ignore
/// struct MyProbe;
/// register_probe!(MyProbe);
/// ```
#[macro_export]
macro_rules! register_probe {
    ($ty:ty) => {
        ::inventory::submit! {
            $crate::ProbeConstructor {
                name: <$ty>::NAME,
                constructor: || Box::new(<$ty>::new()),
            }
        }
    };
}

/// Instantiates every probe registered in this binary/library.
#[must_use]
pub fn all_probes() -> Vec<Box<dyn Probe>> {
    inventory::iter::<ProbeConstructor>
        .into_iter()
        .map(|ctor| (ctor.constructor)())
        .collect()
}

/// Instantiates only the probes whose names appear in `wanted`.
///
/// Unknown names are ignored; callers wanting strict validation should diff
/// against [`all_probes`] themselves.
#[must_use]
pub fn probes_by_name<'a>(wanted: impl IntoIterator<Item = &'a str>) -> Vec<Box<dyn Probe>> {
    let wanted: Vec<&str> = wanted.into_iter().collect();
    all_probes()
        .into_iter()
        .filter(|p| wanted.iter().any(|w| p.name() == *w))
        .collect()
}

/// Shared execution engine for template-driven probes.
///
/// Dispatches every payload from `template` through `target`. Payloads are
/// executed concurrently via a [`JoinSet`] capped at `concurrency`
/// in-flight requests by a semaphore; each task owns its data
/// (`'static`), keeping the engine free of external future combinators.
/// Verdicts come from the probe-specific `evaluate` callback, shared into
/// tasks as an `Arc`.
pub(crate) async fn run_template(
    probe_name: &str,
    template: &ProbeTemplate,
    session_id: Uuid,
    target: Arc<dyn TargetAdapter>,
    concurrency: usize,
    evaluate: Arc<dyn Fn(&AttackRecord) -> Verdict + Send + Sync>,
    detectors: Arc<[Arc<dyn Detector>]>,
) -> Result<Vec<AttackRecord>> {
    let filtered: Vec<Arc<dyn Detector>> = if template.detector_hints.is_empty() {
        Vec::new()
    } else {
        detectors
            .iter()
            .filter(|d| template.detector_hints.iter().any(|hint| hint == d.name()))
            .cloned()
            .collect()
    };
    let filtered = Arc::new(filtered);
    let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency.max(1)));
    let mut tasks = tokio::task::JoinSet::new();

    for payload in template.payloads() {
        let permit = Arc::clone(&semaphore).acquire_owned().await;
        let target = Arc::clone(&target);
        let evaluate = Arc::clone(&evaluate);
        let probe_name = probe_name.to_owned();
        let filtered = Arc::clone(&filtered);

        tasks.spawn(async move {
            let _permit = permit;

            let mut record = AttackRecord::new(session_id, &probe_name, &payload);
            match target.send(&payload).await {
                Ok(response) => {
                    record.response = Some(response.text);
                    record.completed_at = chrono::Utc::now();
                }
                Err(_) => {
                    // Per-attempt failures become evidence records, not errors.
                    record.completed_at = chrono::Utc::now();
                    record.verdict = Verdict::Error;
                }
            }

            record.verdict = evaluate(&record);
            if !filtered.is_empty() {
                let pipeline = DetectorPipeline::from_detectors(filtered.iter().cloned());
                if let Ok(outcomes) = pipeline.run(&record.prompt, record.response.as_deref()).await {
                    record.detections = outcomes;
                }
            }
            // TODO(Phase 2): thread the applied MutationType through
            // template.payloads() so records carry it precisely.
            record.mutation_type = MutationType::None;
            target.enrich_record(&mut record);
            record
        });
    }

    let mut records = Vec::with_capacity(tasks.len());
    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok(record) => records.push(record),
            Err(join_err) => {
                // Task panicked or was cancelled; surface as an error record
                // so one bad attempt never poisons the whole campaign.
                let mut record =
                    AttackRecord::new(session_id, probe_name, "<task failure>");
                record.completed_at = chrono::Utc::now();
                record.verdict = Verdict::Error;
                let _ = join_err;
                records.push(record);
            }
        }
    }

    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;
    use redteamer_core::traits::adapter::{AdapterInfo, AdapterResponse, TargetAdapter};
    use redteamer_core::traits::detector::Detector;
    use redteamer_detectors::StringMatchDetector;
    use std::sync::Arc;

    struct MockTarget {
        response: String,
    }

    #[async_trait::async_trait]
    impl TargetAdapter for MockTarget {
        fn info(&self) -> &AdapterInfo {
            static INFO: AdapterInfo = AdapterInfo {
                name: "mock",
                version: "0.0.0",
                model: None,
            };
            &INFO
        }

        async fn send(&self, _prompt: &str) -> Result<AdapterResponse> {
            Ok(AdapterResponse {
                text: self.response.clone(),
                completed: true,
                metadata: serde_json::json!({}),
            })
        }
    }

    fn make_template(hints: Vec<&str>) -> ProbeTemplate {
        ProbeTemplate {
            name: "test_probe".to_string(),
            description: String::new(),
            owasp_categories: vec![],
            seeds: vec!["seed".to_string()],
            mutations: vec![],
            detector_hints: hints.into_iter().map(|s| s.to_string()).collect(),
        }
    }

    #[tokio::test]
    async fn detections_populated_when_hint_matches() {
        let template = make_template(vec!["test_detector"]);
        let detector = Arc::new(
            StringMatchDetector::new("test_detector", "test", vec!["vulnerable"]).unwrap(),
        ) as Arc<dyn Detector>;
        let detectors: Arc<[Arc<dyn Detector>]> = Arc::from(vec![detector]);
        let target: Arc<dyn TargetAdapter> = Arc::new(MockTarget {
            response: "this is vulnerable".to_string(),
        });
        let evaluate = Arc::new(|_: &AttackRecord| Verdict::Resistant) as Arc<dyn Fn(&AttackRecord) -> Verdict + Send + Sync>;

        let records = run_template(
            "test_probe",
            &template,
            uuid::Uuid::new_v4(),
            target,
            1,
            evaluate,
            detectors,
        )
        .await
        .unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].detections.len(), 1);
        assert_eq!(records[0].detections[0].detector_name, "test_detector");
        assert!(records[0].detections[0].matched);
    }

    #[tokio::test]
    async fn detections_empty_when_no_hints() {
        let template = make_template(vec![]);
        let detector = Arc::new(
            StringMatchDetector::new("test_detector", "test", vec!["vulnerable"]).unwrap(),
        ) as Arc<dyn Detector>;
        let detectors: Arc<[Arc<dyn Detector>]> = Arc::from(vec![detector]);
        let target: Arc<dyn TargetAdapter> = Arc::new(MockTarget {
            response: "vulnerable".to_string(),
        });
        let evaluate = Arc::new(|_: &AttackRecord| Verdict::Resistant) as Arc<dyn Fn(&AttackRecord) -> Verdict + Send + Sync>;

        let records = run_template(
            "test_probe",
            &template,
            uuid::Uuid::new_v4(),
            target,
            1,
            evaluate,
            detectors,
        )
        .await
        .unwrap();

        assert_eq!(records[0].detections.len(), 0);
    }

    #[tokio::test]
    async fn detections_empty_when_hint_no_match() {
        let template = make_template(vec!["nonexistent_detector"]);
        let detector = Arc::new(
            StringMatchDetector::new("test_detector", "test", vec!["vulnerable"]).unwrap(),
        ) as Arc<dyn Detector>;
        let detectors: Arc<[Arc<dyn Detector>]> = Arc::from(vec![detector]);
        let target: Arc<dyn TargetAdapter> = Arc::new(MockTarget {
            response: "vulnerable".to_string(),
        });
        let evaluate = Arc::new(|_: &AttackRecord| Verdict::Resistant) as Arc<dyn Fn(&AttackRecord) -> Verdict + Send + Sync>;

        let records = run_template(
            "test_probe",
            &template,
            uuid::Uuid::new_v4(),
            target,
            1,
            evaluate,
            detectors,
        )
        .await
        .unwrap();

        assert_eq!(records[0].detections.len(), 0);
    }

    #[tokio::test]
    async fn verdict_unaffected_by_detector_filtering() {
        let template_match = make_template(vec!["test_detector"]);
        let template_no_match = make_template(vec![]);
        let detector = Arc::new(
            StringMatchDetector::new("test_detector", "test", vec!["vulnerable"]).unwrap(),
        ) as Arc<dyn Detector>;
        let detectors: Arc<[Arc<dyn Detector>]> = Arc::from(vec![detector.clone()]);
        let detectors_clone: Arc<[Arc<dyn Detector>]> = Arc::from(vec![detector]);

        let target: Arc<dyn TargetAdapter> = Arc::new(MockTarget {
            response: "vulnerable".to_string(),
        });

        // Both should have same verdict from evaluate (Vulnerable), regardless of detections
        let eval_vuln = Arc::new(|_: &AttackRecord| Verdict::Vulnerable) as Arc<dyn Fn(&AttackRecord) -> Verdict + Send + Sync>;
        let eval_resistant = Arc::new(|_: &AttackRecord| Verdict::Resistant) as Arc<dyn Fn(&AttackRecord) -> Verdict + Send + Sync>;

        let records_match = run_template(
            "test_probe",
            &template_match,
            uuid::Uuid::new_v4(),
            Arc::clone(&target),
            1,
            Arc::clone(&eval_vuln),
            detectors,
        )
        .await
        .unwrap();
        let records_no_match = run_template(
            "test_probe",
            &template_no_match,
            uuid::Uuid::new_v4(),
            target,
            1,
            eval_resistant,
            detectors_clone,
        )
        .await
        .unwrap();

        assert_eq!(records_match[0].verdict, Verdict::Vulnerable);
        assert_eq!(records_no_match[0].verdict, Verdict::Resistant);
        // Detections differ but verdicts are independent
        assert_eq!(records_match[0].detections.len(), 1);
        assert_eq!(records_no_match[0].detections.len(), 0);
    }
}
