// crates/redteamer-detectors/src/lib.rs

//! Built-in [`Detector`](redteamer_core::traits::Detector) implementations.
//!
//! All detectors are pure functions of `(prompt, response)` and are safe to
//! share across tasks via `Arc`.

pub mod llm_judge;
pub mod pipeline;
pub mod regex_set;
pub mod semantic;
pub mod string_match;

pub use llm_judge::{JudgeVerdict, LlmJudgeDetector};
pub use pipeline::DetectorPipeline;
pub use regex_set::RegexSetDetector;
pub use semantic::SemanticDetector;
pub use string_match::StringMatchDetector;
