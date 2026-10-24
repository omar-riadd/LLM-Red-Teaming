// crates/redteamer-core/src/traits/mod.rs

//! Plugin contracts for the `llm-redteamer` framework.
//!
//! The framework is extended along four axes, each expressed as a single
//! async trait. Plugins are object-safe so they can be stored as
//! `Arc<dyn Trait>` and dispatched concurrently by the orchestrator.

pub mod adapter;
pub mod detector;
pub mod probe;
pub mod reporter;

pub use adapter::{ChatMessage, GenerationOptions, Role, TargetAdapter, ToolCall, ToolDefinition};
pub use detector::{DetectContext, Detector};
pub use probe::Probe;
pub use reporter::{ReportContext, ReportExporter, ReportFormat};
