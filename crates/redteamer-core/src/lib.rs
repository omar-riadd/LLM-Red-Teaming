//! # redteamer-core
//!
//! Core domain types, error model, and async trait contracts for the
//! `llm-redteamer` framework.
//!
//! The crate is intentionally dependency-light and allocation-friendly:
//! everything here is a zero-cost abstraction over plain data and traits,
//! with no I/O or runtime assumptions. Higher-level crates (adapters for
//! specific providers, orchestration, reporting) build on top of these
//! contracts.

pub mod error;
pub mod traits;
pub mod types;

pub use error::RedTeamerError;

/// Convenient prelude re-exporting the most commonly used items.
pub mod prelude {
    pub use crate::error::RedTeamerError;
    pub use crate::traits::adapter::{ChatMessage, GenerationOptions, Role, TargetAdapter};
    pub use crate::traits::detector::{DetectContext, Detector};
    pub use crate::traits::probe::Probe;
    pub use crate::traits::reporter::{ReportContext, ReportExporter, ReportFormat};
    pub use crate::types::*;
}
