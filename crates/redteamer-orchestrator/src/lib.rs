// crates/redteamer-orchestrator/src/lib.rs

//! Campaign orchestration: wires probes, detectors, and a target adapter
//! into concurrent scan executions.

pub mod scan;

pub use scan::{ScanBuilder, ScanConfig, ScanReport};
