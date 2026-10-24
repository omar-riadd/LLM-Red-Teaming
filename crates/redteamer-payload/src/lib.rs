// crates/redteamer-payload/src/lib.rs

//! Payload corpus handling for `llm-redteamer`: declarative probe
//! templates (YAML) and composable, lazily-evaluated mutation pipelines.

pub mod mutation;
pub mod template;

pub use mutation::{GeneratedPayload, Mutation, MutationPipeline};
pub use template::{InlineDetectorRule, ProbeScope, ProbeTemplate};

