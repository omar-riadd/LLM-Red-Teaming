// crates/redteamer-cli/src/cmd/health.rs

//! Target adapter pre-flight health check command.

use clap::Args;
use redteamer_core::error::Result;
use redteamer_core::traits::adapter::GenerationOptions;

#[derive(Debug, Args)]
pub struct HealthArgs {
    /// Target provider ("openai", "ollama", "anthropic", "mock") or OpenAI-compatible base URL.
    #[arg(long)]
    pub target: String,

    /// Override target model name (e.g. "gpt-4o", "llama3.2", "claude-sonnet-4-5").
    #[arg(long)]
    pub model: Option<String>,

    /// Override target base URL.
    #[arg(long)]
    pub base_url: Option<String>,
}

pub async fn run_health(args: HealthArgs) -> Result<()> {
    let adapter = crate::adapter_builder::build_adapter(
        &args.target,
        args.model.as_deref(),
        args.base_url.as_deref(),
        None,
        GenerationOptions::default(),
    )?;

    adapter.health_check().await?;
    println!(
        "target '{}' (model: {:?}) is healthy and reachable.",
        adapter.info().name,
        adapter.info().model
    );
    Ok(())
}
