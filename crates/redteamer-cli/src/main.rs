// crates/redteamer-cli/src/main.rs

//! `llm-redteamer` CLI entry point.

mod adapter_builder;
mod cmd;

use clap::{Parser, Subcommand};

/// Command-line interface for the llm-redteamer framework.
#[derive(Debug, Parser)]
#[command(
    name = "llm-redteamer",
    version,
    about = "High-performance, concurrent LLM red-teaming framework"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run an attack campaign against a target LLM.
    Scan(Box<cmd::scan::ScanArgs>),

    /// List available probes or detectors.
    List(cmd::list::ListArgs),

    /// Compare two JSON scan reports (`ReportContext`) and summarize regressions.
    Diff(cmd::diff::DiffArgs),

    /// Check target LLM health and connectivity.
    Health(cmd::health::HealthArgs),
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Scan(args) => match cmd::scan::run_scan(*args).await {
            Ok(threshold_exceeded) => {
                if threshold_exceeded {
                    std::process::exit(2);
                }
            }
            Err(err) => {
                eprintln!("error: {err}");
                std::process::exit(1);
            }
        },
        Command::List(args) => {
            cmd::list::run_list(args);
        }
        Command::Diff(args) => {
            match cmd::diff::run_diff(&args.baseline, &args.current, args.fail_on_regression) {
                Ok(regressed) => {
                    if regressed && args.fail_on_regression {
                        std::process::exit(2);
                    }
                }
                Err(err) => {
                    eprintln!("error: {err}");
                    std::process::exit(1);
                }
            }
        }
        Command::Health(args) => match cmd::health::run_health(args).await {
            Ok(()) => {}
            Err(err) => {
                eprintln!("error: {err}");
                std::process::exit(1);
            }
        },
    }
}
