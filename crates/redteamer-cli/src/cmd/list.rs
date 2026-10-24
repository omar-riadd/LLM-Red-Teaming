// crates/redteamer-cli/src/cmd/list.rs

//! List built-in probes and detectors.

use clap::{Args, ValueEnum};
use redteamer_probes as probes;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ListKind {
    Probes,
    Detectors,
}

#[derive(Debug, Args)]
pub struct ListArgs {
    /// Kind of listing to show.
    #[arg(long, value_enum)]
    pub kind: ListKind,
}

pub fn run_list(args: ListArgs) {
    match args.kind {
        ListKind::Probes => {
            let mut probe_names: Vec<String> = probes::all_probes()
                .iter()
                .map(|p| p.name().to_owned())
                .collect();
            probe_names.sort();
            for name in probe_names {
                println!("{name}");
            }
        }
        ListKind::Detectors => {
            for info in redteamer_detectors::builtin_detector_descriptions() {
                println!("{:<16} {}", info.name, info.description);
            }
        }
    }
}
