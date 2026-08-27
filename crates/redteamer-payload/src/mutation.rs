// crates/redteamer-payload/src/mutation.rs

use base64::Engine as _;
use serde::{Deserialize, Serialize};

/// A single string-to-string transformation applied to a seed payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum Mutation {
    /// Return the seed unchanged.
    Identity,
    /// Standard Base64 encoding of the UTF-8 seed.
    Base64,
    /// ROT13 over ASCII letters (leaves other chars untouched).
    Rot13,
    /// Uppercase the whole payload.
    Uppercase,
    /// Reverse the character order.
    Reverse,
    /// Wrap the payload in a fixed prefix/suffix (e.g. roleplay framing).
    Wrap {
        #[serde(default)]
        prefix: String,
        #[serde(default)]
        suffix: String,
    },
}

impl Mutation {
    /// Applies this mutation to `input`, always producing a fresh
    /// [`String`] (mutations may grow the payload; borrowing is not
    /// generally possible).
    #[must_use]
    pub fn apply(&self, input: &str) -> String {
        match self {
            Self::Identity => input.to_owned(),
            Self::Base64 => base64::engine::general_purpose::STANDARD.encode(input.as_bytes()),
            Self::Rot13 => rot13(input),
            Self::Uppercase => input.to_uppercase(),
            Self::Reverse => input.chars().rev().collect(),
            Self::Wrap { prefix, suffix } => format!("{prefix}{input}{suffix}"),
        }
    }

    /// The canonical name used in audit records.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::Base64 => "base64",
            Self::Rot13 => "rot13",
            Self::Uppercase => "uppercase",
            Self::Reverse => "reverse",
            Self::Wrap { .. } => "wrap",
        }
    }
}

/// An ordered set of mutations.
///
/// [`MutationPipeline::iter`] is *zero-copy with respect to the pipeline*:
/// it borrows the pipeline and the seed and yields each mutated variant
/// lazily, so a 10k-entry corpus never materializes more than one mutated
/// string at a time.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MutationPipeline {
    mutations: Vec<Mutation>,
}

impl MutationPipeline {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            mutations: Vec::new(),
        }
    }

    #[must_use]
    pub fn from_mutations(mutations: impl IntoIterator<Item = Mutation>) -> Self {
        Self {
            mutations: mutations.into_iter().collect(),
        }
    }

    pub fn push(&mut self, mutation: Mutation) {
        self.mutations.push(mutation);
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.mutations.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.mutations.len()
    }

    /// Lazily yields every seed mutated by every registered mutation.
    ///
    /// With an empty pipeline this yields nothing; use
    /// [`MutationPipeline::with_identity`] to include the raw seed.
    pub fn iter<'a>(&'a self, seed: &'a str) -> impl Iterator<Item = String> + 'a {
        self.mutations.iter().map(move |m| m.apply(seed))
    }

    /// Like [`MutationPipeline::iter`], but guarantees the unmodified seed
    /// is yielded first.
    pub fn iter_with_identity<'a>(&'a self, seed: &'a str) -> impl Iterator<Item = String> + 'a {
        std::iter::once(seed.to_owned()).chain(self.iter(seed))
    }

    /// Builder-style enablement of the identity pass.
    #[must_use]
    pub fn with_identity(mut self) -> Self {
        self.push(Mutation::Identity);
        self
    }
}

impl IntoIterator for MutationPipeline {
    type Item = Mutation;
    type IntoIter = std::vec::IntoIter<Mutation>;

    fn into_iter(self) -> Self::IntoIter {
        self.mutations.into_iter()
    }
}

fn rot13(input: &str) -> String {
    input
        .chars()
        .map(|c| match c {
            'a'..='z' => ((c as u8 - b'a' + 13) % 26 + b'a') as char,
            'A'..='Z' => ((c as u8 - b'A' + 13) % 26 + b'A') as char,
            _ => c,
        })
        .collect()
}
