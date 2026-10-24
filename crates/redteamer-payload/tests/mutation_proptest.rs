// crates/redteamer-payload/tests/mutation_proptest.rs

//! Property-based testing for `Mutation` and `MutationPipeline` using `proptest`.

use base64::Engine as _;
use proptest::prelude::*;
use redteamer_payload::{Mutation, MutationPipeline};

proptest! {
    /// Property 1: Identity and pipeline iterations always produce at least 1 output
    /// when using iter_with_identity, regardless of seed length.
    #[test]
    fn prop_pipeline_iter_with_identity_non_empty(seed in "\\PC{0,200}") {
        let pipe = MutationPipeline::default();
        let outputs: Vec<_> = pipe.iter_with_identity(&seed).collect();
        prop_assert!(!outputs.is_empty());
        prop_assert_eq!(&outputs[0], &seed);
    }

    /// Property 2: No standard mutation produces an empty string when the input seed is non-empty.
    #[test]
    fn prop_mutation_output_non_empty_for_non_empty_input(seed in "\\PC{1,200}") {
        let pipeline = MutationPipeline::from_mutations([
            Mutation::Identity,
            Mutation::Base64,
            Mutation::Rot13,
            Mutation::Uppercase,
            Mutation::Reverse,
            Mutation::Leetspeak,
            Mutation::Homoglyph,
            Mutation::ZeroWidth,
            Mutation::JsonTaskWrap,
            Mutation::Wrap {
                prefix: "[AUDIT]: ".into(),
                suffix: " [END]".into(),
            },
        ]);

        for payload in pipeline.iter_tagged(&seed) {
            prop_assert!(
                !payload.text.is_empty(),
                "mutation produced empty text for non-empty seed"
            );
        }
    }

    /// Property 3: Base64 mutation payload correctly contains decodable Base64 that roundtrips to the original seed.
    #[test]
    fn prop_base64_mutation_roundtrip(seed in "[a-zA-Z0-9 _\\-.,!?]{1,100}") {
        let mutated = Mutation::Base64.apply(&seed);
        // The Base64 encoded payload is the last non-empty line of the wrapper
        let b64_str = mutated.lines().last().expect("Base64 wrapper should have lines");
        let decoded_bytes = base64::engine::general_purpose::STANDARD
            .decode(b64_str)
            .expect("payload should contain valid base64");
        let decoded_str = String::from_utf8(decoded_bytes).expect("decoded bytes must be valid utf8");
        prop_assert_eq!(decoded_str, seed);
    }

    /// Property 4: Reversing the reverse wrapper extracts the exact original reversed characters.
    #[test]
    fn prop_reverse_mutation_contains_reversed_seed(seed in "\\PC{1,100}") {
        let mutated = Mutation::Reverse.apply(&seed);
        let rev_line = mutated.lines().last().expect("Reverse wrapper should have lines");
        let double_reversed: String = rev_line.chars().rev().collect();
        prop_assert_eq!(double_reversed, seed);
    }
}
