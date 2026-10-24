#![no_main]

use libfuzzer_sys::fuzz_target;
use redteamer_payload::{Mutation, MutationPipeline};

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
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
        ]);
        for mutated in pipeline.iter(s) {
            let _ = mutated.len();
        }
    }
});
