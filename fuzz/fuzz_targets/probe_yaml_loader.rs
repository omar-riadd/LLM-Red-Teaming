#![no_main]

use libfuzzer_sys::fuzz_target;
use redteamer_payload::ProbeTemplate;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Assert loader never panics on arbitrary YAML strings
        let _ = ProbeTemplate::from_yaml_str(s);
    }
});
