#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = crue_engine::proof::ProofEnvelopeV1::from_canonical_bytes(data);
});
