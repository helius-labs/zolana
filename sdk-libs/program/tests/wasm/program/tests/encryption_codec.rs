#![cfg(feature = "wasm")]

use wasm_test_program::CompactCounter;
use zolana_program::{
    circuit::UtxoData,
    conversion::{Allocator, ProofInput},
    EncryptionCodec,
};

#[test]
fn custom_payload_reconstructs_the_full_state_for_wasm_serialization() {
    let state = CompactCounter {
        count: 21,
        doubled: 42,
    };
    let circuit = state
        .instantiate(&Allocator::native())
        .expect("instantiate");
    let payload = circuit.utxo_data().expect("validated payload");
    let decoded = CompactCounter::deserialize_after_decryption(&payload).expect("decode");
    assert_eq!(
        (
            payload.len(),
            borsh::to_vec(&state).expect("full state").len(),
            serde_json::to_value(decoded).expect("wasm state serialization"),
        ),
        (8, 16, serde_json::json!({ "count": 21, "doubled": 42 }))
    );
}
