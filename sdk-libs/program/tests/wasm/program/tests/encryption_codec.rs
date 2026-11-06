use spr_program::{circuit::UtxoData, EncryptionCodec};
use wasm_test_program::CompactCounter;

#[test]
fn the_custom_payload_carries_only_the_count_and_reconstructs_the_full_state() {
    let state = CompactCounter {
        count: 21,
        doubled: 42,
    };
    let payload = state.utxo_data().unwrap();
    assert_eq!(
        (
            payload.clone(),
            CompactCounter::deserialize_after_decryption(&payload).unwrap(),
        ),
        (borsh::to_vec(&21u64).unwrap(), state)
    );
}

#[test]
fn a_count_whose_double_overflows_is_refused() {
    let error = CompactCounter::deserialize_after_decryption(&borsh::to_vec(&u64::MAX).unwrap())
        .unwrap_err();
    assert_eq!(
        (error.kind(), error.to_string()),
        (
            std::io::ErrorKind::InvalidData,
            "doubled count overflows".into()
        )
    );
}
