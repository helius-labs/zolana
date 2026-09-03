//! Layout of the split `transact` instruction data.
//!
//! Deliberately a separate binary from `transact_ref`: that test counts global
//! allocations, and any test running concurrently in the same binary corrupts
//! the count.

use zolana_interface::instruction::{
    CircuitId, InputUtxo, InterfaceTransfer, MessageData, OwnerTag, TransactIxBound,
    TransactIxData, TransactIxDataRef, TransactIxTail, TransactOutput, TransactProof,
};

fn sample_ix_data() -> TransactIxData {
    TransactIxData {
        bound: TransactIxBound {
            expiry_unix_ts: 1,
            tx_viewing_pk: [3; 33],
            salt: [4; 16],
            interface_transfers: vec![InterfaceTransfer::SolDeposit { amount: 8 }],
            outputs: vec![TransactOutput {
                utxo_hash: [10; 32],
                owner_tag: OwnerTag::Inline([11; 32]),
                data: Some(vec![12, 13]),
            }],
            messages: vec![MessageData {
                view_tag: [14; 32],
                data: vec![15, 16],
            }],
        },
        tail: TransactIxTail {
            private_tx_hash: [2; 32],
            circuit: CircuitId::ConfidentialEddsa(1, 1, 1),
            proof: TransactProof::zeroed(),
            inputs: vec![InputUtxo {
                nullifier_hash: [5; 32],
                nullifier_tree_root_index: 6,
                utxo_tree_root_index: 7,
            }],
            data_hash: Some([9; 32]),
            ring_data_hash: None,
        },
    }
}

/// The two representations must not drift: the concatenated halves are the
/// serialized instruction, and the bound slice `parse_bound` measures is exactly
/// the serialized bound half. This is what keeps `external_data_hash` hashing
/// the same bytes the program acts on.
#[test]
fn bound_region_is_the_serialized_prefix() {
    let owned = sample_ix_data();
    let bytes = owned.serialize().unwrap();

    let bound_bytes = wincode::serialize(&owned.bound).unwrap();
    let tail_bytes = wincode::serialize(&owned.tail).unwrap();
    let mut concatenated = bound_bytes.clone();
    concatenated.extend_from_slice(&tail_bytes);
    assert_eq!(
        bytes, concatenated,
        "the payload is the bound half followed by the tail half, with no framing"
    );

    let (view, measured) = TransactIxDataRef::parse_bound(&bytes).unwrap();
    assert_eq!(
        measured,
        &bound_bytes[..],
        "the measured bound prefix is the serialized bound half"
    );
    assert_eq!(view.bound.expiry_unix_ts, owned.bound.expiry_unix_ts);
    assert_eq!(view.bound.tx_viewing_pk, &owned.bound.tx_viewing_pk);
    assert_eq!(view.bound.salt, &owned.bound.salt);
    assert_eq!(
        view.bound.interface_transfers,
        owned.bound.interface_transfers
    );
    assert_eq!(view.bound.outputs.len(), owned.bound.outputs.len());
    assert_eq!(view.bound.messages.len(), owned.bound.messages.len());
    assert_eq!(view.tail.circuit, owned.tail.circuit);
    assert_eq!(view.tail.private_tx_hash, &owned.tail.private_tx_hash);
    assert_eq!(view.tail.inputs, owned.tail.inputs);
    assert_eq!(view.tail.data_hash, owned.tail.data_hash);
    assert_eq!(view.tail.ring_data_hash, owned.tail.ring_data_hash);
}
