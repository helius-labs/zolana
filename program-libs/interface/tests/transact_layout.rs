//! Layout of the flat `transact` instruction data.
//!
//! Deliberately a separate binary from `transact_ref`: that test counts global
//! allocations, and any test running concurrently in the same binary corrupts
//! the count.

use zolana_interface::instruction::{
    CircuitId, InputUtxo, InterfaceTransfer, MessageData, OwnerTag, TransactIxData,
    TransactIxDataRef, TransactOutput, TransactProof,
};

fn sample_ix_data() -> TransactIxData {
    TransactIxData {
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
        data_hash: Some([9; 32]),
        ring_data_hash: None,
        circuit: CircuitId::ConfidentialEddsa(1, 1, 1),
        proof: TransactProof::zeroed(),
        private_tx_hash: [2; 32],
        inputs: vec![InputUtxo {
            nullifier_hash: [5; 32],
            nullifier_tree_root_index: 6,
            utxo_tree_root_index: 7,
        }],
    }
}

/// The borrowed parser returns the external-data bytes as a prefix borrowed
/// from the original instruction allocation. The program can therefore hash
/// the bytes it parsed without reconstructing or copying them.
#[test]
fn external_data_region_borrows_the_instruction_prefix() {
    let owned = sample_ix_data();
    let bytes = owned.serialize().unwrap();
    let (view, measured) = TransactIxDataRef::parse_with_external_data_prefix(&bytes).unwrap();
    assert_eq!(measured.as_ptr(), bytes.as_ptr());
    assert_eq!(
        measured.as_ptr().wrapping_add(measured.len()),
        view.private_tx_hash.as_ptr(),
        "the prefix must end exactly where the first non-external field begins",
    );
    assert!(measured.len() < bytes.len());
    assert_eq!(view.expiry_unix_ts, owned.expiry_unix_ts);
    assert_eq!(view.tx_viewing_pk, &owned.tx_viewing_pk);
    assert_eq!(view.salt, &owned.salt);
    assert_eq!(
        view.interface_transfers
            .try_iter()
            .collect::<Result<Vec<_>, _>>()
            .unwrap(),
        owned.interface_transfers,
    );
    assert_eq!(view.outputs.len(), owned.outputs.len());
    assert_eq!(view.messages.len(), owned.messages.len());
    assert_eq!(view.circuit, owned.circuit);
    assert_eq!(view.private_tx_hash, &owned.private_tx_hash);
    assert_eq!(view.inputs.len(), owned.inputs.len());
    for (got, want) in view.inputs.try_iter().zip(&owned.inputs) {
        let got = got.unwrap();
        assert_eq!(got.nullifier_hash, &want.nullifier_hash);
        assert_eq!(
            got.nullifier_tree_root_index,
            want.nullifier_tree_root_index
        );
        assert_eq!(got.utxo_tree_root_index, want.utxo_tree_root_index);
    }
    assert_eq!(view.data_hash, owned.data_hash.as_ref());
    assert_eq!(view.ring_data_hash, owned.ring_data_hash.as_ref());
}
