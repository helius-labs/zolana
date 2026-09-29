use timelock_escrow_program::spp::{ProvenOutput, ProvenTransact};
use zolana_interface::{
    instruction::instruction_data::transact::{
        CircuitId, InputUtxo, OwnerTag, TransactIxData, TransactOutput, TransactProof, TreeContext,
    },
    N_PUBLIC_SLOTS,
};

fn proven() -> ProvenTransact<2, 2> {
    ProvenTransact {
        proof: TransactProof {
            a: [1u8; 32],
            b: [2u8; 128],
            c: [3u8; 32],
        },
        private_tx_hash: [4u8; 32],
        expiry_unix_ts: 1_234,
        tx_viewing_pk: [5u8; 33],
        salt: [6u8; 16],
        inputs: [
            InputUtxo {
                nullifier_hash: [7u8; 32],
                tree_index: 0,
            },
            InputUtxo {
                nullifier_hash: [8u8; 32],
                tree_index: 0,
            },
        ],
        tree_contexts: vec![TreeContext {
            utxo_tree_root_index: 9,
            nullifier_tree_root_index: 10,
        }],
        outputs: [
            ProvenOutput {
                utxo_hash: [11u8; 32],
                data: Some(vec![12u8; 3]),
            },
            ProvenOutput {
                utxo_hash: [13u8; 32],
                data: None,
            },
        ],
    }
}

#[test]
fn into_ix_data_assigns_owner_tags_by_slot_and_fixes_the_rest() {
    let ix = proven().into_ix_data([[21u8; 32], [22u8; 32]]);

    assert_eq!(
        ix,
        TransactIxData {
            expiry_unix_ts: 1_234,
            tx_viewing_pk: [5u8; 33],
            salt: [6u8; 16],
            interface_transfers: Vec::new(),
            data_hash: None,
            ring_data_hash: None,
            outputs: vec![
                TransactOutput {
                    utxo_hash: [11u8; 32],
                    owner_tag: OwnerTag::Inline([21u8; 32]),
                    data: Some(vec![12u8; 3]),
                },
                TransactOutput {
                    utxo_hash: [13u8; 32],
                    owner_tag: OwnerTag::Inline([22u8; 32]),
                    data: None,
                },
            ],
            messages: Vec::new(),
            private_tx_hash: [4u8; 32],
            circuit: CircuitId::ConfidentialEddsa(2, 2, N_PUBLIC_SLOTS as u8),
            proof: TransactProof {
                a: [1u8; 32],
                b: [2u8; 128],
                c: [3u8; 32],
            },
            inputs: vec![
                InputUtxo {
                    nullifier_hash: [7u8; 32],
                    tree_index: 0,
                },
                InputUtxo {
                    nullifier_hash: [8u8; 32],
                    tree_index: 0,
                },
            ],
            tree_contexts: vec![TreeContext {
                utxo_tree_root_index: 9,
                nullifier_tree_root_index: 10,
            }],
        }
    );
}

#[test]
fn circuit_follows_the_shape() {
    assert_eq!(
        (
            ProvenTransact::<1, 1>::CIRCUIT,
            ProvenTransact::<2, 3>::CIRCUIT
        ),
        (
            CircuitId::ConfidentialEddsa(1, 1, N_PUBLIC_SLOTS as u8),
            CircuitId::ConfidentialEddsa(2, 3, N_PUBLIC_SLOTS as u8)
        )
    );
}
