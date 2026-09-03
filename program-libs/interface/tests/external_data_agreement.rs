//! Program and client must derive the same `external_data_hash`.
//!
//! The program hashes the bound region straight out of the instruction buffer;
//! a client serializes the bound half it is about to send. These must agree for
//! every interface-transfer kind and both owner-tag kinds, because a mismatch
//! is indistinguishable from an invalid proof at runtime.

use zolana_interface::instruction::instruction_data::transact::{external_data_hash, CircuitId};
use zolana_interface::instruction::{
    tag, InterfaceTransfer, MessageData, OwnerTag, TransactIxBound, TransactIxData,
    TransactIxDataRef, TransactIxTail, TransactOutput, TransactProof,
};

fn bound(
    interface_transfers: Vec<InterfaceTransfer>,
    outputs: Vec<TransactOutput>,
) -> TransactIxBound {
    TransactIxBound {
        expiry_unix_ts: 42,
        tx_viewing_pk: [3u8; 33],
        salt: [4u8; 16],
        interface_transfers,
        outputs,
        messages: vec![MessageData {
            view_tag: [5u8; 32],
            data: vec![6, 7, 8],
        }],
    }
}

fn ix_data(bound: TransactIxBound) -> TransactIxData {
    TransactIxData {
        bound,
        tail: TransactIxTail {
            circuit: CircuitId::ConfidentialEddsa(1, 1, 3),
            proof: TransactProof {
                a: [1u8; 32],
                b: [2u8; 64],
                c: [3u8; 32],
            },
            private_tx_hash: [9u8; 32],
            inputs: vec![],
            data_hash: None,
            ring_data_hash: None,
        },
    }
}

/// The client's view: serialize the bound half directly.
fn client_hash(data: &TransactIxData, addresses: &[[u8; 32]]) -> [u8; 32] {
    let bound = wincode::serialize(&data.bound).expect("serialize bound half");
    external_data_hash(tag::TRANSACT, &bound, addresses.iter()).expect("client hash")
}

/// The program's view: parse the instruction and hash the measured prefix.
fn program_hash(data: &TransactIxData, addresses: &[[u8; 32]]) -> [u8; 32] {
    let bytes = data.serialize().expect("serialize instruction");
    let (_, bound_bytes) = TransactIxDataRef::parse_bound(&bytes).expect("parse instruction");
    external_data_hash(tag::TRANSACT, bound_bytes, addresses.iter()).expect("program hash")
}

#[test]
fn program_and_client_agree_for_every_interface_transfer_kind() {
    let kinds = [
        vec![],
        vec![InterfaceTransfer::SolDeposit { amount: 1 }],
        vec![InterfaceTransfer::SolWithdrawal { amount: 2 }],
        vec![InterfaceTransfer::SplDeposit {
            amount: 3,
            spl_interface_bump: 254,
        }],
        vec![InterfaceTransfer::SplWithdrawal {
            amount: 4,
            spl_interface_bump: 253,
        }],
        vec![
            InterfaceTransfer::SolDeposit { amount: 5 },
            InterfaceTransfer::SplWithdrawal {
                amount: 6,
                spl_interface_bump: 252,
            },
        ],
    ];

    for transfers in kinds {
        // Two addresses per SPL leg, one per SOL leg; the values themselves do
        // not matter here, only that both sides consume the same list.
        let addresses: Vec<[u8; 32]> = transfers
            .iter()
            .flat_map(|transfer| match transfer {
                InterfaceTransfer::SolDeposit { .. } | InterfaceTransfer::SolWithdrawal { .. } => {
                    vec![[10u8; 32]]
                }
                _ => vec![[11u8; 32], [12u8; 32]],
            })
            .collect();

        for (tag_label, owner_tag, mut tag_addresses) in [
            ("inline", OwnerTag::Inline([13u8; 32]), Vec::new()),
            ("account", OwnerTag::Account(2), vec![[14u8; 32]]),
        ] {
            let data = ix_data(bound(
                transfers.clone(),
                vec![TransactOutput {
                    utxo_hash: [15u8; 32],
                    owner_tag,
                    data: Some(vec![16, 17]),
                }],
            ));
            let mut all = addresses.clone();
            all.append(&mut tag_addresses);

            assert_eq!(
                program_hash(&data, &all),
                client_hash(&data, &all),
                "{tag_label} owner tag with {} legs",
                transfers.len(),
            );
        }
    }
}

/// The measured prefix is what changes the digest: a byte flipped anywhere in
/// the bound region must move the hash, and appending a tail byte must not be
/// silently accepted.
#[test]
fn bound_region_covers_every_byte_it_measures() {
    let data = ix_data(bound(
        vec![InterfaceTransfer::SolDeposit { amount: 1 }],
        vec![TransactOutput {
            utxo_hash: [15u8; 32],
            owner_tag: OwnerTag::Inline([13u8; 32]),
            data: Some(vec![16, 17]),
        }],
    ));
    let bytes = data.serialize().expect("serialize");
    let (_, bound_bytes) = TransactIxDataRef::parse_bound(&bytes).expect("parse");
    let baseline = external_data_hash(tag::TRANSACT, bound_bytes, [[10u8; 32]].iter()).unwrap();

    for index in 0..bound_bytes.len() {
        let mut flipped = bound_bytes.to_vec();
        flipped[index] ^= 0xff;
        let hash = external_data_hash(tag::TRANSACT, &flipped, [[10u8; 32]].iter()).unwrap();
        assert_ne!(
            baseline, hash,
            "byte {index} of the bound region is unbound"
        );
    }

    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(
        TransactIxDataRef::parse_bound(&trailing).is_err(),
        "a trailing byte must be rejected rather than ignored"
    );
}
