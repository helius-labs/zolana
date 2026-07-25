//! The one-pass writer must produce exactly the borsh encoding of the
//! `GeneralEvent` it stands in for, or indexers and wallets stop parsing deposit
//! events. These properties compare it against the derived implementation over
//! arbitrary events, and pin that the precomputed length is exact so the encoding
//! lands in a single allocation.

use proptest::prelude::*;
use zolana_event::{
    encode_event_instruction, encode_output_data, DepositWithdraw, EventKind, GeneralEvent,
    OutputUtxo, ProoflessEvent, ProoflessOutput, ProoflessOutputSlot,
};

/// The event the writer stands in for, built the original way: each output's
/// plaintext encoded into its own byte vector, then the whole struct serialized.
fn reference_event(
    slots: &[ProoflessOutputSlot],
    deposit_withdraws: &[DepositWithdraw],
    first_output_leaf_index: u64,
    output_tree: [u8; 32],
) -> GeneralEvent {
    GeneralEvent {
        inputs: Vec::new(),
        outputs: slots
            .iter()
            .map(|slot| OutputUtxo {
                view_tag: slot.view_tag,
                utxo_hash: slot.utxo_hash,
                data: encode_output_data(slot.output.clone()),
            })
            .collect(),
        messages: Vec::new(),
        tx_viewing_pk: [0u8; 33],
        salt: [0u8; 16],
        first_output_leaf_index,
        output_tree,
        relay_fee: None,
        deposit_withdraws: deposit_withdraws.to_vec(),
    }
}

fn arb_hash() -> impl Strategy<Value = [u8; 32]> {
    any::<[u8; 32]>()
}

fn arb_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..300)
}

fn arb_output() -> impl Strategy<Value = ProoflessOutput> {
    (
        arb_hash(),
        any::<[u8; 31]>(),
        arb_hash(),
        any::<u64>(),
        prop::option::of(arb_hash()),
        prop::option::of(arb_bytes()),
        prop::option::of(arb_hash()),
        prop::option::of(arb_hash()),
        prop::option::of(arb_bytes()),
        prop::option::of(arb_bytes()),
    )
        .prop_map(
            |(
                owner,
                blinding,
                asset,
                amount,
                data_hash,
                utxo_data,
                zone_program_id,
                zone_data_hash,
                zone_data,
                memo,
            )| ProoflessOutput {
                owner,
                blinding,
                asset,
                amount,
                data_hash,
                utxo_data,
                zone_program_id,
                zone_data_hash,
                zone_data,
                memo,
            },
        )
}

fn arb_slot() -> impl Strategy<Value = ProoflessOutputSlot> {
    (arb_hash(), arb_hash(), arb_output()).prop_map(|(view_tag, utxo_hash, output)| {
        ProoflessOutputSlot {
            view_tag,
            utxo_hash,
            output,
        }
    })
}

fn arb_deposit_withdraw() -> impl Strategy<Value = DepositWithdraw> {
    (any::<bool>(), any::<u64>(), prop::option::of(arb_hash())).prop_map(
        |(is_deposit, amount, asset)| DepositWithdraw {
            is_deposit,
            amount,
            asset,
        },
    )
}

proptest! {
    /// The whole point: byte-for-byte identical to the derived borsh encoding.
    #[test]
    fn writer_matches_derived_borsh(
        slots in prop::collection::vec(arb_slot(), 1..6),
        deposit_withdraws in prop::collection::vec(arb_deposit_withdraw(), 1..6),
        first_output_leaf_index in any::<u64>(),
        output_tree in arb_hash(),
    ) {
        let written = ProoflessEvent {
            outputs: &slots,
            deposit_withdraws: &deposit_withdraws,
            first_output_leaf_index,
            output_tree,
        }
        .encode(EventKind::Deposit)
        .expect("encode");

        let expected = encode_event_instruction(
            EventKind::Deposit,
            reference_event(&slots, &deposit_withdraws, first_output_leaf_index, output_tree),
        );
        prop_assert_eq!(written, expected);
    }

    /// The precomputed length must be exact, otherwise the single allocation
    /// either reallocates or over-reserves.
    #[test]
    fn encoded_len_is_exact(
        slots in prop::collection::vec(arb_slot(), 1..6),
        deposit_withdraws in prop::collection::vec(arb_deposit_withdraw(), 1..6),
        first_output_leaf_index in any::<u64>(),
        output_tree in arb_hash(),
    ) {
        let event = ProoflessEvent {
            outputs: &slots,
            deposit_withdraws: &deposit_withdraws,
            first_output_leaf_index,
            output_tree,
        };
        let encoded_len = event.encoded_len().expect("length");
        let encoded = event.encode(EventKind::Deposit).expect("encode");
        // Two bytes for the instruction tag and the event kind.
        prop_assert_eq!(encoded.len(), encoded_len + 2);
    }

    /// What is written decodes back to the event it stands in for.
    #[test]
    fn written_event_decodes_back(
        slots in prop::collection::vec(arb_slot(), 1..6),
        deposit_withdraws in prop::collection::vec(arb_deposit_withdraw(), 1..6),
        first_output_leaf_index in any::<u64>(),
        output_tree in arb_hash(),
    ) {
        let written = ProoflessEvent {
            outputs: &slots,
            deposit_withdraws: &deposit_withdraws,
            first_output_leaf_index,
            output_tree,
        }
        .encode(EventKind::Deposit)
        .expect("encode");

        let decoded = zolana_event::decode_event_instruction(&written).expect("decode");
        prop_assert_eq!(
            decoded,
            reference_event(&slots, &deposit_withdraws, first_output_leaf_index, output_tree)
        );
    }
}
