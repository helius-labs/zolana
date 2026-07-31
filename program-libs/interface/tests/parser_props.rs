//! Property tests for the owned wire parsers of the interface crate: the
//! decoders the program runs on untrusted instruction data. Three invariant
//! families:
//!
//! 1. Arbitrary bytes never panic any parser; they parse or fail cleanly.
//! 2. Structured corruptions of valid encodings (truncation, trailing bytes,
//!    bit flips) never panic, and exact-length decoders reject length changes.
//! 3. The owned decoder and the zero-copy view decoder agree field-by-field on
//!    every valid encoding (two hand-maintained decode paths, not a derive
//!    round-trip).

use proptest::{prelude::*, test_runner::TestCaseError};
use zolana_event::MessageData;
use zolana_interface::instruction::instruction_data::{
    deposit::{
        DepositEntry, DepositIxData, EncryptedRingDepositData, UtxoData, RingDepositEntry,
        RingDepositIxData,
    },
    merge_transact::{MergeProof, MergeTransactIxData, MergeTransactIxDataRef, MERGE_INPUT_COUNT},
    merge_ring::{MergeRingIxData, MergeRingIxDataRef},
    transact::{
        CircuitId, InputUtxo, InterfaceTransfer, OwnerTag, TransactIxData, TransactIxDataRef,
        TransactOutput, TransactProof,
    },
};

mod strategies {
    use super::*;

    pub fn owner_tag() -> impl Strategy<Value = OwnerTag> {
        prop_oneof![
            any::<[u8; 32]>().prop_map(OwnerTag::Inline),
            any::<u8>().prop_map(OwnerTag::Account),
        ]
    }

    pub fn circuit_id() -> impl Strategy<Value = CircuitId> {
        (0u8..3, any::<u8>(), any::<u8>(), any::<u8>()).prop_map(
            |(variant, n_in, n_out, n_slots)| match variant {
                0 => CircuitId::ConfidentialEddsa(n_in, n_out, n_slots),
                1 => CircuitId::RingEddsa(n_in, n_out, n_slots),
                _ => CircuitId::RingAuthority(n_in, n_out, n_slots),
            },
        )
    }

    pub fn transact_proof() -> impl Strategy<Value = TransactProof> {
        (any::<[u8; 32]>(), any::<[u8; 64]>(), any::<[u8; 32]>())
            .prop_map(|(a, b, c)| TransactProof { a, b, c })
    }

    pub fn interface_transfer() -> impl Strategy<Value = InterfaceTransfer> {
        prop_oneof![
            any::<u64>().prop_map(|amount| InterfaceTransfer::SolDeposit { amount }),
            any::<u64>().prop_map(|amount| InterfaceTransfer::SolWithdrawal { amount }),
            (any::<u64>(), any::<u8>()).prop_map(|(amount, spl_interface_bump)| {
                InterfaceTransfer::SplDeposit {
                    amount,
                    spl_interface_bump,
                }
            }),
            (any::<u64>(), any::<u8>()).prop_map(|(amount, spl_interface_bump)| {
                InterfaceTransfer::SplWithdrawal {
                    amount,
                    spl_interface_bump,
                }
            }),
        ]
    }

    pub fn input_utxo() -> impl Strategy<Value = InputUtxo> {
        (any::<[u8; 32]>(), any::<u16>(), any::<u16>()).prop_map(
            |(nullifier_hash, nullifier_tree_root_index, utxo_tree_root_index)| InputUtxo {
                nullifier_hash,
                nullifier_tree_root_index,
                utxo_tree_root_index,
            },
        )
    }

    pub fn transact_output() -> impl Strategy<Value = TransactOutput> {
        (
            any::<[u8; 32]>(),
            owner_tag(),
            // Beyond 255 bytes so the u16 data length prefix is exercised.
            prop::option::of(prop::collection::vec(any::<u8>(), 0..300)),
        )
            .prop_map(|(utxo_hash, owner_tag, data)| TransactOutput {
                utxo_hash,
                owner_tag,
                data,
            })
    }

    pub fn message_data() -> impl Strategy<Value = MessageData> {
        (
            any::<[u8; 32]>(),
            prop::collection::vec(any::<u8>(), 0..300),
        )
            .prop_map(|(view_tag, data)| MessageData { view_tag, data })
    }

    pub fn transact_ix_data() -> impl Strategy<Value = TransactIxData> {
        (
            (
                any::<u64>(),
                any::<[u8; 32]>(),
                circuit_id(),
                any::<[u8; 33]>(),
                any::<[u8; 16]>(),
                transact_proof(),
            ),
            (
                prop::collection::vec(input_utxo(), 0..=5),
                prop::collection::vec(interface_transfer(), 0..=4),
                prop::option::of(any::<[u8; 32]>()),
                prop::option::of(any::<[u8; 32]>()),
                prop::collection::vec(transact_output(), 0..=8),
                prop::collection::vec(message_data(), 0..=3),
            ),
        )
            .prop_map(
                |(
                    (expiry_unix_ts, private_tx_hash, circuit, tx_viewing_pk, salt, proof),
                    (inputs, interface_transfers, data_hash, ring_data_hash, outputs, messages),
                )| TransactIxData {
                    expiry_unix_ts,
                    private_tx_hash,
                    circuit,
                    tx_viewing_pk,
                    salt,
                    proof,
                    inputs,
                    interface_transfers,
                    data_hash,
                    ring_data_hash,
                    outputs,
                    messages,
                },
            )
    }

    pub fn merge_ix_data() -> impl Strategy<Value = MergeTransactIxData> {
        (
            any::<u64>(),
            (any::<[u8; 32]>(), any::<[u8; 64]>(), any::<[u8; 32]>()),
            any::<[u8; 32]>(),
            prop::collection::vec(any::<[u8; 32]>(), MERGE_INPUT_COUNT),
            prop::collection::vec(any::<u16>(), MERGE_INPUT_COUNT),
            prop::collection::vec(any::<u16>(), MERGE_INPUT_COUNT),
            any::<[u8; 32]>(),
            any::<bool>(),
        )
            .prop_map(
                |(
                    expiry_unix_ts,
                    (a, b, c),
                    output_utxo_hash,
                    nullifiers,
                    utxo_tree_root_index,
                    nullifier_tree_root_index,
                    private_tx_hash,
                    eddsa_owner,
                )| {
                    MergeTransactIxData {
                        expiry_unix_ts,
                        proof: MergeProof { a, b, c },
                        output_utxo_hash,
                        eddsa_owner,
                        private_tx_hash,
                        nullifiers,
                        utxo_tree_root_index,
                        nullifier_tree_root_index,
                    }
                },
            )
    }
}

/// Every field of the zero-copy view must equal its owned counterpart.
fn assert_ref_matches_owned(
    view: &TransactIxDataRef,
    owned: &TransactIxData,
) -> Result<(), TestCaseError> {
    prop_assert_eq!(view.expiry_unix_ts, owned.expiry_unix_ts);
    prop_assert_eq!(view.private_tx_hash, &owned.private_tx_hash);
    prop_assert_eq!(view.circuit, owned.circuit);
    prop_assert_eq!(view.tx_viewing_pk, &owned.tx_viewing_pk);
    prop_assert_eq!(view.salt, &owned.salt);
    prop_assert_eq!(view.proof, owned.proof);
    prop_assert_eq!(&view.inputs, &owned.inputs);
    prop_assert_eq!(&view.interface_transfers, &owned.interface_transfers);
    prop_assert_eq!(view.data_hash, owned.data_hash);
    prop_assert_eq!(view.ring_data_hash, owned.ring_data_hash);
    prop_assert_eq!(view.outputs.len(), owned.outputs.len());
    for (got, want) in view.outputs.iter().zip(owned.outputs.iter()) {
        prop_assert_eq!(got.utxo_hash, &want.utxo_hash);
        prop_assert_eq!(got.owner_tag, want.owner_tag);
        prop_assert_eq!(got.data, want.data.as_deref());
    }
    prop_assert_eq!(view.messages.len(), owned.messages.len());
    for (got, want) in view.messages.iter().zip(owned.messages.iter()) {
        prop_assert_eq!(got.view_tag, &want.view_tag);
        prop_assert_eq!(got.data, want.data.as_slice());
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    /// Arbitrary bytes never panic any owned instruction-data parser; every
    /// decoder returns `Ok` or a clean `Err`.
    #[test]
    fn arbitrary_bytes_never_panic_any_ix_parser(bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
        let _ = TransactIxData::deserialize(&bytes);
        let _ = TransactIxDataRef::from_bytes(&bytes);
        let _ = MergeTransactIxData::deserialize(&bytes);
        let _ = MergeTransactIxDataRef::from_bytes(&bytes);
        let _ = MergeRingIxData::deserialize(&bytes);
        let _ = MergeRingIxDataRef::from_bytes(&bytes);
        let _ = DepositIxData::deserialize(&bytes);
        let _ = RingDepositIxData::deserialize(&bytes);
    }

    /// The owned exact-length decoder and the zero-copy view agree
    /// field-by-field on every valid `transact` encoding.
    #[test]
    fn transact_owned_and_ref_decoders_agree(owned in strategies::transact_ix_data()) {
        let bytes = owned.serialize().expect("serialize transact ix");
        let reparsed = TransactIxData::deserialize(&bytes).ok();
        prop_assert_eq!(reparsed.as_ref(), Some(&owned));
        let view = TransactIxDataRef::from_bytes(&bytes);
        prop_assert!(view.is_ok(), "ref parse failed on valid encoding: {:?}", view.err());
        if let Ok(view) = view {
            assert_ref_matches_owned(&view, &owned)?;
        }
    }

    /// Truncating or extending a valid `transact` encoding never panics, and
    /// the exact-length owned decoder rejects both length changes.
    #[test]
    fn transact_length_corruptions_fail_cleanly(
        owned in strategies::transact_ix_data(),
        cut in any::<prop::sample::Index>(),
        trailing in any::<u8>(),
        flip in any::<prop::sample::Index>(),
        flip_mask in 1u8..=255,
    ) {
        let bytes = owned.serialize().expect("serialize transact ix");

        // Truncation strictly under-runs a pending read: must fail, not panic.
        if !bytes.is_empty() {
            let cut_at = cut.index(bytes.len());
            let truncated = bytes.get(..cut_at).unwrap_or_default();
            prop_assert!(TransactIxData::deserialize(truncated).is_err());
            let _ = TransactIxDataRef::from_bytes(truncated);
        }

        // A trailing byte violates the exact-length contract of `deserialize`.
        let mut extended = bytes.clone();
        extended.push(trailing);
        prop_assert!(TransactIxData::deserialize(&extended).is_err());
        let _ = TransactIxDataRef::from_bytes(&extended);

        // A flipped byte may decode to a different message or fail; it must
        // never panic.
        let mut flipped = bytes;
        if !flipped.is_empty() {
            let at = flip.index(flipped.len());
            if let Some(byte) = flipped.get_mut(at) {
                *byte ^= flip_mask;
            }
            let _ = TransactIxData::deserialize(&flipped);
            let _ = TransactIxDataRef::from_bytes(&flipped);
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// The merge view decoder accepts exactly the 8-in/1-out shape; every
    /// other nullifier or root-index element count is rejected.
    #[test]
    fn merge_shape_guard_accepts_exactly_the_documented_shape(
        owned in strategies::merge_ix_data(),
        nullifier_count in 0usize..=12,
        root_count in 0usize..=12,
    ) {
        let bytes = owned.serialize().expect("serialize merge ix");
        prop_assert!(MergeTransactIxDataRef::from_bytes(&bytes).is_ok());

        let mut wrong_nullifiers = owned.clone();
        wrong_nullifiers.nullifiers = vec![[7u8; 32]; nullifier_count];
        let bytes = wrong_nullifiers.serialize().expect("serialize merge ix");
        prop_assert_eq!(
            MergeTransactIxDataRef::from_bytes(&bytes).is_ok(),
            nullifier_count == MERGE_INPUT_COUNT
        );

        let mut wrong_roots = owned.clone();
        wrong_roots.nullifier_tree_root_index = vec![3u16; root_count];
        let bytes = wrong_roots.serialize().expect("serialize merge ix");
        prop_assert_eq!(
            MergeTransactIxDataRef::from_bytes(&bytes).is_ok(),
            root_count == MERGE_INPUT_COUNT
        );
    }

    /// The `merge_ring` wrapper enforces the embedded merge shape through its
    /// own decoder.
    #[test]
    fn merge_ring_wrapper_enforces_the_embedded_shape(
        merge in strategies::merge_ix_data(),
        view_tag in any::<[u8; 32]>(),
        drop_last_nullifier in any::<bool>(),
    ) {
        let mut owned = MergeRingIxData {
            output_ring_data_hash: view_tag,
            merge,
        };
        if drop_last_nullifier {
            owned.merge.nullifiers.pop();
        }
        let bytes = owned.serialize().expect("serialize merge_ring ix");
        prop_assert_eq!(
            MergeRingIxDataRef::from_bytes(&bytes).is_ok(),
            !drop_last_nullifier
        );
    }

    /// The deposit decoders enforce their exact-length wire contract: any
    /// truncation or trailing byte on a valid encoding is rejected cleanly,
    /// including around >255-byte payloads behind u16 length prefixes.
    #[test]
    fn deposit_length_corruptions_fail_cleanly(
        view_tag in any::<[u8; 32]>(),
        owner in any::<[u8; 32]>(),
        blinding in any::<[u8; 32]>(),
        amount in any::<u64>(),
        utxo_data in prop::option::of((any::<[u8; 32]>(), prop::collection::vec(any::<u8>(), 0..300))),
        memo in prop::option::of(prop::collection::vec(any::<u8>(), 0..300)),
        ring_data_hash in any::<[u8; 32]>(),
        ring_data in prop::collection::vec(any::<u8>(), 0..300),
        cut in any::<prop::sample::Index>(),
        trailing in any::<u8>(),
    ) {
        let utxo_data = utxo_data.map(|(data_hash, data)| UtxoData { data_hash, data });
        let entry = DepositEntry {
            asset_index: 0,
            view_tag,
            owner,
            blinding,
            amount,
            utxo_data: utxo_data.clone(),
            memo: memo.clone(),
        };
        let deposit = DepositIxData {
            assets: vec![],
            deposits: vec![entry.clone()],
        };
        let ring_deposit = RingDepositIxData {
            assets: vec![],
            deposits: vec![RingDepositEntry {
                asset_index: 0,
                view_tag,
                owner_utxo_hash: owner,
                amount,
                data_hash: utxo_data.map(|data| data.data_hash),
                ring_data_hash,
                encrypted: EncryptedRingDepositData {
                    tx_viewing_pk: [blinding[0]; 33],
                    salt: [blinding[1]; 16],
                    ciphertext: ring_data,
                },
            }],
        };
        let deposit_bytes = deposit.serialize().expect("serialize deposit ix");
        let ring_bytes = ring_deposit.serialize().expect("serialize ring deposit ix");

        let cut_at = cut.index(deposit_bytes.len());
        prop_assert!(DepositIxData::deserialize(deposit_bytes.get(..cut_at).unwrap_or_default()).is_err());
        let cut_at = cut.index(ring_bytes.len());
        prop_assert!(RingDepositIxData::deserialize(ring_bytes.get(..cut_at).unwrap_or_default()).is_err());

        let mut extended = deposit_bytes;
        extended.push(trailing);
        prop_assert!(DepositIxData::deserialize(&extended).is_err());
        let mut extended = ring_bytes;
        extended.push(trailing);
        prop_assert!(RingDepositIxData::deserialize(&extended).is_err());
    }
}
