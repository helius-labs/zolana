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
    deposit::{DepositIxData, UtxoData, ZoneDepositIxData},
    merge_transact::{
        MergeTransactIxData, MergeTransactIxDataRef, MERGE_ENCRYPTED_UTXO_LEN, MERGE_INPUT_COUNT,
    },
    merge_zone::{MergeZoneIxData, MergeZoneIxDataRef},
    transact::{
        InputUtxo, OwnerTag, P256Proof, TransactIxData, TransactIxDataRef, TransactOutput,
        TransactProof,
    },
};

mod strategies {
    use super::*;

    pub fn owner_tag() -> impl Strategy<Value = OwnerTag> {
        prop_oneof![
            any::<[u8; 32]>().prop_map(OwnerTag::Inline),
            any::<u8>().prop_map(OwnerTag::Account),
            Just(OwnerTag::P256SigningKey),
        ]
    }

    pub fn transact_proof() -> impl Strategy<Value = TransactProof> {
        prop_oneof![
            (any::<[u8; 32]>(), any::<[u8; 64]>(), any::<[u8; 32]>())
                .prop_map(|(a, b, c)| TransactProof::Eddsa { a, b, c }),
            (
                any::<[u8; 32]>(),
                any::<[u8; 64]>(),
                any::<[u8; 32]>(),
                any::<[u8; 32]>(),
                any::<[u8; 32]>(),
            )
                .prop_map(|(a, b, c, commitment, commitment_pok)| {
                    TransactProof::P256(P256Proof {
                        a,
                        b,
                        c,
                        commitment,
                        commitment_pok,
                    })
                }),
        ]
    }

    pub fn input_utxo() -> impl Strategy<Value = InputUtxo> {
        (
            any::<[u8; 32]>(),
            any::<u16>(),
            any::<u16>(),
            any::<u8>(),
            any::<u8>(),
        )
            .prop_map(
                |(
                    nullifier_hash,
                    nullifier_tree_root_index,
                    utxo_tree_root_index,
                    tree_index,
                    eddsa_signer_index,
                )| InputUtxo {
                    nullifier_hash,
                    nullifier_tree_root_index,
                    utxo_tree_root_index,
                    tree_index,
                    eddsa_signer_index,
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
                any::<u16>(),
                any::<[u8; 32]>(),
                prop::option::of(any::<[u8; 32]>()),
                any::<[u8; 33]>(),
                any::<[u8; 16]>(),
                transact_proof(),
            ),
            (
                prop::collection::vec(input_utxo(), 0..=5),
                prop::option::of(any::<i64>()),
                prop::option::of(any::<i64>()),
                prop::option::of(any::<[u8; 32]>()),
                prop::option::of(any::<[u8; 32]>()),
                prop::collection::vec(transact_output(), 0..=8),
                prop::collection::vec(message_data(), 0..=3),
            ),
        )
            .prop_map(
                |(
                    (
                        expiry_unix_ts,
                        relayer_fee,
                        private_tx_hash,
                        p256_signing_pk_x,
                        tx_viewing_pk,
                        salt,
                        proof,
                    ),
                    (
                        inputs,
                        public_sol_amount,
                        public_spl_amount,
                        data_hash,
                        zone_data_hash,
                        outputs,
                        messages,
                    ),
                )| TransactIxData {
                    expiry_unix_ts,
                    relayer_fee,
                    private_tx_hash,
                    p256_signing_pk_x,
                    tx_viewing_pk,
                    salt,
                    proof,
                    inputs,
                    public_sol_amount,
                    public_spl_amount,
                    data_hash,
                    zone_data_hash,
                    outputs,
                    messages,
                },
            )
    }

    pub fn merge_ix_data() -> impl Strategy<Value = MergeTransactIxData> {
        (
            any::<u64>(),
            (
                any::<[u8; 32]>(),
                any::<[u8; 64]>(),
                any::<[u8; 32]>(),
                any::<[u8; 32]>(),
                any::<[u8; 32]>(),
            ),
            any::<[u8; 32]>(),
            prop::collection::vec(any::<[u8; 32]>(), MERGE_INPUT_COUNT),
            prop::collection::vec(any::<u16>(), MERGE_INPUT_COUNT),
            prop::collection::vec(any::<u16>(), MERGE_INPUT_COUNT),
            any::<[u8; 32]>(),
            prop::collection::vec(any::<u8>(), MERGE_ENCRYPTED_UTXO_LEN),
            any::<bool>(),
        )
            .prop_map(
                |(
                    expiry_unix_ts,
                    (a, b, c, commitment, commitment_pok),
                    output_utxo_hash,
                    nullifiers,
                    utxo_tree_root_index,
                    nullifier_tree_root_index,
                    private_tx_hash,
                    encrypted_utxo,
                    eddsa_owner,
                )| {
                    MergeTransactIxData {
                        expiry_unix_ts,
                        proof: P256Proof {
                            a,
                            b,
                            c,
                            commitment,
                            commitment_pok,
                        },
                        output_utxo_hash,
                        nullifiers,
                        utxo_tree_root_index,
                        nullifier_tree_root_index,
                        private_tx_hash,
                        encrypted_utxo,
                        eddsa_owner,
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
    prop_assert_eq!(view.relayer_fee, owned.relayer_fee);
    prop_assert_eq!(view.private_tx_hash, &owned.private_tx_hash);
    prop_assert_eq!(view.p256_signing_pk_x, owned.p256_signing_pk_x);
    prop_assert_eq!(view.tx_viewing_pk, &owned.tx_viewing_pk);
    prop_assert_eq!(view.salt, &owned.salt);
    prop_assert_eq!(view.proof, owned.proof);
    prop_assert_eq!(&view.inputs, &owned.inputs);
    prop_assert_eq!(view.public_sol_amount, owned.public_sol_amount);
    prop_assert_eq!(view.public_spl_amount, owned.public_spl_amount);
    prop_assert_eq!(view.data_hash, owned.data_hash);
    prop_assert_eq!(view.zone_data_hash, owned.zone_data_hash);
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
        let _ = MergeZoneIxData::deserialize(&bytes);
        let _ = MergeZoneIxDataRef::from_bytes(&bytes);
        let _ = DepositIxData::deserialize(&bytes);
        let _ = ZoneDepositIxData::deserialize(&bytes);
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

    /// The merge view decoder accepts exactly the 8-in/1-out shape with a
    /// 110-byte encrypted output; every other element count is rejected.
    #[test]
    fn merge_shape_guard_accepts_exactly_the_documented_shape(
        owned in strategies::merge_ix_data(),
        nullifier_count in 0usize..=12,
        root_count in 0usize..=12,
        blob_len in 0usize..=180,
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

        let mut wrong_blob = owned;
        wrong_blob.encrypted_utxo = vec![9u8; blob_len];
        let bytes = wrong_blob.serialize().expect("serialize merge ix");
        prop_assert_eq!(
            MergeTransactIxDataRef::from_bytes(&bytes).is_ok(),
            blob_len == MERGE_ENCRYPTED_UTXO_LEN
        );
    }

    /// The `merge_zone` wrapper enforces the embedded merge shape through its
    /// own decoder.
    #[test]
    fn merge_zone_wrapper_enforces_the_embedded_shape(
        merge in strategies::merge_ix_data(),
        view_tag in any::<[u8; 32]>(),
        drop_last_nullifier in any::<bool>(),
    ) {
        let mut owned = MergeZoneIxData {
            merge_view_tag: view_tag,
            merge,
        };
        if drop_last_nullifier {
            owned.merge.nullifiers.pop();
        }
        let bytes = owned.serialize().expect("serialize merge_zone ix");
        prop_assert_eq!(
            MergeZoneIxDataRef::from_bytes(&bytes).is_ok(),
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
        blinding in any::<[u8; 31]>(),
        amount in any::<u64>(),
        utxo_data in prop::option::of((any::<[u8; 32]>(), prop::collection::vec(any::<u8>(), 0..300))),
        memo in prop::option::of(prop::collection::vec(any::<u8>(), 0..300)),
        zone_data_hash in any::<[u8; 32]>(),
        zone_data in prop::collection::vec(any::<u8>(), 0..300),
        cut in any::<prop::sample::Index>(),
        trailing in any::<u8>(),
    ) {
        let utxo_data = utxo_data.map(|(data_hash, data)| UtxoData { data_hash, data });
        let deposit = DepositIxData {
            view_tag,
            owner,
            blinding,
            amount,
            utxo_data: utxo_data.clone(),
            memo: memo.clone(),
        };
        let zone_deposit = ZoneDepositIxData {
            view_tag,
            owner,
            blinding,
            amount,
            zone_data_hash,
            zone_data,
            utxo_data,
            memo,
        };
        let deposit_bytes = deposit.serialize().expect("serialize deposit ix");
        let zone_bytes = zone_deposit.serialize().expect("serialize zone deposit ix");

        let cut_at = cut.index(deposit_bytes.len());
        prop_assert!(DepositIxData::deserialize(deposit_bytes.get(..cut_at).unwrap_or_default()).is_err());
        let cut_at = cut.index(zone_bytes.len());
        prop_assert!(ZoneDepositIxData::deserialize(zone_bytes.get(..cut_at).unwrap_or_default()).is_err());

        let mut extended = deposit_bytes;
        extended.push(trailing);
        prop_assert!(DepositIxData::deserialize(&extended).is_err());
        let mut extended = zone_bytes;
        extended.push(trailing);
        prop_assert!(ZoneDepositIxData::deserialize(&extended).is_err());
    }
}
