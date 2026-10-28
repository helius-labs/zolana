mod common;

use common::{keypair, wallet_utxo};
use spr_event::{OutputDataEncoding, ProoflessOutput};
use spr_transaction::{
    serialization::{
        confidential::{Confidential, ConfidentialOutputPlaintext},
        plaintext::{
            PlaintextEncode, PlaintextTransfer, TransferPlaintextRecipient,
            TransferPlaintextSender, TransferPlaintextSplChange, TransferPlaintextUtxos,
        },
        proofless::{Proofless, ProoflessEncode},
    },
    utxo::derive_transact_output_blinding,
    Address, AssetRegistry, Data, DataRecord, DecodeCx, EncryptedScheme, Mint, OutputContext,
    OutputSlot, OwnerCx, TransactionError, UtxoSerialization, TRANSFER_PLAINTEXT,
};

fn plaintext() -> TransferPlaintextUtxos {
    TransferPlaintextUtxos {
        type_prefix: TRANSFER_PLAINTEXT,
        blinding_seed: [2; 32],
        sender: Some(TransferPlaintextSender {
            owner_pubkey: keypair(41).signing_pubkey(),
            spl: Some(TransferPlaintextSplChange {
                amount: 23,
                asset_id: 9,
            }),
            sol_amount: Some(31),
            spl_data: Data::default(),
            sol_data: Data::default(),
        }),
        recipient_slots: vec![TransferPlaintextRecipient {
            owner_pubkey: keypair(42).signing_pubkey(),
            asset_id: 1,
            amount: 17,
            data: Data::default(),
        }],
    }
}

fn confidential() -> ConfidentialOutputPlaintext {
    ConfidentialOutputPlaintext {
        asset_id: 1,
        amount: 17,
        blinding: [1; 32],
        ring_program_id: None,
        data: Data::default(),
    }
}

#[test]
fn scheme_discriminators_cover_the_entire_byte_space() {
    let known = [
        (0, EncryptedScheme::Proofless),
        (1, EncryptedScheme::AnonymousRecipient),
        (2, EncryptedScheme::AnonymousSender),
        (3, EncryptedScheme::Confidential),
        (4, EncryptedScheme::RingConfidential),
        (6, EncryptedScheme::Merge),
        (7, EncryptedScheme::PlaintextTransfer),
        (8, EncryptedScheme::RingDeposit),
    ];
    for byte in 0..=u8::MAX {
        match known.iter().find(|(tag, _)| *tag == byte) {
            Some((_, scheme)) => {
                assert_eq!(EncryptedScheme::from_byte(byte), Ok(*scheme));
                assert_eq!(scheme.as_byte(), byte);
            }
            None => assert_eq!(
                EncryptedScheme::from_byte(byte),
                Err(TransactionError::BadDiscriminator(byte))
            ),
        }
    }
}

#[test]
fn payload_wrappers_validate_all_record_kinds_on_write_and_read() {
    let records = [
        DataRecord::RingData(vec![]),
        DataRecord::UtxoData(vec![1]),
        DataRecord::Memo(vec![2]),
    ];
    let mut cases = Vec::new();
    for record in &records {
        cases.push((
            Data::new(vec![record.clone(), record.clone()]),
            TransactionError::DuplicateDataRecord,
        ));
    }
    for (first, second) in [(1, 0), (2, 0), (2, 1)] {
        cases.push((
            Data::new(vec![
                records.get(first).unwrap().clone(),
                records.get(second).unwrap().clone(),
            ]),
            TransactionError::NonCanonicalDataOrder,
        ));
    }
    for (invalid, error) in cases {
        let mut note = confidential();
        note.data = invalid.clone();
        assert_eq!(note.serialize(), Err(error.clone()));
        assert_eq!(
            ConfidentialOutputPlaintext::deserialize(&wincode::serialize(&note).unwrap()),
            Err(error.clone())
        );
        for field in 0..3 {
            let mut note = plaintext();
            match field {
                0 => note.sender.as_mut().unwrap().spl_data = invalid.clone(),
                1 => note.sender.as_mut().unwrap().sol_data = invalid.clone(),
                _ => note.recipient_slots.first_mut().unwrap().data = invalid.clone(),
            }
            assert_eq!(note.serialize(), Err(error.clone()));
            assert_eq!(
                TransferPlaintextUtxos::deserialize(&wincode::serialize(&note).unwrap()),
                Err(error.clone())
            );
        }
    }
}

#[test]
fn exact_payload_decoders_reject_every_truncation_trailing_bytes_and_invalid_prefix() {
    fn reject_mutations<T>(bytes: Vec<u8>, decode: impl Fn(&[u8]) -> Result<T, TransactionError>) {
        assert!(decode(&bytes).is_ok());
        for length in 0..bytes.len() {
            assert!(
                matches!(
                    decode(bytes.get(..length).unwrap()),
                    Err(TransactionError::Deserialize(_))
                ),
                "truncation at {length}"
            );
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(matches!(
            decode(&trailing),
            Err(TransactionError::Deserialize(_))
        ));
    }
    reject_mutations(
        confidential().serialize().unwrap(),
        Confidential::deserialize,
    );
    reject_mutations(
        plaintext().serialize().unwrap(),
        PlaintextTransfer::deserialize,
    );

    let mut bad_prefix = plaintext().serialize().unwrap();
    *bad_prefix.first_mut().unwrap() = 255;
    assert_eq!(
        PlaintextTransfer::deserialize(&bad_prefix),
        Err(TransactionError::BadDiscriminator(255))
    );
}

#[test]
fn encrypted_formats_require_both_context_fields_and_reconstruction_checks_assets_and_rings() {
    let owner = keypair(43);
    for (tx_viewing_pk, salt) in [
        (None, Some([7; 16])),
        (Some(owner.viewing_pubkey()), None),
        (None, None),
    ] {
        let cx = DecodeCx {
            viewing_key: &owner.viewing_key,
            tx_viewing_pk,
            salt,
            slot_index: 0,
            first_nullifier: None,
        };
        assert_eq!(
            Confidential::decrypt(&[], &cx),
            Err(TransactionError::MissingEncryptionContext)
        );
    }
    let spl = Mint::new(Address::new_from_array([44; 32]), 9);
    let assets = AssetRegistry::new([(9, spl.asset)]).unwrap();
    let owner_cx = OwnerCx {
        owner: owner.signing_pubkey(),
        assets: &assets,
        ring_program_id: None,
        first_nullifier: Some([1; 32]),
    };
    let mut note = confidential();
    note.asset_id = 99;
    assert_eq!(
        Confidential::into_utxos(note, &owner_cx),
        Err(TransactionError::UnknownAsset(99))
    );
    let mut note = plaintext();
    note.recipient_slots.first_mut().unwrap().asset_id = 99;
    assert_eq!(
        PlaintextTransfer::into_utxos(note, &owner_cx),
        Err(TransactionError::UnknownAsset(99))
    );
    let ring_data = Data::new(vec![DataRecord::RingData(vec![1])]);
    let mut note = confidential();
    note.data = ring_data.clone();
    assert_eq!(
        Confidential::into_utxos(note, &owner_cx),
        Err(TransactionError::MissingRingProgramId)
    );
    let mut note = plaintext();
    note.recipient_slots.first_mut().unwrap().data = ring_data;
    assert_eq!(
        PlaintextTransfer::into_utxos(note, &owner_cx),
        Err(TransactionError::MissingRingProgramId)
    );
    let missing_nullifier = OwnerCx {
        first_nullifier: None,
        ..owner_cx
    };
    assert_eq!(
        PlaintextTransfer::into_utxos(plaintext(), &missing_nullifier),
        Err(TransactionError::MissingFirstNullifier)
    );
}

#[test]
fn present_change_outputs_lead_and_recipients_follow_them() {
    let owner = keypair(41);
    let spl = Mint::new(Address::new_from_array([45; 32]), 9);
    let assets = AssetRegistry::new([(9, spl.asset)]).unwrap();
    let first_nullifier = [1; 32];
    let seed = [2; 32];
    let ring = Address::new_from_array([46; 32]);
    for spl_present in [false, true] {
        for sol_present in [false, true] {
            for has_ring_data in [false, true] {
                let data = if has_ring_data {
                    Data::new(vec![DataRecord::RingData(vec![3])])
                } else {
                    Data::default()
                };
                let mut plain = plaintext();
                let plain_sender = plain.sender.as_mut().unwrap();
                plain_sender.spl = spl_present.then_some(TransferPlaintextSplChange {
                    amount: 23,
                    asset_id: 9,
                });
                plain_sender.sol_amount = sol_present.then_some(31);
                plain_sender.spl_data = if spl_present {
                    data.clone()
                } else {
                    Data::default()
                };
                plain_sender.sol_data = if sol_present {
                    data.clone()
                } else {
                    Data::default()
                };
                let mut expected = vec![];
                let sol_slot = u32::from(spl_present);
                for (present, amount, mint, slot) in [
                    (spl_present, 23, spl, 0),
                    (sol_present, 31, Mint::SOL, sol_slot),
                ] {
                    if present {
                        let mut utxo = wallet_utxo(&owner, mint, amount, 0, 1).utxo;
                        utxo.blinding =
                            derive_transact_output_blinding(&first_nullifier, &seed, slot).unwrap();
                        utxo.ring_program_id = has_ring_data.then_some(ring);
                        utxo.data = data.clone();
                        expected.push(utxo);
                    }
                }
                let mut receiver = wallet_utxo(&keypair(42), Mint::SOL, 17, 0, 1).utxo;
                let receiver_slot = u32::from(spl_present) + u32::from(sol_present);
                receiver.blinding =
                    derive_transact_output_blinding(&first_nullifier, &seed, receiver_slot)
                        .unwrap();
                expected.push(receiver);
                assert_eq!(
                    plain
                        .clone()
                        .into_utxos(&first_nullifier, &assets, Some(ring))
                        .unwrap(),
                    expected
                );
                if !spl_present && !sol_present {
                    plain.sender = None;
                    assert_eq!(
                        plain
                            .into_utxos(&first_nullifier, &assets, Some(ring))
                            .unwrap(),
                        expected
                    );
                }
            }
        }
    }
}

#[test]
fn plaintext_encoder_rejects_unknown_duplicate_reordered_and_gapped_positions() {
    let owner = keypair(47);
    let assets = AssetRegistry::default();
    let cx = OwnerCx {
        owner: owner.signing_pubkey(),
        assets: &assets,
        ring_program_id: None,
        first_nullifier: Some([1; 32]),
    };
    let encode = PlaintextEncode {
        first_nullifier: [1; 32],
        blinding_seed: [2; 32],
    };
    let at = |position| {
        let mut note = wallet_utxo(&owner, Mint::SOL, 17, 0, 1).utxo;
        note.blinding = derive_transact_output_blinding(
            &encode.first_nullifier,
            &encode.blinding_seed,
            position,
        )
        .unwrap();
        note
    };
    for (positions, index, position) in [
        (vec![0, 0], 1, 0),
        (vec![1, 0], 0, 1),
        (vec![3], 0, 3),
        (vec![0, 2], 1, 2),
        (vec![0, 1, 3], 2, 3),
    ] {
        let notes: Vec<_> = positions.into_iter().map(at).collect();
        assert_eq!(
            PlaintextTransfer::from_utxos(&notes, &cx, &encode),
            Err(TransactionError::InvalidPlaintextOutputPosition { index, position })
        );
    }
    assert_eq!(
        PlaintextTransfer::from_utxos(
            &[wallet_utxo(&owner, Mint::SOL, 17, 0, 1).utxo],
            &cx,
            &encode
        ),
        Err(TransactionError::MissingOutput)
    );
    for positions in [vec![0], vec![0, 1], vec![0, 1, 2]] {
        let notes: Vec<_> = positions.into_iter().map(at).collect();
        let parsed = PlaintextTransfer::from_utxos(&notes, &cx, &encode).unwrap();
        assert_eq!(PlaintextTransfer::into_utxos(parsed, &cx).unwrap(), notes);
    }
    let mut widest = plaintext();
    widest.sender = None;
    let recipient = widest.recipient_slots.first().unwrap().clone();
    widest.recipient_slots = vec![recipient.clone(); spr_interface::MAX_OUTPUTS];
    assert_eq!(
        widest
            .clone()
            .into_utxos(&[1; 32], &assets, None)
            .unwrap()
            .len(),
        spr_interface::MAX_OUTPUTS
    );
    widest.recipient_slots.push(recipient);
    assert_eq!(
        widest.into_utxos(&[1; 32], &assets, None),
        Err(TransactionError::TooManyOutputs)
    );
}

#[test]
fn data_requires_a_present_sender_output_but_explicit_zero_plaintext_outputs_exist() {
    let assets = AssetRegistry::new([(9, Address::new_from_array([48; 32]))]).unwrap();
    for spl in [true, false] {
        let mut plain = plaintext();
        let sender = plain.sender.as_mut().unwrap();
        if spl {
            sender.spl = None;
            sender.spl_data = Data::new(vec![DataRecord::Memo(vec![1])]);
        } else {
            sender.sol_amount = None;
            sender.sol_data = Data::new(vec![DataRecord::Memo(vec![1])]);
        }
        assert_eq!(
            plain.clone().into_utxos(&[1; 32], &assets, None),
            Err(TransactionError::DataWithoutOutput)
        );
        let sender = plain.sender.as_mut().unwrap();
        if spl {
            sender.spl = Some(TransferPlaintextSplChange {
                amount: 0,
                asset_id: 9,
            });
        } else {
            sender.sol_amount = Some(0);
        }
        let notes = plain.into_utxos(&[1; 32], &assets, None).unwrap();
        let zero = notes.iter().find(|note| note.amount == 0).unwrap();
        assert_eq!(zero.asset.asset_id, if spl { 9 } else { 1 });
        assert_eq!(zero.data.memo(), Some([1].as_slice()));
    }
}

#[test]
fn proofless_full_fields_use_exact_borsh_and_resolve_the_published_mint() {
    let owner = keypair(49);
    let mint = Mint::new(Address::new_from_array([50; 32]), 9);
    let assets = AssetRegistry::new([(9, mint.asset)]).unwrap();
    let cx = OwnerCx {
        owner: owner.signing_pubkey(),
        assets: &assets,
        ring_program_id: None,
        first_nullifier: None,
    };
    let mut note = wallet_utxo(&owner, mint, 0x0102030405060708, 7, 1);
    note.utxo.ring_program_id = Some(Address::new_from_array([51; 32]));
    note.utxo.data = Data::new(vec![
        DataRecord::RingData(vec![]),
        DataRecord::UtxoData(vec![7, 8]),
        DataRecord::Memo(vec![9]),
    ]);
    let expected = ProoflessOutput {
        owner: [1; 32],
        blinding: note.utxo.blinding,
        asset: [50; 32],
        amount: 0x0102030405060708,
        data_hash: Some([2; 32]),
        utxo_data: Some(vec![7, 8]),
        ring_program_id: Some([51; 32]),
        ring_data_hash: Some([3; 32]),
        ring_data: Some(vec![]),
        memo: Some(vec![9]),
    };
    let encode = ProoflessEncode {
        owner_hash: [1; 32],
        data_hash: Some([2; 32]),
        ring_data_hash: Some([3; 32]),
    };
    assert_eq!(
        Proofless::from_utxos(&[note.utxo.clone()], &cx, &encode).unwrap(),
        expected
    );
    let bytes = Proofless::serialize(&expected).unwrap();
    for end in 0..bytes.len() {
        assert!(matches!(
            Proofless::deserialize(bytes.get(..end).unwrap()),
            Err(TransactionError::Deserialize(_))
        ));
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(matches!(
        Proofless::deserialize(&trailing),
        Err(TransactionError::Deserialize(_))
    ));
    assert_eq!(Proofless::deserialize(&bytes).unwrap(), expected);
    assert_eq!(
        Proofless::into_utxos(expected.clone(), &cx).unwrap(),
        vec![note.utxo]
    );
    let default_assets = AssetRegistry::default();
    assert_eq!(
        Proofless::into_utxos(
            expected.clone(),
            &OwnerCx {
                assets: &default_assets,
                ..cx
            }
        ),
        Err(TransactionError::UnknownMint(mint.asset))
    );
    let encoded = Proofless::encode_plaintext(&expected, [4; 32], &encode).unwrap();
    let output_slot = OutputSlot {
        view_tag: encoded.view_tag,
        output_context: OutputContext {
            hash: [0; 32],
            tree_id: 7,
            leaf_index: 8,
        },
        payload: encoded.data,
    };
    assert_eq!(output_slot.proofless_output(), Some(expected));
    let mut blob = vec![0];
    blob.extend(bytes);
    assert_eq!(
        output_slot.output_data(),
        Some(OutputDataEncoding::Plaintext(blob.clone()))
    );
    for envelope in [
        OutputDataEncoding::Encrypted(blob.clone()),
        OutputDataEncoding::VerifiablyEncrypted(blob),
        OutputDataEncoding::Plaintext(vec![]),
        OutputDataEncoding::Plaintext(vec![7, 1]),
        OutputDataEncoding::Plaintext(vec![0, 1]),
    ] {
        let mut invalid = output_slot.clone();
        invalid.payload = borsh::to_vec(&envelope).unwrap();
        assert_eq!(invalid.proofless_output(), None);
    }
}

#[test]
fn ring_deposit_framing_preserves_opaque_payloads_and_rejects_invalid_frames() {
    use spr_event::{
        encode_encrypted_ring_deposit_output, EncryptedRingDepositData, EncryptedRingDepositOutput,
    };

    fn unframe(ciphertext: &[u8]) -> Result<Option<&[u8]>, TransactionError> {
        ciphertext
            .strip_prefix(b"frame")
            .map(Some)
            .ok_or_else(|| TransactionError::Deserialize("bad frame".into()))
    }

    let ring = Address::new_from_array([4; 32]);
    let output = EncryptedRingDepositOutput {
        owner_utxo_hash: [1; 32],
        asset: *Mint::SOL.asset.as_array(),
        amount: 50,
        data_hash: None,
        ring_program_id: *ring.as_array(),
        ring_data_hash: [2; 32],
        encrypted: EncryptedRingDepositData {
            tx_viewing_pk: *keypair(58).viewing_pubkey().as_bytes(),
            salt: [3; 16],
            ciphertext: b"frameopaque".to_vec(),
        },
    };
    let original = OutputSlot {
        view_tag: [5; 32],
        output_context: OutputContext {
            hash: [6; 32],
            tree_id: 7,
            leaf_index: 8,
        },
        payload: encode_encrypted_ring_deposit_output(output.clone()),
    };
    let mut slot = original.clone();
    slot.unwrap_ring_deposit(&Address::new_from_array([9; 32]), unframe)
        .unwrap();
    assert_eq!(slot, original, "another ring's framing is not applied");

    slot.unwrap_ring_deposit(&ring, unframe).unwrap();
    let mut unframed = output;
    unframed.encrypted.ciphertext = b"opaque".to_vec();
    let expected = OutputSlot {
        payload: encode_encrypted_ring_deposit_output(unframed),
        ..original
    };
    assert_eq!(slot, expected, "only the framing is removed");
    assert_eq!(
        slot.unwrap_ring_deposit(&ring, unframe),
        Err(TransactionError::Deserialize("bad frame".into()))
    );
    assert_eq!(slot, expected, "invalid framing does not mutate the slot");
}

#[test]
fn data_and_payload_lengths_match_literal_little_endian_layouts() {
    // Independently assembled protocol layout: u8 count, u8 tag, u16 LE length, bytes.
    let data = Data::new(vec![
        DataRecord::RingData(vec![]),
        DataRecord::UtxoData(vec![0xaa, 0xbb]),
        DataRecord::Memo(vec![0xcc]),
    ]);
    assert_eq!(
        wincode::serialize(&data).unwrap(),
        vec![3, 1, 0, 0, 2, 2, 0, 0xaa, 0xbb, 3, 1, 0, 0xcc]
    );
    assert_eq!(wincode::serialize(&Data::default()).unwrap(), vec![0]);
    let mut expected = vec![1, 3, 255, 255];
    expected.extend(vec![7; u16::MAX as usize]);
    assert_eq!(
        wincode::serialize(&Data::new(vec![DataRecord::Memo(vec![
            7;
            u16::MAX as usize
        ])]))
        .unwrap(),
        expected
    );
    assert!(wincode::serialize(&Data::new(vec![DataRecord::Memo(vec![
        7;
        u16::MAX as usize
            + 1
    ])]))
    .is_err());

    // Confidential primitive fields have no owner key: asset/amount LE, blinding, optional ring, data.
    let mut note = confidential();
    note.asset_id = 0x0102030405060708;
    note.amount = 0x1112131415161718;
    note.data = data;
    let mut expected = vec![8, 7, 6, 5, 4, 3, 2, 1, 24, 23, 22, 21, 20, 19, 18, 17];
    expected.extend([1; 32]);
    expected.push(0);
    expected.extend([3, 1, 0, 0, 2, 2, 0, 0xaa, 0xbb, 3, 1, 0, 0xcc]);
    assert_eq!(note.serialize().unwrap(), expected);

    let mut plain = plaintext();
    plain.sender = None;
    let recipient = plain.recipient_slots.first().unwrap().clone();
    plain.recipient_slots = vec![recipient.clone(); 255];
    let mut expected = vec![4];
    expected.extend([2; 32]);
    expected.extend([0, 255]);
    for _ in 0..255 {
        expected.extend(recipient.owner_pubkey.as_bytes());
        expected.extend(1u64.to_le_bytes());
        expected.extend(17u64.to_le_bytes());
        expected.push(0);
    }
    assert_eq!(plain.serialize().unwrap(), expected);
    plain.recipient_slots.push(recipient);
    assert!(matches!(
        plain.serialize(),
        Err(TransactionError::Serialize(_))
    ));
}

#[test]
fn encoders_publish_the_expected_envelope_and_scheme_with_decodable_bodies() {
    use spr_transaction::serialization::confidential::ConfidentialEncode;
    let owner = keypair(56);
    let tx = keypair(57).viewing_key;
    let salt = [7; 16];
    let decode = DecodeCx {
        viewing_key: &owner.viewing_key,
        tx_viewing_pk: Some(tx.pubkey()),
        salt: Some(salt),
        slot_index: 3,
        first_nullifier: Some([1; 32]),
    };
    let confidential_cx = ConfidentialEncode {
        tx: tx.clone(),
        recipient_pubkey: owner.viewing_pubkey(),
        salt,
        slot_index: 3,
    };
    let encoded =
        Confidential::encode_plaintext(&confidential(), [9; 32], &confidential_cx).unwrap();
    assert_eq!(encoded.view_tag, [9; 32]);
    let OutputDataEncoding::Encrypted(blob) = borsh::from_slice(&encoded.data).unwrap() else {
        panic!("confidential encrypted envelope")
    };
    assert_eq!(blob.first(), Some(&3));
    assert_eq!(
        Confidential::embedded_viewing_pk(blob.get(1..).unwrap()).unwrap(),
        owner.viewing_pubkey()
    );
    assert_eq!(
        Confidential::decode(blob.get(1..).unwrap(), &decode).unwrap(),
        confidential()
    );
    let plain_cx = PlaintextEncode {
        first_nullifier: [1; 32],
        blinding_seed: [2; 32],
    };
    let encoded = PlaintextTransfer::encode_plaintext(&plaintext(), [9; 32], &plain_cx).unwrap();
    let OutputDataEncoding::Plaintext(blob) = borsh::from_slice(&encoded.data).unwrap() else {
        panic!("plaintext envelope")
    };
    assert_eq!(blob.first(), Some(&7));
    assert_eq!(
        PlaintextTransfer::decode(blob.get(1..).unwrap(), &decode).unwrap(),
        plaintext()
    );
}
