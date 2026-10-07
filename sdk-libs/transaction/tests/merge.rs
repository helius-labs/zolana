mod common;

use std::cell::RefCell;

use common::{keypair, wallet_utxo};
use zolana_keypair::{
    DecryptedMergeEnvelope, MergeEnvelopeDecryption, P256Pubkey, ShieldedAddress, ShieldedKeypair,
    SigningKey, ViewingKey,
};
use zolana_transaction::{
    instructions::merge::{
        merge_circuit_width, merge_dummy_nullifier, merge_output_blinding, MergeBlindingSource,
        MergeProofInputs, MergeTransaction, MAX_MERGE_INPUTS,
    },
    utxo::SppProofInputUtxo,
    Address, Data, DataRecord, DecryptRequest, DeriveRequest, Mint, ShieldedKeys, TransactionError,
    TransactionKeyRequest, Utxo, WalletUtxo,
};

fn inputs(owner: &ShieldedKeypair, count: u8) -> Vec<WalletUtxo> {
    (1..=count)
        .map(|nonce| wallet_utxo(owner, Mint::SOL, 2, 0, nonce))
        .collect()
}

fn ring_input(
    owner: &ShieldedKeypair,
    ring: Address,
    mint: Mint,
    amount: u64,
    nonce: u8,
) -> WalletUtxo {
    let mut note = wallet_utxo(owner, mint, amount, 0, nonce);
    note.utxo.ring_program_id = Some(ring);
    note.utxo_hash = note
        .utxo
        .hash(&note.nullifier_pubkey, &[0; 32], &[0; 32], 0)
        .unwrap();
    note.nullifier = owner
        .nullifier(&note.utxo_hash, &note.utxo.blinding)
        .unwrap();
    note
}

fn assert_preserved(actual: &SppProofInputUtxo, expected: &WalletUtxo) {
    assert_eq!(
        (
            &actual.utxo,
            actual.nullifier_pubkey,
            actual.utxo_hash,
            actual.nullifier,
            actual.data_hash,
            actual.ring_data_hash,
            actual.tree_id,
            actual.leaf_index,
        ),
        (
            &expected.utxo,
            expected.nullifier_pubkey,
            expected.utxo_hash,
            expected.nullifier,
            expected.data_hash,
            expected.ring_data_hash,
            expected.tree_id,
            expected.leaf_index,
        )
    );
}

fn decrypt_envelope(result: &MergeProofInputs, recipient: &ViewingKey) -> DecryptedMergeEnvelope {
    let encrypted = result
        .encrypted_envelope()
        .unwrap()
        .expect("default merge envelope");
    let ephemeral_pk = P256Pubkey::from_bytes(encrypted.ephemeral_pk).unwrap();
    let decrypted = MergeEnvelopeDecryption {
        viewing_key: recipient,
        ephemeral_pk: &ephemeral_pk,
        ciphertext: &encrypted.ciphertext,
    }
    .decrypt()
    .unwrap();
    assert_eq!(decrypted.output_blinding, encrypted.output_blinding);
    decrypted
}

#[test]
fn merge_count_boundaries_are_explicit() {
    let owner = keypair(7);
    for (count, padded) in [
        (0, None),
        (1, Some(8)),
        (8, Some(8)),
        (9, Some(24)),
        (23, Some(24)),
        (24, Some(24)),
        (25, Some(54)),
        (53, Some(54)),
        (54, Some(54)),
        (55, None),
        (usize::MAX, None),
    ] {
        assert_eq!(merge_circuit_width(count), padded);
    }
    assert_eq!(
        MergeTransaction::new(vec![]).err(),
        Some(TransactionError::NoInputs)
    );
    assert_eq!(
        MergeTransaction::new(inputs(&owner, 55)).err(),
        Some(TransactionError::TooManyInputs { got: 55, max: 54 })
    );
    let ring = Address::new_from_array([8; 32]);
    assert_eq!(
        MergeTransaction::new_with_ring(vec![], ring, None).err(),
        Some(TransactionError::NoInputs)
    );
    assert_eq!(
        MergeTransaction::new_with_ring(inputs(&owner, 55), ring, None).err(),
        Some(TransactionError::TooManyInputs { got: 55, max: 54 })
    );
}

#[test]
fn every_merge_size_preserves_inputs_and_recovers_the_exact_sum() {
    let owner = keypair(7);
    let sender = owner.shielded_address().unwrap();
    for (count, padded) in [(1, 8), (8, 8), (9, 24), (24, 24), (25, 54), (54, 54)] {
        let notes = inputs(&owner, count);
        let result = MergeTransaction::new(notes.clone())
            .unwrap()
            .with_expiry(12345)
            .with_output_tree_id(17)
            .encrypt(&owner)
            .unwrap();
        assert_eq!(result.input_utxos.len(), padded);
        for (actual, expected) in result.input_utxos.iter().zip(&notes) {
            assert_preserved(actual, expected);
        }
        assert!(result
            .input_utxos
            .iter()
            .skip(notes.len())
            .all(|input| input.is_compact() && input.utxo.amount == 0));
        let decrypted = decrypt_envelope(&result, &owner.viewing_key);
        assert_eq!(
            decrypted,
            DecryptedMergeEnvelope {
                amount: u64::from(count) * 2,
                mint: Mint::SOL.asset.to_bytes(),
                output_blinding: result.output_utxo.blinding,
            }
        );
        assert_eq!(
            result.envelope.as_ref().map(|envelope| envelope.recipient),
            Some(sender.viewing_pubkey)
        );
        assert_eq!(
            (
                result.expiry_unix_ts,
                result.output_tree_id,
                result.signing_pubkey,
                result.ring_program_id
            ),
            (12345, 17, sender.signing_pubkey, None)
        );
        assert_eq!(result.output_utxo.owner_address, Some(sender));
        let recovered = Utxo {
            owner: sender.signing_pubkey,
            asset: Mint::SOL,
            amount: decrypted.amount,
            blinding: decrypted.output_blinding,
            ring_program_id: None,
            data: Data::default(),
        };
        assert_eq!(
            recovered
                .hash(&sender.nullifier_pubkey, &[0; 32], &[0; 32], 17)
                .unwrap(),
            result.output_hash().unwrap()
        );
        assert_ne!(
            result.output_utxo.hash(16).unwrap(),
            result.output_hash().unwrap()
        );
    }
}

/// A merge pads its circuit with compact slots only. Each still derives the
/// deterministic dummy nullifier of its slot, which its non-inclusion witness
/// is fetched by, and publishes 0 instead.
#[test]
fn merge_pads_with_compact_slots() {
    let owner = keypair(7);
    for (count, padded) in [(3, 8), (9, 24), (25, 54)] {
        let notes = inputs(&owner, count);
        let result = MergeTransaction::new(notes.clone())
            .unwrap()
            .encrypt(&owner)
            .unwrap();
        assert_eq!(result.input_utxos.len(), padded);
        for (actual, expected) in result.input_utxos.iter().zip(&notes) {
            assert_preserved(actual, expected);
        }
        let padding: Vec<_> = result.input_utxos.iter().skip(notes.len()).collect();
        assert!(padding.iter().all(|input| input.is_compact()));
        assert!(padding
            .iter()
            .all(|input| input.published_nullifier() == [0u8; 32]));
        let first = result.input_utxos.first().unwrap().nullifier;
        let expected: Vec<_> = (notes.len()..padded)
            .map(|slot| merge_dummy_nullifier(&owner.nullifier_key, &first, slot as u8).unwrap())
            .collect();
        assert_eq!(result.dummy_nullifiers(), expected);
        result.check_padding().expect("compact merge padding");
    }
}

#[test]
fn ring_merge_pads_with_compact_slots() {
    let owner = keypair(7);
    let ring = Address::new_from_array([8; 32]);
    let notes: Vec<WalletUtxo> = inputs(&owner, 53)
        .into_iter()
        .map(|mut note| {
            note.utxo.ring_program_id = Some(ring);
            note.utxo_hash = note
                .utxo
                .hash(&note.nullifier_pubkey, &[0; 32], &[0; 32], 0)
                .unwrap();
            note.nullifier = owner
                .nullifier(&note.utxo_hash, &note.utxo.blinding)
                .unwrap();
            note
        })
        .collect();
    let result = MergeTransaction::new_with_ring(notes.clone(), ring, None)
        .unwrap()
        .encrypt(&owner)
        .unwrap();
    assert_eq!(result.input_utxos.len(), MAX_MERGE_INPUTS);
    assert_eq!(result.ring_program_id, Some(ring));
    for (actual, expected) in result.input_utxos.iter().zip(&notes) {
        assert_preserved(actual, expected);
    }
    let padding: Vec<_> = result.input_utxos.iter().skip(notes.len()).collect();
    assert_eq!(padding.len(), 1);
    assert!(padding
        .iter()
        .all(|input| input.is_compact() && input.published_nullifier() == [0u8; 32]));
    result.check_padding().expect("compact ring merge padding");
}

/// SPP fills compact padding back in at the end and picks the circuit from the
/// sent count, so a merge with compact padding elsewhere or at another width
/// is refused before proving.
#[test]
fn merge_padding_must_match_what_spp_fills_back_in() {
    let owner = keypair(7);
    let compact = MergeTransaction::new(inputs(&owner, 3))
        .unwrap()
        .encrypt(&owner)
        .unwrap();
    let tree_id = compact.input_utxos.first().unwrap().tree_id;

    let mut dummy_after_compact = compact.clone();
    *dummy_after_compact.input_utxos.get_mut(4).unwrap() =
        SppProofInputUtxo::dummy(tree_id).unwrap();
    assert!(matches!(
        dummy_after_compact.check_padding(),
        Err(TransactionError::InputAfterCompactPadding { index: 4 })
    ));

    let mut too_wide = compact;
    too_wide
        .input_utxos
        .resize(54, SppProofInputUtxo::compact(tree_id).unwrap());
    assert!(matches!(
        too_wide.check_padding(),
        Err(TransactionError::CompactMergeWidthMismatch { sent: 3, width: 54 })
    ));

    let mut dummies = MergeTransaction::new(inputs(&owner, 3))
        .unwrap()
        .encrypt(&owner)
        .unwrap();
    for input in dummies.input_utxos.iter_mut().skip(3) {
        input.compact = false;
    }
    dummies
        .check_padding()
        .expect("deterministic dummies fill the circuit");
}

#[test]
fn merge_requires_one_mint_and_checked_total() {
    let owner = keypair(7);
    for mint in [
        Mint::new(Address::new_from_array([9; 32]), 2),
        Mint::new(Mint::SOL.asset, 99),
    ] {
        let notes = vec![
            wallet_utxo(&owner, Mint::SOL, 1, 0, 1),
            wallet_utxo(&owner, mint, 1, 0, 2),
        ];
        assert_eq!(
            MergeTransaction::new(notes).err(),
            Some(TransactionError::MergeInputAssetMismatch { index: 1 })
        );
    }
    let exact = vec![
        wallet_utxo(&owner, Mint::SOL, u64::MAX - 1, 0, 1),
        wallet_utxo(&owner, Mint::SOL, 1, 0, 2),
    ];
    let result = MergeTransaction::new(exact)
        .unwrap()
        .encrypt(&owner)
        .unwrap();
    assert_eq!(result.output_utxo.amount, u64::MAX);
    let over = vec![
        wallet_utxo(&owner, Mint::SOL, u64::MAX, 0, 1),
        wallet_utxo(&owner, Mint::SOL, 1, 0, 2),
    ];
    assert_eq!(
        MergeTransaction::new(over).err(),
        Some(TransactionError::SelectedBalanceOverflow)
    );
}

#[test]
fn default_and_ring_merge_apply_distinct_data_rules() {
    let owner = keypair(7);
    let ring = Address::new_from_array([8; 32]);
    let base = wallet_utxo(&owner, Mint::SOL, 2, 0, 1);
    let mut ring_note = base.clone();
    ring_note.utxo.ring_program_id = Some(ring);
    assert_eq!(
        MergeTransaction::new(vec![ring_note.clone()]).err(),
        Some(TransactionError::MergeInputRingMismatch { index: 0 })
    );
    assert_eq!(
        MergeTransaction::new_with_ring(vec![base.clone()], ring, None).err(),
        Some(TransactionError::MergeInputRingMismatch { index: 0 })
    );
    for record in [
        DataRecord::Memo(vec![1]),
        DataRecord::RingData(vec![1]),
        DataRecord::UtxoData(vec![1]),
    ] {
        let mut note = base.clone();
        note.utxo.data = Data::new(vec![record]);
        assert_eq!(
            MergeTransaction::new(vec![note]).err(),
            Some(TransactionError::MergeInputHasData { index: 0 })
        );
    }
    for is_ring_hash in [false, true] {
        let mut note = base.clone();
        if is_ring_hash {
            note.ring_data_hash = Some([0; 32]);
        } else {
            note.data_hash = Some([0; 32]);
        }
        assert_eq!(
            MergeTransaction::new(vec![note]).err(),
            Some(TransactionError::MergeInputHasData { index: 0 })
        );
    }
    for preimage in [false, true] {
        let mut note = ring_note.clone();
        if preimage {
            note.utxo.data = Data::new(vec![DataRecord::UtxoData(vec![1])]);
        } else {
            note.data_hash = Some([0; 32]);
        }
        assert_eq!(
            MergeTransaction::new_with_ring(vec![note], ring, None).err(),
            Some(TransactionError::MergeInputHasData { index: 0 })
        );
    }
    ring_note.utxo.data = Data::new(vec![
        DataRecord::RingData(vec![1]),
        DataRecord::Memo(vec![2]),
    ]);
    ring_note.ring_data_hash = Some([3; 32]);
    ring_note.utxo_hash = ring_note
        .utxo
        .hash(&ring_note.nullifier_pubkey, &[0; 32], &[3; 32], 0)
        .unwrap();
    ring_note.nullifier = owner
        .nullifier(&ring_note.utxo_hash, &ring_note.utxo.blinding)
        .unwrap();
    let first_nullifier = ring_note.nullifier;
    let result = MergeTransaction::new_with_ring(vec![ring_note], ring, Some([4; 32]))
        .unwrap()
        .encrypt(&owner)
        .unwrap();
    assert_eq!(result.output_utxo.ring_data_hash, Some([4; 32]));
    assert_eq!(result.output_utxo.ring_program_id, Some(ring));
    assert_eq!(result.input_utxo_hashes().unwrap().len(), 1);
    assert!(result.envelope.is_none());
    assert_eq!(
        (result.output_utxo.amount, result.output_utxo.blinding),
        (
            2,
            merge_output_blinding(&owner.nullifier_key, &first_nullifier).unwrap()
        )
    );
}

#[test]
fn merge_rejects_foreign_owner_rail_and_nullifier_key() {
    let owner = keypair(7);
    let stranger = keypair(9);
    let p256 =
        ShieldedKeypair::from_keypair(SigningKey::from_p256_bytes(&[5; 32]).unwrap()).unwrap();
    let sender = owner.shielded_address().unwrap();
    let tx = ViewingKey::new();
    for (foreign, error) in [
        (
            wallet_utxo(&stranger, Mint::SOL, 1, 0, 2),
            TransactionError::MergeInputOwnerMismatch { index: 1 },
        ),
        (
            wallet_utxo(&p256, Mint::SOL, 1, 0, 2),
            TransactionError::MergeInputRailMismatch { index: 1 },
        ),
        (
            {
                let mut n = wallet_utxo(&owner, Mint::SOL, 1, 0, 2);
                n.nullifier_pubkey = stranger.shielded_address().unwrap().nullifier_pubkey;
                n
            },
            TransactionError::MergeInputNullifierKeyMismatch { index: 1 },
        ),
    ] {
        let notes = vec![wallet_utxo(&owner, Mint::SOL, 1, 0, 1), foreign];
        assert_eq!(
            MergeTransaction::new(notes.clone())
                .unwrap()
                .encrypt(&owner)
                .err(),
            Some(error.clone())
        );
        assert_eq!(
            MergeTransaction::new(notes)
                .unwrap()
                .encrypt_with(
                    &sender,
                    MergeBlindingSource::Envelope { ephemeral: &tx },
                    &[]
                )
                .err(),
            Some(error)
        );
    }
    let result = MergeTransaction::new(inputs(&p256, 1))
        .unwrap()
        .encrypt(&p256)
        .unwrap();
    assert_eq!(result.signing_pubkey, p256.signing_pubkey());
    assert_eq!(result.output_utxo.amount, 2);
}

#[test]
fn merge_accessors_filter_dummies_and_recheck_data() {
    let owner = keypair(7);
    let mut result = MergeTransaction::new(inputs(&owner, 2))
        .unwrap()
        .encrypt(&owner)
        .unwrap();
    assert_eq!(result.input_utxo_hashes().unwrap().len(), 2);
    let first = result.input_utxos.first().unwrap().nullifier;
    let expected = (2..8)
        .map(|slot| merge_dummy_nullifier(&owner.nullifier_key, &first, slot).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(result.dummy_nullifiers(), expected);
    result.input_utxos.get_mut(1).unwrap().utxo.data = Data::new(vec![DataRecord::Memo(vec![1])]);
    assert_eq!(
        result.input_utxo_hashes().err(),
        Some(TransactionError::MergeInputHasData { index: 1 })
    );
    result.input_utxos.clear();
    assert!(result.dummy_nullifiers().is_empty());
    result
        .input_utxos
        .push(SppProofInputUtxo::dummy_with_blinding([0; 32], 0).unwrap());
    assert_eq!(
        result.dummy_nullifiers(),
        vec![result.input_utxos[0].nullifier]
    );
}

#[derive(Clone, Copy)]
enum Reply {
    Normal,
    EmptyDerive,
    EmptyKey,
    DeriveError,
    KeyError,
    AddressError,
}

struct RecordingKeys {
    owner: ShieldedKeypair,
    reply: Reply,
    derived: RefCell<Vec<DeriveRequest>>,
    keys: RefCell<Vec<TransactionKeyRequest>>,
}

impl ShieldedKeys for RecordingKeys {
    fn address(&self) -> Result<ShieldedAddress, TransactionError> {
        if matches!(self.reply, Reply::AddressError) {
            return Err(TransactionError::Authority("address".into()));
        }
        self.owner.address()
    }
    fn viewing_public_keys(&self) -> Vec<P256Pubkey> {
        self.owner.viewing_public_keys()
    }
    fn decrypt(&self, requests: &[DecryptRequest<'_>]) -> Result<Vec<Vec<u8>>, TransactionError> {
        self.owner.decrypt(requests)
    }
    fn derive(&self, requests: &[DeriveRequest]) -> Result<Vec<[u8; 32]>, TransactionError> {
        self.derived.borrow_mut().extend_from_slice(requests);
        match self.reply {
            Reply::EmptyDerive => Ok(vec![]),
            Reply::DeriveError => Err(TransactionError::Authority("derive".into())),
            _ => self.owner.derive(requests),
        }
    }
    fn transaction_keys(
        &self,
        requests: &[TransactionKeyRequest],
    ) -> Result<Vec<ViewingKey>, TransactionError> {
        self.keys.borrow_mut().extend_from_slice(requests);
        match self.reply {
            Reply::EmptyKey => Ok(vec![]),
            Reply::KeyError => Err(TransactionError::Authority("key".into())),
            _ => self.owner.transaction_keys(requests),
        }
    }
}

#[test]
fn merge_routes_key_requests_and_propagates_failures() {
    for (reply, expected_error) in [
        (Reply::Normal, None),
        (
            Reply::EmptyDerive,
            Some(TransactionError::IncompleteDerivation { got: 0, want: 7 }),
        ),
        (Reply::EmptyKey, None),
        (
            Reply::DeriveError,
            Some(TransactionError::Authority("derive".into())),
        ),
        (Reply::KeyError, None),
        (
            Reply::AddressError,
            Some(TransactionError::Authority("address".into())),
        ),
    ] {
        let keys = RecordingKeys {
            owner: keypair(7),
            reply,
            derived: RefCell::new(vec![]),
            keys: RefCell::new(vec![]),
        };
        let notes = inputs(&keys.owner, 1);
        let first_nullifier = notes.first().unwrap().nullifier;
        let result = MergeTransaction::new(notes).unwrap().encrypt(&keys);
        assert!(keys.keys.borrow().is_empty(), "a merge needs no tx key");
        if let Some(error) = expected_error {
            assert_eq!(result.err(), Some(error));
            continue;
        }
        let output = result.unwrap();
        assert_eq!(
            *keys.derived.borrow(),
            (1..8)
                .map(|slot_index| DeriveRequest::MergeDummyNullifier {
                    first_nullifier,
                    slot_index
                })
                .collect::<Vec<_>>()
        );
        assert_eq!(
            output.output_utxo.blinding,
            decrypt_envelope(&output, &keys.owner.viewing_key).output_blinding
        );
    }
}

#[test]
fn ring_merge_derives_its_output_blinding_from_the_nullifier_secret() {
    let keys = RecordingKeys {
        owner: keypair(7),
        reply: Reply::Normal,
        derived: RefCell::new(vec![]),
        keys: RefCell::new(vec![]),
    };
    let ring = Address::new_from_array([8; 32]);
    let note = ring_input(&keys.owner, ring, Mint::SOL, 2, 1);
    let first_nullifier = note.nullifier;
    let output = MergeTransaction::new_with_ring(vec![note], ring, None)
        .unwrap()
        .encrypt(&keys)
        .unwrap();
    assert_eq!(
        *keys.derived.borrow(),
        std::iter::once(DeriveRequest::MergeOutputBlinding { first_nullifier })
            .chain((1..8).map(|slot_index| DeriveRequest::MergeDummyNullifier {
                first_nullifier,
                slot_index
            }))
            .collect::<Vec<_>>()
    );
    assert!(output.envelope.is_none());
    assert_eq!(
        output.output_utxo.blinding,
        merge_output_blinding(&keys.owner.nullifier_key, &first_nullifier).unwrap()
    );
}

#[test]
fn merge_blinding_source_must_match_the_rail() {
    let owner = keypair(7);
    let sender = owner.shielded_address().unwrap();
    let ring = Address::new_from_array([8; 32]);
    let ephemeral = ViewingKey::new();
    assert_eq!(
        MergeTransaction::new_with_ring(
            vec![ring_input(&owner, ring, Mint::SOL, 2, 1)],
            ring,
            None
        )
        .unwrap()
        .encrypt_with(
            &sender,
            MergeBlindingSource::Envelope {
                ephemeral: &ephemeral
            },
            &[[0; 32]; 7]
        )
        .err(),
        Some(TransactionError::MergeBlindingRailMismatch)
    );
    assert_eq!(
        MergeTransaction::new(inputs(&owner, 1))
            .unwrap()
            .encrypt_with(
                &sender,
                MergeBlindingSource::Derived {
                    output_blinding: [6; 32]
                },
                &[[0; 32]; 7]
            )
            .err(),
        Some(TransactionError::MergeBlindingRailMismatch)
    );
}

#[test]
fn default_merge_envelope_encrypts_to_the_owner_with_the_given_ephemeral_key() {
    let owner = keypair(7);
    let notes = inputs(&owner, 1);
    let first_nullifier = notes.first().unwrap().nullifier;
    let dummy_nullifiers = (1..8)
        .map(|slot| merge_dummy_nullifier(&owner.nullifier_key, &first_nullifier, slot).unwrap())
        .collect::<Vec<_>>();
    let ephemeral = ViewingKey::from_bytes(&[3; 32]).unwrap();
    let result = MergeTransaction::new(notes)
        .unwrap()
        .encrypt_with(
            &owner.shielded_address().unwrap(),
            MergeBlindingSource::Envelope {
                ephemeral: &ephemeral,
            },
            &dummy_nullifiers,
        )
        .unwrap();
    let encrypted = result.encrypted_envelope().unwrap().unwrap();
    assert_eq!(encrypted.ephemeral_pk, *ephemeral.pubkey().as_bytes());
    let foreign = MergeEnvelopeDecryption {
        viewing_key: &keypair(9).viewing_key,
        ephemeral_pk: &ephemeral.pubkey(),
        ciphertext: &encrypted.ciphertext,
    }
    .decrypt()
    .unwrap();
    assert_ne!(foreign.output_blinding, result.output_utxo.blinding);
}

#[test]
fn ring_merge_preserves_spl_and_explicit_output_context() {
    let owner = keypair(7);
    let sender = owner.shielded_address().unwrap();
    let mint = Mint::new(Address::new_from_array([10; 32]), 77);
    let ring = Address::new_from_array([8; 32]);
    let notes: Vec<_> = [(5, 1), (9, 2)]
        .into_iter()
        .map(|(amount, nonce)| ring_input(&owner, ring, mint, amount, nonce))
        .collect();
    let first_nullifier = notes.first().unwrap().nullifier;
    let dummy_nullifiers = (2..8)
        .map(|slot| merge_dummy_nullifier(&owner.nullifier_key, &first_nullifier, slot).unwrap())
        .collect::<Vec<_>>();
    let result = MergeTransaction::new_with_ring(notes, ring, None)
        .unwrap()
        .with_expiry(500)
        .with_output_tree_id(12)
        .encrypt_with(
            &sender,
            MergeBlindingSource::Derived {
                output_blinding: [6; 32],
            },
            &dummy_nullifiers,
        )
        .unwrap();
    assert!(result.envelope.is_none());
    assert_eq!(
        (
            result.output_utxo.asset,
            result.output_utxo.amount,
            result.output_utxo.blinding,
            result.output_utxo.ring_data_hash,
            result.output_tree_id,
            result.expiry_unix_ts
        ),
        (mint, 14, [6; 32], None, 12, 500)
    );
    let recovered = Utxo {
        owner: sender.signing_pubkey,
        asset: mint,
        amount: 14,
        blinding: [6; 32],
        ring_program_id: Some(ring),
        data: Data::default(),
    };
    assert_eq!(
        recovered
            .hash(&sender.nullifier_pubkey, &[0; 32], &[0; 32], 12)
            .unwrap(),
        result.output_hash().unwrap()
    );
}

#[test]
fn merge_derivations_match_shared_vectors_and_bind_every_parameter() {
    use zolana_keypair::NullifierKey;
    use zolana_transaction::instructions::merge::{
        merge_private_tx_blinding, DOMAIN_MERGE_DUMMY_NULLIFIER, DOMAIN_MERGE_OUTPUT_BLINDING_V1,
    };
    #[derive(serde::Deserialize)]
    struct Vectors {
        merge_recovery: Recovery,
    }
    #[derive(serde::Deserialize)]
    struct Recovery {
        nullifier_secret: String,
        first_nullifier: String,
        output_blinding: String,
        dummy_slot_index: u8,
        dummy_nullifier: String,
        private_tx_blinding: String,
    }
    let vector: Vectors =
        serde_json::from_str(include_str!("../../../test-vectors/key_derivation.json")).unwrap();
    let vector = vector.merge_recovery;
    let secret: [u8; 31] = hex::decode(vector.nullifier_secret)
        .unwrap()
        .try_into()
        .unwrap();
    let first: [u8; 32] = hex::decode(vector.first_nullifier)
        .unwrap()
        .try_into()
        .unwrap();
    let key = NullifierKey::from_secret(secret);
    let output = merge_output_blinding(&key, &first).unwrap();
    let dummy = merge_dummy_nullifier(&key, &first, vector.dummy_slot_index).unwrap();
    assert_eq!(hex::encode(output), vector.output_blinding);
    assert_eq!(hex::encode(dummy), vector.dummy_nullifier);
    assert_eq!(DOMAIN_MERGE_DUMMY_NULLIFIER, u32::from_be_bytes(*b"TMDN"));
    assert_eq!(
        DOMAIN_MERGE_OUTPUT_BLINDING_V1,
        u32::from_be_bytes(*b"TMOB")
    );
    let mut other_secret = secret;
    other_secret[30] = other_secret[30].checked_add(1).unwrap();
    let other_key = NullifierKey::from_secret(other_secret);
    let mut other_first = first;
    other_first[31] = other_first[31].checked_add(1).unwrap();
    assert_ne!(output, merge_output_blinding(&other_key, &first).unwrap());
    assert_ne!(output, merge_output_blinding(&key, &other_first).unwrap());
    assert_ne!(
        dummy,
        merge_dummy_nullifier(&other_key, &first, vector.dummy_slot_index).unwrap()
    );
    assert_ne!(
        dummy,
        merge_dummy_nullifier(&key, &other_first, vector.dummy_slot_index).unwrap()
    );
    assert_ne!(
        dummy,
        merge_dummy_nullifier(
            &key,
            &first,
            vector.dummy_slot_index.checked_add(1).unwrap()
        )
        .unwrap()
    );
    let private = merge_private_tx_blinding(&key, &first).unwrap();
    assert_eq!(hex::encode(private), vector.private_tx_blinding);
    assert_ne!(private, output);
    assert_ne!(private, dummy);
    assert_ne!(
        private,
        merge_private_tx_blinding(&other_key, &first).unwrap()
    );
    assert_ne!(
        private,
        merge_private_tx_blinding(&key, &other_first).unwrap()
    );
}
