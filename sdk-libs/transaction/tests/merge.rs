mod common;

use std::cell::RefCell;

use borsh::BorshDeserialize;
use common::{keypair, wallet_utxo};
use zolana_event::OutputDataEncoding;
use zolana_keypair::{P256Pubkey, ShieldedAddress, ShieldedKeypair, SigningKey, ViewingKey};
use zolana_transaction::{
    instructions::merge::{
        merge_dummy_nullifier, merge_output_blinding, merge_padded_input_count, MergeProofInputs,
        MergeTransaction,
    },
    serialization::confidential::{Confidential, ConfidentialOutputPlaintext},
    utxo::SppProofInputUtxo,
    Address, Data, DataRecord, DecodeCx, DecryptRequest, DeriveRequest, EncryptedScheme, Mint,
    ShieldedKeys, TransactionError, TransactionKeyRequest, UtxoSerialization, WalletUtxo,
};

fn inputs(owner: &ShieldedKeypair, count: u8) -> Vec<WalletUtxo> {
    (1..=count)
        .map(|nonce| wallet_utxo(owner, Mint::SOL, 2, 0, nonce))
        .collect()
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

fn recover(
    result: &MergeProofInputs,
    tx: &ViewingKey,
    recipient: &ViewingKey,
) -> ConfidentialOutputPlaintext {
    let OutputDataEncoding::Encrypted(blob) =
        OutputDataEncoding::try_from_slice(&result.output_data.data).expect("envelope")
    else {
        panic!("encrypted merge output");
    };
    let (scheme, body) = blob.split_first().expect("scheme");
    assert_eq!(
        *scheme,
        if result.ring_program_id.is_some() {
            EncryptedScheme::RingConfidential.as_byte()
        } else {
            EncryptedScheme::Confidential.as_byte()
        }
    );
    assert_eq!(
        Confidential::embedded_viewing_pk(body).unwrap(),
        recipient.pubkey()
    );
    let recipient_plaintext = Confidential::decode(
        body,
        &DecodeCx {
            viewing_key: recipient,
            tx_viewing_pk: Some(P256Pubkey::from_bytes(result.tx_viewing_pk).unwrap()),
            salt: Some(result.salt),
            slot_index: 0,
            first_nullifier: None,
        },
    )
    .expect("recipient recovers merge");
    let tx_plaintext = Confidential::decrypt_with_tx_key(tx, body, result.salt, 0)
        .expect("transaction key recovers merge");
    assert_eq!(recipient_plaintext, tx_plaintext);
    recipient_plaintext
}

#[test]
fn merge_count_boundaries_are_explicit() {
    let owner = keypair(7);
    for (count, padded) in [
        (0, Some(8)),
        (1, Some(8)),
        (7, Some(8)),
        (8, Some(8)),
        (9, Some(36)),
        (35, Some(36)),
        (36, Some(36)),
        (37, None),
        (usize::MAX, None),
    ] {
        assert_eq!(merge_padded_input_count(count), padded);
    }
    assert_eq!(
        MergeTransaction::new(vec![]).err(),
        Some(TransactionError::NoInputs)
    );
    assert_eq!(
        MergeTransaction::new(inputs(&owner, 37)).err(),
        Some(TransactionError::TooManyInputs { got: 37, max: 36 })
    );
    let ring = Address::new_from_array([8; 32]);
    assert_eq!(
        MergeTransaction::new_with_ring(vec![], ring, None).err(),
        Some(TransactionError::NoInputs)
    );
    assert_eq!(
        MergeTransaction::new_with_ring(inputs(&owner, 37), ring, None).err(),
        Some(TransactionError::TooManyInputs { got: 37, max: 36 })
    );
}

#[test]
fn both_merge_sizes_preserve_inputs_and_recover_the_exact_sum() {
    let owner = keypair(7);
    let sender = owner.shielded_address().unwrap();
    for (count, padded) in [(1, 8), (8, 8), (9, 36), (36, 36)] {
        let notes = inputs(&owner, count);
        let first_nullifier = notes.first().unwrap().nullifier;
        let tx = owner.get_transaction_viewing_key(&first_nullifier).unwrap();
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
            .all(|input| input.is_dummy() && input.utxo.amount == 0));
        let expected_blinding =
            merge_output_blinding(&owner.nullifier_key, &first_nullifier).unwrap();
        let expected = ConfidentialOutputPlaintext {
            asset_id: Mint::SOL.asset_id,
            amount: u64::from(count) * 2,
            blinding: expected_blinding,
            ring_program_id: None,
            data: Data::default(),
        };
        assert_eq!(recover(&result, &tx, &owner.viewing_key), expected);
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
        assert_eq!(result.tx_viewing_pk, *tx.pubkey().as_bytes());
        assert_eq!(
            result.output_data.view_tag,
            sender.signing_pubkey.confidential_view_tag().unwrap()
        );
        let recovered = expected
            .into_utxo(sender.signing_pubkey, &Default::default())
            .unwrap();
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
    let tx = owner
        .get_transaction_viewing_key(&ring_note.nullifier)
        .unwrap();
    let result = MergeTransaction::new_with_ring(vec![ring_note], ring, Some([4; 32]))
        .unwrap()
        .encrypt(&owner)
        .unwrap();
    assert_eq!(result.output_utxo.ring_data_hash, Some([4; 32]));
    assert_eq!(result.output_utxo.ring_program_id, Some(ring));
    assert_eq!(result.input_utxo_hashes().unwrap().len(), 1);
    let plaintext = recover(&result, &tx, &owner.viewing_key);
    assert_eq!(
        (plaintext.amount, plaintext.ring_program_id, plaintext.data),
        (2, Some(ring), Data::default())
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
                .encrypt_with_viewing_key(&sender, &tx, [0; 32], &[])
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
            Some(TransactionError::IncompleteDerivation { got: 0, want: 8 }),
        ),
        (
            Reply::EmptyKey,
            Some(TransactionError::IncompleteDerivation { got: 0, want: 1 }),
        ),
        (
            Reply::DeriveError,
            Some(TransactionError::Authority("derive".into())),
        ),
        (
            Reply::KeyError,
            Some(TransactionError::Authority("key".into())),
        ),
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
        if let Some(error) = expected_error {
            assert_eq!(result.err(), Some(error));
        } else {
            let output = result.unwrap();
            assert_eq!(
                *keys.derived.borrow(),
                std::iter::once(DeriveRequest::MergeOutputBlinding { first_nullifier })
                    .chain((1..8).map(|slot_index| DeriveRequest::MergeDummyNullifier {
                        first_nullifier,
                        slot_index
                    }))
                    .collect::<Vec<_>>()
            );
            assert_eq!(
                *keys.keys.borrow(),
                vec![TransactionKeyRequest {
                    viewing_pubkey: keys.owner.viewing_pubkey(),
                    first_nullifier
                }]
            );
            assert_eq!(
                output.output_utxo.blinding,
                merge_output_blinding(&keys.owner.nullifier_key, &first_nullifier).unwrap()
            );
        }
        if matches!(
            reply,
            Reply::EmptyDerive | Reply::DeriveError | Reply::AddressError
        ) {
            assert!(
                keys.keys.borrow().is_empty(),
                "no later key call after failure"
            );
        }
    }
}

#[test]
fn ring_merge_preserves_spl_and_explicit_output_context() {
    let owner = keypair(7);
    let sender = owner.shielded_address().unwrap();
    let mint = Mint::new(Address::new_from_array([10; 32]), 77);
    let ring = Address::new_from_array([8; 32]);
    let notes: Vec<_> = [(5, 1), (9, 2)]
        .into_iter()
        .map(|(amount, nonce)| {
            let mut note = wallet_utxo(&owner, mint, amount, 0, nonce);
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
    let tx = ViewingKey::new();
    let first_nullifier = notes[0].nullifier;
    let dummy_nullifiers = (2..8)
        .map(|slot| merge_dummy_nullifier(&owner.nullifier_key, &first_nullifier, slot).unwrap())
        .collect::<Vec<_>>();
    let result = MergeTransaction::new_with_ring(notes, ring, None)
        .unwrap()
        .with_expiry(500)
        .with_output_tree_id(12)
        .encrypt_with_viewing_key(&sender, &tx, [6; 32], &dummy_nullifiers)
        .unwrap();
    let expected = ConfidentialOutputPlaintext {
        asset_id: 77,
        amount: 14,
        blinding: [6; 32],
        ring_program_id: Some(ring),
        data: Data::default(),
    };
    assert_eq!(recover(&result, &tx, &owner.viewing_key), expected);
    assert_eq!(
        (
            result.output_utxo.asset,
            result.output_utxo.amount,
            result.output_utxo.ring_data_hash,
            result.output_tree_id,
            result.expiry_unix_ts
        ),
        (mint, 14, None, 12, 500)
    );
    let assets = zolana_transaction::AssetRegistry::new([(77, mint.asset)]).unwrap();
    let recovered = expected.into_utxo(sender.signing_pubkey, &assets).unwrap();
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
