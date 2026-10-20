mod common;

use std::cell::RefCell;

use common::{keypair, wallet_utxo};
use zolana_keypair::{ShieldedAddress, ShieldedKeypair, SigningKey, ViewingKey, X25519Pubkey};
use zolana_transaction::{
    instructions::merge::{
        merge_circuit_width, merge_dummy_nullifier, merge_output_blinding, merge_output_key,
        MergeOutputPlaintext, MergeOutputSecrets, MergeProofInputs, MergeTransaction,
        MAX_MERGE_INPUTS,
    },
    utxo::{SppProofInputUtxo, Utxo},
    Address, AssetRegistry, Data, DataRecord, DecryptRequest, DeriveRequest, Mint, ShieldedKeys,
    TransactionError, TransactionKeyRequest, WalletUtxo,
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

/// Decrypts the merge output the way the owner's wallet does: the salt and
/// ciphertext the instruction carries, the per-merge key and the blinding from
/// the nullifier secret, and nothing the merger could withhold.
fn recover(result: &MergeProofInputs, owner: &ShieldedKeypair, assets: &AssetRegistry) -> Utxo {
    let first_nullifier = result.input_utxos.first().expect("first input").nullifier;
    let mut body = result.output_ciphertext_salt.to_vec();
    for element in &result.output_ciphertext {
        body.extend_from_slice(element);
    }
    let plaintext = MergeOutputPlaintext::decrypt(
        &body,
        &merge_output_key(&owner.nullifier_key, &first_nullifier).unwrap(),
    )
    .expect("owner decrypts the merge output");
    plaintext.into_utxo(
        owner.signing_pubkey(),
        assets.mint(&plaintext.mint).expect("registered mint"),
        merge_output_blinding(&owner.nullifier_key, &first_nullifier).unwrap(),
        result.ring_program_id,
    )
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
        (25, Some(52)),
        (51, Some(52)),
        (52, Some(52)),
        (53, None),
        (usize::MAX, None),
    ] {
        assert_eq!(merge_circuit_width(count), padded);
    }
    assert_eq!(
        MergeTransaction::new(vec![]).err(),
        Some(TransactionError::NoInputs)
    );
    assert_eq!(
        MergeTransaction::new(inputs(&owner, 53)).err(),
        Some(TransactionError::TooManyInputs { got: 53, max: 52 })
    );
    let ring = Address::new_from_array([8; 32]);
    assert_eq!(
        MergeTransaction::new_with_ring(vec![], ring, None).err(),
        Some(TransactionError::NoInputs)
    );
    assert_eq!(
        MergeTransaction::new_with_ring(inputs(&owner, 53), ring, None).err(),
        Some(TransactionError::TooManyInputs { got: 53, max: 52 })
    );
}

#[test]
fn every_merge_size_preserves_inputs_and_recovers_the_exact_sum() {
    let owner = keypair(7);
    let sender = owner.shielded_address().unwrap();
    for (count, padded) in [(1, 8), (8, 8), (9, 24), (24, 24), (25, 52), (52, 52)] {
        let notes = inputs(&owner, count);
        let first_nullifier = notes.first().unwrap().nullifier;
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
        let expected_blinding =
            merge_output_blinding(&owner.nullifier_key, &first_nullifier).unwrap();
        let recovered = recover(&result, &owner, &Default::default());
        assert_eq!(
            recovered,
            Utxo {
                owner: sender.signing_pubkey,
                asset: Mint::SOL,
                amount: u64::from(count) * 2,
                blinding: expected_blinding,
                ring_program_id: None,
                data: Data::default(),
            }
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
    for (count, padded) in [(3, 8), (9, 24), (25, 52)] {
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
    let notes: Vec<WalletUtxo> = inputs(&owner, 51)
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
        .resize(52, SppProofInputUtxo::compact(tree_id).unwrap());
    assert!(matches!(
        too_wide.check_padding(),
        Err(TransactionError::CompactMergeWidthMismatch { sent: 3, width: 52 })
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
    let two_trees = vec![
        wallet_utxo(&owner, Mint::SOL, 1, 0, 1),
        wallet_utxo(&owner, Mint::SOL, 1, 1, 2),
    ];
    assert_eq!(
        MergeTransaction::new(two_trees).err(),
        Some(TransactionError::MergeInputTreeMismatch { index: 1 })
    );
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
    assert_eq!(
        MergeTransaction::new_with_ring(vec![ring_note.clone()], ring, Some([4; 32])).err(),
        Some(TransactionError::MergeOutputRingDataMismatch)
    );
    let result = MergeTransaction::new_with_ring(vec![ring_note], ring, None)
        .unwrap()
        .encrypt(&owner)
        .unwrap();
    assert_eq!(result.output_utxo.ring_data_hash, Some([3; 32]));
    assert_eq!(result.output_utxo.ring_program_id, Some(ring));
    assert_eq!(result.input_utxo_hashes().unwrap().len(), 1);
    let recovered = recover(&result, &owner, &Default::default());
    assert_eq!(
        (recovered.amount, recovered.ring_program_id, recovered.data),
        (2, Some(ring), Data::default())
    );
}

#[test]
fn merge_rejects_foreign_owner_rail_and_nullifier_key() {
    let owner = keypair(7);
    let stranger = keypair(9);
    let independent =
        ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[5; 32])).unwrap();
    let sender = owner.shielded_address().unwrap();
    let secrets = MergeOutputSecrets {
        blinding: [0; 32],
        key: [0; 32],
    };
    for (foreign, error) in [
        (
            wallet_utxo(&stranger, Mint::SOL, 1, 0, 2),
            TransactionError::MergeInputOwnerMismatch { index: 1 },
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
                .encrypt_with_derived(&sender, secrets, [0; 16], &[])
                .err(),
            Some(error)
        );
    }
    let result = MergeTransaction::new(inputs(&independent, 1))
        .unwrap()
        .encrypt(&independent)
        .unwrap();
    assert_eq!(result.signing_pubkey, independent.signing_pubkey());
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
    DeriveError,
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
    fn viewing_public_keys(&self) -> Vec<X25519Pubkey> {
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
        self.owner.transaction_keys(requests)
    }
}

#[test]
fn merge_routes_key_requests_and_propagates_failures() {
    for (reply, expected_error) in [
        (Reply::Normal, None),
        (
            Reply::EmptyDerive,
            Some(TransactionError::IncompleteDerivation { got: 0, want: 9 }),
        ),
        (
            Reply::DeriveError,
            Some(TransactionError::Authority("derive".into())),
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
                [
                    DeriveRequest::MergeOutputBlinding { first_nullifier },
                    DeriveRequest::MergeOutputKey { first_nullifier },
                ]
                .into_iter()
                .chain((1..8).map(|slot_index| DeriveRequest::MergeDummyNullifier {
                    first_nullifier,
                    slot_index
                }))
                .collect::<Vec<_>>()
            );
            assert_eq!(
                output.output_utxo.blinding,
                merge_output_blinding(&keys.owner.nullifier_key, &first_nullifier).unwrap()
            );
            assert_eq!(
                recover(&output, &keys.owner, &Default::default()).amount,
                output.output_utxo.amount
            );
        }
        // The output ciphertext is keyed by the nullifier secret, so a merge
        // never asks the wallet for a transaction viewing key.
        assert!(
            keys.keys.borrow().is_empty(),
            "merge requested a viewing key"
        );
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
    let first_nullifier = notes.first().unwrap().nullifier;
    let dummy_nullifiers = (2..8)
        .map(|slot| merge_dummy_nullifier(&owner.nullifier_key, &first_nullifier, slot).unwrap())
        .collect::<Vec<_>>();
    let blinding = merge_output_blinding(&owner.nullifier_key, &first_nullifier).unwrap();
    let result = MergeTransaction::new_with_ring(notes, ring, None)
        .unwrap()
        .with_expiry(500)
        .with_output_tree_id(12)
        .encrypt_with_derived(
            &sender,
            MergeOutputSecrets {
                blinding,
                key: merge_output_key(&owner.nullifier_key, &first_nullifier).unwrap(),
            },
            [9; 16],
            &dummy_nullifiers,
        )
        .unwrap();
    assert_eq!(result.output_ciphertext_salt, [9; 16]);
    let assets = zolana_transaction::AssetRegistry::new([(77, mint.asset)]).unwrap();
    let recovered = recover(&result, &owner, &assets);
    assert_eq!(
        recovered,
        Utxo {
            owner: sender.signing_pubkey,
            asset: mint,
            amount: 14,
            blinding,
            ring_program_id: Some(ring),
            data: Data::default(),
        }
    );
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

#[test]
fn merge_output_ciphertext_matches_shared_vectors_and_decrypts_only_under_its_key() {
    use zolana_keypair::NullifierKey;
    use zolana_transaction::{
        instructions::merge::{
            merge_output_key, DOMAIN_MERGE_OUTPUT_CIPHERTEXT, DOMAIN_MERGE_OUTPUT_KEY,
        },
        EncryptedScheme,
    };
    #[derive(serde::Deserialize)]
    struct Vectors {
        merge_recovery: Recovery,
    }
    #[derive(serde::Deserialize)]
    struct Recovery {
        nullifier_secret: String,
        first_nullifier: String,
        output_key: String,
        output_ciphertext_salt: String,
        output_amount: u64,
        output_mint: String,
        output_ciphertext: Vec<String>,
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
    let nullifier_key = NullifierKey::from_secret(secret);
    let key = merge_output_key(&nullifier_key, &first).unwrap();
    assert_eq!(hex::encode(key), vector.output_key);
    assert_eq!(DOMAIN_MERGE_OUTPUT_KEY, u32::from_be_bytes(*b"TMOK"));
    assert_eq!(DOMAIN_MERGE_OUTPUT_CIPHERTEXT, u32::from_be_bytes(*b"TMOC"));
    // The indexer writes the scheme byte the wallet dispatches on.
    assert_eq!(
        EncryptedScheme::Merge.as_byte(),
        zolana_event::MERGE_OUTPUT_SCHEME
    );

    let mint: [u8; 32] = hex::decode(vector.output_mint).unwrap().try_into().unwrap();
    let plaintext = MergeOutputPlaintext {
        amount: vector.output_amount,
        mint: Address::new_from_array(mint),
    };
    let salt: [u8; 16] = hex::decode(vector.output_ciphertext_salt)
        .unwrap()
        .try_into()
        .unwrap();
    let ciphertext = plaintext.encrypt(&key, &salt).unwrap();
    assert_eq!(
        ciphertext.iter().map(hex::encode).collect::<Vec<_>>(),
        vector.output_ciphertext
    );

    let mut body = salt.to_vec();
    for element in &ciphertext {
        body.extend_from_slice(element);
    }
    assert_eq!(MergeOutputPlaintext::decrypt(&body, &key), Ok(plaintext));

    let mut other_first = first;
    other_first[31] = other_first[31].checked_add(1).unwrap();
    let other_key = merge_output_key(&nullifier_key, &other_first).unwrap();
    assert_ne!(other_key, key);
    assert_eq!(
        MergeOutputPlaintext::decrypt(&body, &other_key),
        Err(TransactionError::InvalidMergeOutputPlaintext { index: 0 })
    );

    let mut tampered = body.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert_ne!(
        MergeOutputPlaintext::decrypt(&tampered, &key),
        Ok(plaintext)
    );
}

#[test]
fn ring_merges_preserve_common_committed_data_and_exempt_only_padding() {
    let owner = keypair(7);
    let ring = Address::new_from_array([42; 32]);
    let notes = |hash: Option<[u8; 32]>| {
        inputs(&owner, 2)
            .into_iter()
            .map(|mut note| {
                note.utxo.ring_program_id = Some(ring);
                note.ring_data_hash = hash;
                note.utxo_hash = note
                    .utxo
                    .hash(
                        &note.nullifier_pubkey,
                        &[0; 32],
                        &hash.unwrap_or_default(),
                        note.tree_id,
                    )
                    .unwrap();
                note.nullifier = owner
                    .nullifier(&note.utxo_hash, &note.utxo.blinding)
                    .unwrap();
                note
            })
            .collect::<Vec<_>>()
    };
    for hash in [None, Some([0; 32]), Some([3; 32])] {
        let mut result = MergeTransaction::new_with_ring(notes(hash), ring, None)
            .unwrap()
            .encrypt(&owner)
            .unwrap();
        assert_eq!(
            result.output_utxo.ring_data_hash.unwrap_or_default(),
            hash.unwrap_or_default()
        );
        result.input_utxo_hashes().unwrap();
        result.input_utxos[2].ring_data_hash = Some([9; 32]);
        result.input_utxo_hashes().unwrap();
        let mut unequal = notes(hash);
        unequal[1].ring_data_hash = Some([7; 32]);
        assert_eq!(
            MergeTransaction::new_with_ring(unequal, ring, None).err(),
            Some(TransactionError::MergeInputRingDataMismatch { index: 1 })
        );
        result.input_utxos[1].ring_data_hash = Some([7; 32]);
        assert!(matches!(
            result.input_utxo_hashes(),
            Err(TransactionError::MergeInputRingDataMismatch { index: 1 })
        ));
        let mut changed_output = MergeTransaction::new_with_ring(notes(hash), ring, None)
            .unwrap()
            .encrypt(&owner)
            .unwrap();
        changed_output.output_utxo.ring_data_hash = Some([8; 32]);
        assert!(matches!(
            changed_output.input_utxo_hashes(),
            Err(TransactionError::MergeOutputRingDataMismatch)
        ));
    }
    // SOL's zero mint address remains a valid nonzero circuit asset identity.
    assert_ne!(
        zolana_transaction::instructions::transact::asset_field(&Mint::SOL.asset).unwrap(),
        [0; 32]
    );
}

#[test]
fn merge_decrypt_rejects_non_canonical_ciphertext_aliases() {
    use num_bigint::BigUint;
    use zolana_hasher::primitives::BN254_SCALAR_MODULUS_BE;
    let plaintext = MergeOutputPlaintext {
        amount: 123,
        mint: Mint::SOL.asset,
    };
    let key = [7; 32];
    let salt = [8; 16];
    let ciphertext = plaintext.encrypt(&key, &salt).unwrap();
    let body = |elements: &[[u8; 32]; 3]| {
        salt.iter()
            .chain(elements.iter().flatten())
            .copied()
            .collect::<Vec<_>>()
    };
    assert_eq!(
        MergeOutputPlaintext::decrypt(&body(&ciphertext), &key),
        Ok(plaintext)
    );
    for (index, element) in ciphertext.iter().enumerate() {
        let alias =
            BigUint::from_bytes_be(element) + BigUint::from_bytes_be(&BN254_SCALAR_MODULUS_BE);
        let alias: [u8; 32] = alias
            .to_bytes_be()
            .try_into()
            .expect("alias is a 32-byte scalar encoding");
        for replacement in [alias, BN254_SCALAR_MODULUS_BE] {
            let mut noncanonical = ciphertext;
            *noncanonical.get_mut(index).unwrap() = replacement;
            assert!(matches!(
                MergeOutputPlaintext::decrypt(&body(&noncanonical), &key),
                Err(TransactionError::NonCanonicalMergeCiphertext { index: got }) if got == index
            ));
        }
    }
}
