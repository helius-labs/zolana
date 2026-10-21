mod common;

use std::{
    cell::RefCell,
    collections::{BTreeSet, HashSet},
};

use common::{keypair, wallet_utxo};
use custom_ring_interface::stream::{DeliveredSlot, RingTag, SlotSecret};
use solana_signature::Signature;
use zolana_event::{
    encode_merge_output_data, encode_ring_confidential_delivered_output,
    EncryptedRingDepositOutput, MergeOutputDataRef, OutputDataEncoding,
};
use zolana_keypair::{ShieldedAddress, ShieldedKeypair, ViewingKey, X25519Pubkey};
use zolana_transaction::{
    decrypt, decrypt_spendable,
    instructions::merge::{
        merge_dummy_nullifier, merge_output_blinding, merge_output_key, MergeOutputPlaintext,
        MERGE_DEFAULT_INPUT_COUNT,
    },
    owner_utxo_hash,
    serialization::{
        anonymous::{AnonymousRecipient, AnonymousRecipientEncode},
        confidential::{Confidential, ConfidentialEncode},
        plaintext::{PlaintextTransfer, TransferPlaintextUtxos},
        proofless::{Proofless, ProoflessEncode},
        RingDeliverySlot,
    },
    verify_owned, verify_spendable, Address, AssetBalance, AssetRegistry, Balances, Data,
    DataRecord, DecryptLabel, DecryptRequest, DecryptionResult, DeriveRequest, EncryptedScheme,
    LocalShieldedKeys, Mint, OutputContext, OutputSlot, OwnerCx, RingDeliveredBody,
    RingDeliveredCandidate, RingDeliveredFind, RingDeliveryRequest, RingDepositPlaintext,
    ShieldedKeys, ShieldedTransaction, SpendableDecryptionResult, TransactionError,
    TransactionKeyRequest, Utxo, UtxoSerialization, WalletUtxo, TRANSFER_PLAINTEXT,
};

fn owner_cx<'a>(owner: &ShieldedKeypair, assets: &'a AssetRegistry) -> OwnerCx<'a> {
    OwnerCx {
        owner: owner.signing_pubkey(),
        assets,
        ring_program_id: None,
        first_nullifier: None,
    }
}

fn slot(note: &WalletUtxo, payload: Vec<u8>) -> OutputSlot {
    OutputSlot {
        view_tag: [0; 32],
        output_context: OutputContext {
            hash: note.utxo_hash,
            tree_id: note.tree_id,
            leaf_index: note.leaf_index,
        },
        payload,
    }
}

fn publication(note: &WalletUtxo, output_slots: Vec<OutputSlot>) -> ShieldedTransaction {
    ShieldedTransaction {
        slot: note.slot,
        tx_signature: note.tx_signature,
        event_index: None,
        tx_viewing_pk: None,
        salt: None,
        output_slots,
        messages: vec![],
        nullifiers: vec![],
        proofless: false,
        ring_config: None,
        ring_program_id: None,
    }
}

fn proofless_slot(note: &WalletUtxo, owner: &ShieldedKeypair) -> OutputSlot {
    let assets = AssetRegistry::default();
    let message = Proofless::encode(
        std::slice::from_ref(&note.utxo),
        &owner_cx(owner, &assets),
        [0; 32],
        &ProoflessEncode {
            owner_hash: owner.shielded_address().unwrap().owner_hash().unwrap(),
            data_hash: note.data_hash,
            ring_data_hash: note.ring_data_hash,
        },
    )
    .unwrap();
    slot(note, message.data)
}

fn confidential_slot(
    note: &WalletUtxo,
    recipient: X25519Pubkey,
    tx: &ViewingKey,
    physical_index: u32,
) -> OutputSlot {
    let assets = AssetRegistry::default();
    let message = Confidential::encode(
        std::slice::from_ref(&note.utxo),
        &OwnerCx {
            owner: note.utxo.owner,
            assets: &assets,
            ring_program_id: None,
            first_nullifier: None,
        },
        [0; 32],
        &ConfidentialEncode {
            tx: tx.clone(),
            recipient_pubkey: recipient,
            salt: [7; 16],
            slot_index: physical_index,
        },
    )
    .unwrap();
    slot(note, message.data)
}

fn balance(notes: Vec<WalletUtxo>, mint: Mint, amount: u64) -> AssetBalance {
    AssetBalance {
        asset_id: mint.asset_id,
        mint: mint.asset,
        amount,
        utxos: notes,
    }
}

fn refresh_commitment(owner: &ShieldedKeypair, note: &mut WalletUtxo) {
    note.utxo_hash = note
        .utxo
        .hash(
            &note.nullifier_pubkey,
            &note.data_hash.unwrap_or_default(),
            &note.ring_data_hash.unwrap_or_default(),
            note.tree_id,
        )
        .unwrap();
    note.nullifier = owner
        .nullifier(&note.utxo_hash, &note.utxo.blinding)
        .unwrap();
}

#[test]
fn sparse_encrypted_slots_preserve_metadata_and_separate_candidates_from_verified_notes() {
    let owner = keypair(11);
    let tx_key = keypair(12).viewing_key;
    let mut first = wallet_utxo(&owner, Mint::SOL, 31, 7, 1);
    first.slot_index = 1;
    let mut second = wallet_utxo(&owner, Mint::SOL, 47, 7, 2);
    second.slot_index = 3;
    second.slot = first.slot;
    second.tx_signature = first.tx_signature;
    let mut tx = publication(
        &first,
        vec![
            slot(&first, vec![]),
            confidential_slot(&first, owner.viewing_pubkey(), &tx_key, 1),
            slot(&first, vec![255]),
            confidential_slot(&second, owner.viewing_pubkey(), &tx_key, 3),
        ],
    );
    tx.tx_viewing_pk = Some(tx_key.pubkey());
    tx.salt = Some([7; 16]);
    let assets = AssetRegistry::default();
    let decoded = decrypt(&owner, &[tx.clone()], &assets).unwrap();
    assert_eq!(
        decoded,
        DecryptionResult {
            utxos: vec![first.clone(), second.clone()],
            spent_nullifiers: HashSet::new(),
            ..Default::default()
        }
    );
    let expected = SpendableDecryptionResult {
        balances: Balances {
            assets: vec![balance(vec![first.clone(), second.clone()], Mint::SOL, 78)],
        },
        utxos_with_data: vec![],
        ..Default::default()
    };
    assert_eq!(
        decrypt_spendable(&owner, &[tx.clone()], &assets).unwrap(),
        expected
    );
    assert_eq!(verify_spendable(&owner, &decoded).unwrap(), expected);

    // A decoded payload is merely a candidate when its published tree is false.
    tx.output_slots.get_mut(1).unwrap().output_context.tree_id += 1;
    let forged = decrypt(&owner, &[tx], &assets).unwrap();
    let first_candidate = forged.utxos.first().unwrap();
    assert_eq!(first_candidate.tree_id, 8);
    assert_eq!(first_candidate.utxo_hash, first.utxo_hash);
    assert_eq!(first_candidate.nullifier, first.nullifier);
    assert_eq!(
        verify_spendable(&owner, &forged).unwrap(),
        SpendableDecryptionResult {
            balances: Balances {
                assets: vec![balance(vec![second], Mint::SOL, 47)],
            },
            utxos_with_data: vec![],
            ..Default::default()
        }
    );
}

#[test]
fn batch_spends_apply_before_or_after_publication_and_cached_nullifiers_are_untrusted() {
    let owner = keypair(13);
    let note = wallet_utxo(&owner, Mint::SOL, 41, 2, 5);
    let publish = publication(&note, vec![proofless_slot(&note, &owner)]);
    let mut spend = publication(&note, vec![]);
    spend.nullifiers = vec![note.nullifier];
    let assets = AssetRegistry::default();
    for txs in [
        vec![publish.clone(), spend.clone()],
        vec![spend, publish.clone()],
    ] {
        let mut candidates = decrypt(&owner, &txs, &assets).unwrap();
        assert_eq!(candidates.spent_nullifiers, HashSet::from([note.nullifier]));
        candidates.utxos.first_mut().unwrap().nullifier = [99; 32];
        let before = candidates.clone();
        assert_eq!(
            verify_spendable(&owner, &candidates).unwrap(),
            SpendableDecryptionResult::default()
        );
        assert_eq!(candidates, before);
        assert_eq!(
            decrypt_spendable(&owner, &txs, &assets).unwrap(),
            SpendableDecryptionResult::default()
        );
    }
    // An isolated publication has no evidence of the spend outside this batch.
    assert_eq!(
        decrypt_spendable(&owner, &[publish], &assets)
            .unwrap()
            .balances
            .assets,
        vec![balance(vec![note], Mint::SOL, 41)]
    );
}

#[test]
fn owned_utxos_keep_the_spent_ones_and_derive_their_nullifiers_again() {
    let owner = keypair(53);
    let spent = wallet_utxo(&owner, Mint::SOL, 41, 2, 1);
    let unspent = wallet_utxo(&owner, Mint::SOL, 9, 2, 2);
    let mut cached = spent.clone();
    cached.nullifier = [99; 32];
    let mut forged = unspent.clone();
    forged.utxo.amount += 1;
    let decrypted = DecryptionResult {
        utxos: vec![cached, forged, unspent.clone(), unspent.clone()],
        spent_nullifiers: HashSet::from([spent.nullifier]),
        ..Default::default()
    };

    let owned = verify_owned(&owner, &decrypted).unwrap();
    assert_eq!(owned.utxos, vec![spent.clone(), unspent.clone()]);
    assert_eq!(owned.spent, HashSet::from([spent.nullifier]));
    let spendable = verify_spendable(&owner, &decrypted).unwrap();
    assert_eq!(owned.spendable(), spendable);
    assert_eq!(
        spendable.utxos().cloned().collect::<Vec<_>>(),
        vec![unspent]
    );
}

#[test]
fn verification_filters_each_untrusted_field_without_losing_the_valid_control() {
    let owner = keypair(14);
    let foreign = keypair(15);
    let control = wallet_utxo(&owner, Mint::SOL, 29, 4, 6);
    let mut invalid = Vec::new();
    let mut note = control.clone();
    note.utxo.owner = foreign.signing_pubkey();
    invalid.push(note);
    let mut note = control.clone();
    note.nullifier_pubkey = foreign.shielded_address().unwrap().nullifier_pubkey;
    invalid.push(note);
    let mut note = control.clone();
    note.utxo.data = Data::new(vec![DataRecord::UtxoData(vec![1])]);
    invalid.push(note);
    let mut note = control.clone();
    note.utxo.data = Data::new(vec![DataRecord::RingData(vec![1])]);
    note.utxo.ring_program_id = Some(Address::new_from_array([2; 32]));
    invalid.push(note);
    let mut note = control.clone();
    note.utxo.amount += 1;
    invalid.push(note);
    let mut note = control.clone();
    note.tree_id += 1;
    invalid.push(note);
    let mut note = control.clone();
    note.utxo_hash = [0; 32];
    invalid.push(note);
    let mut note = control.clone();
    note.utxo.blinding[31] += 1;
    invalid.push(note);
    for candidate in invalid {
        let decrypted = DecryptionResult {
            utxos: vec![candidate, control.clone()],
            spent_nullifiers: HashSet::new(),
            ..Default::default()
        };
        let before = decrypted.clone();
        assert_eq!(
            verify_spendable(&owner, &decrypted).unwrap(),
            SpendableDecryptionResult {
                balances: Balances {
                    assets: vec![balance(vec![control.clone()], Mint::SOL, 29)],
                },
                utxos_with_data: vec![],
                ..Default::default()
            }
        );
        assert_eq!(decrypted, before);
    }
    let mut malformed = control.clone();
    malformed.utxo.blinding = [255; 32];
    let expected_error = malformed
        .utxo
        .hash(
            &malformed.nullifier_pubkey,
            &[0; 32],
            &[0; 32],
            malformed.tree_id,
        )
        .unwrap_err();
    assert_eq!(
        verify_spendable(
            &owner,
            &DecryptionResult {
                utxos: vec![control, malformed],
                spent_nullifiers: HashSet::new(),
                ..Default::default()
            }
        ),
        Err(expected_error)
    );
}

#[test]
fn unique_notes_sort_by_metadata_and_separate_ring_and_data_from_balances() {
    let owner = keypair(16);
    let spl = Mint::new(Address::new_from_array([17; 32]), 9);
    let sol_a = wallet_utxo(&owner, Mint::SOL, 10, 3, 1);
    let mut sol_b = wallet_utxo(&owner, Mint::SOL, 20, 3, 2);
    sol_b.utxo.data = Data::new(vec![DataRecord::Memo(b"informational".to_vec())]);
    let spl_note = wallet_utxo(&owner, spl, 7, 3, 3);
    let mut sol_c = wallet_utxo(&owner, Mint::SOL, 30, 3, 4);
    sol_c.slot = sol_b.slot;
    sol_c.tx_signature = sol_b.tx_signature;
    sol_c.slot_index = 2;
    let mut sol_d = wallet_utxo(&owner, Mint::SOL, 40, 3, 5);
    sol_d.slot = sol_b.slot;
    sol_d.tx_signature = Signature::from([3; 64]);
    let mut ring = wallet_utxo(&owner, Mint::SOL, 50, 3, 6);
    ring.utxo.ring_program_id = Some(Address::new_from_array([8; 32]));
    refresh_commitment(&owner, &mut ring);
    let mut hash_only = wallet_utxo(&owner, Mint::SOL, 60, 3, 7);
    hash_only.data_hash = Some([1; 32]);
    refresh_commitment(&owner, &mut hash_only);
    let mut ring_hash_only = wallet_utxo(&owner, Mint::SOL, 70, 3, 8);
    ring_hash_only.ring_data_hash = Some([2; 32]);
    refresh_commitment(&owner, &mut ring_hash_only);
    let mut preimages = wallet_utxo(&owner, Mint::SOL, 80, 3, 9);
    preimages.utxo.ring_program_id = Some(Address::new_from_array([8; 32]));
    preimages.utxo.data = Data::new(vec![
        DataRecord::RingData(vec![1]),
        DataRecord::UtxoData(vec![2]),
    ]);
    preimages.data_hash = Some([1; 32]);
    preimages.ring_data_hash = Some([2; 32]);
    refresh_commitment(&owner, &mut preimages);
    let mut earlier_duplicate = sol_a.clone();
    earlier_duplicate.slot = 0;
    let mut duplicate_data = hash_only.clone();
    duplicate_data.slot = 0;
    let candidates = DecryptionResult {
        utxos: vec![
            sol_d.clone(),
            preimages.clone(),
            sol_c.clone(),
            hash_only.clone(),
            sol_b.clone(),
            sol_a.clone(),
            spl_note.clone(),
            ring_hash_only.clone(),
            ring.clone(),
            earlier_duplicate,
            duplicate_data,
        ],
        spent_nullifiers: HashSet::new(),
        ..Default::default()
    };
    let before = candidates.clone();
    assert_eq!(
        verify_spendable(&owner, &candidates).unwrap(),
        SpendableDecryptionResult {
            balances: Balances {
                assets: vec![
                    balance(vec![sol_a, sol_b, sol_c, sol_d], Mint::SOL, 100),
                    balance(vec![spl_note], spl, 7)
                ]
            },
            utxos_with_data: vec![ring, hash_only, ring_hash_only, preimages],
            ..Default::default()
        }
    );
    assert_eq!(candidates, before);
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RecordedDecrypt {
    ciphertext: Vec<u8>,
    viewing_pubkey: X25519Pubkey,
    tx_viewing_pubkey: X25519Pubkey,
    salt: [u8; 16],
    slot_index: u32,
    label: DecryptLabel,
}

struct RecordingKeys {
    local: LocalShieldedKeys,
    plaintexts: Option<Vec<Vec<u8>>>,
    derivations: Option<Vec<[u8; 32]>>,
    fail: Option<&'static str>,
    decrypt_calls: RefCell<Vec<Vec<RecordedDecrypt>>>,
    derive_calls: RefCell<Vec<Vec<DeriveRequest>>>,
}

impl RecordingKeys {
    fn new(owner: &ShieldedKeypair) -> Self {
        Self {
            local: LocalShieldedKeys::from_keypair(owner).unwrap(),
            plaintexts: None,
            derivations: None,
            fail: None,
            decrypt_calls: RefCell::new(vec![]),
            derive_calls: RefCell::new(vec![]),
        }
    }
    fn error(&self, stage: &str) -> Result<(), TransactionError> {
        if self.fail == Some(stage) {
            Err(TransactionError::Authority(stage.into()))
        } else {
            Ok(())
        }
    }
}

impl ShieldedKeys for RecordingKeys {
    fn address(&self) -> Result<ShieldedAddress, TransactionError> {
        self.error("address")?;
        self.local.address()
    }
    fn viewing_public_keys(&self) -> Vec<X25519Pubkey> {
        self.local.viewing_public_keys()
    }
    fn decrypt(&self, requests: &[DecryptRequest<'_>]) -> Result<Vec<Vec<u8>>, TransactionError> {
        self.decrypt_calls.borrow_mut().push(
            requests
                .iter()
                .map(|r| RecordedDecrypt {
                    ciphertext: r.ciphertext.to_vec(),
                    viewing_pubkey: r.viewing_pubkey,
                    tx_viewing_pubkey: r.tx_viewing_pubkey,
                    salt: r.salt,
                    slot_index: r.slot_index,
                    label: r.label,
                })
                .collect(),
        );
        self.error("decrypt")?;
        match &self.plaintexts {
            Some(values) => Ok(values.clone()),
            None => self.local.decrypt(requests),
        }
    }
    fn derive(&self, requests: &[DeriveRequest]) -> Result<Vec<[u8; 32]>, TransactionError> {
        self.derive_calls.borrow_mut().push(requests.to_vec());
        self.error("derive")?;
        match &self.derivations {
            Some(values) => Ok(values.clone()),
            None => self.local.derive(requests),
        }
    }
    fn transaction_keys(
        &self,
        requests: &[TransactionKeyRequest],
    ) -> Result<Vec<ViewingKey>, TransactionError> {
        self.local.transaction_keys(requests)
    }
    fn ring_address_keys(
        &self,
        ring: &Address,
        indexes: &[u32],
    ) -> Result<Vec<X25519Pubkey>, TransactionError> {
        self.local.ring_address_keys(ring, indexes)
    }
    fn ring_delivery_secrets(
        &self,
        requests: &[RingDeliveryRequest],
    ) -> Result<Vec<[u8; 32]>, TransactionError> {
        self.local.ring_delivery_secrets(requests)
    }
    fn ring_change_key(&self, ring: &Address) -> Result<X25519Pubkey, TransactionError> {
        self.local.ring_change_key(ring)
    }
    fn sender_view_tags(&self, counters: &[u64]) -> Result<Vec<[u8; 32]>, TransactionError> {
        self.local.sender_view_tags(counters)
    }
}

#[test]
fn response_cardinality_and_empty_batches_are_checked_at_each_scan_stage() {
    let owner = keypair(18);
    let note = wallet_utxo(&owner, Mint::SOL, 12, 1, 1);
    let tx_key = keypair(19).viewing_key;
    let mut encrypted = publication(
        &note,
        vec![confidential_slot(&note, owner.viewing_pubkey(), &tx_key, 0)],
    );
    encrypted.tx_viewing_pk = Some(tx_key.pubkey());
    encrypted.salt = Some([7; 16]);
    let assets = AssetRegistry::default();
    for got in [0, 2] {
        let mut keys = RecordingKeys::new(&owner);
        keys.plaintexts = Some(vec![vec![]; got]);
        assert_eq!(
            decrypt(&keys, &[encrypted.clone()], &assets),
            Err(TransactionError::IncompleteDecryption { got, want: 1 })
        );
        assert!(keys.derive_calls.borrow().is_empty());
        let mut keys = RecordingKeys::new(&owner);
        keys.derivations = Some(vec![[0; 32]; got]);
        assert_eq!(
            decrypt(&keys, &[encrypted.clone()], &assets),
            Err(TransactionError::IncompleteDerivation { got, want: 1 })
        );
        let candidates = DecryptionResult {
            utxos: vec![note.clone()],
            spent_nullifiers: HashSet::new(),
            ..Default::default()
        };
        assert_eq!(
            verify_spendable(&keys, &candidates),
            Err(TransactionError::IncompleteDerivation { got, want: 1 })
        );
    }
    let keys = RecordingKeys::new(&owner);
    assert_eq!(
        decrypt_spendable(&keys, &[], &assets).unwrap(),
        SpendableDecryptionResult::default()
    );
    let mut foreign = note.clone();
    foreign.utxo.owner = keypair(20).signing_pubkey();
    assert_eq!(
        verify_spendable(
            &keys,
            &DecryptionResult {
                utxos: vec![foreign],
                spent_nullifiers: HashSet::new(),
                ..Default::default()
            }
        )
        .unwrap(),
        SpendableDecryptionResult::default()
    );
    assert!(keys.decrypt_calls.borrow().is_empty());
    assert!(keys.derive_calls.borrow().is_empty());
}

#[test]
fn nullifier_requests_preserve_candidate_order_before_metadata_sorting() {
    let owner = keypair(21);
    let mut earlier = wallet_utxo(&owner, Mint::SOL, 11, 2, 1);
    let mut later = wallet_utxo(&owner, Mint::SOL, 13, 2, 9);
    let mut keys = RecordingKeys::new(&owner);
    keys.derivations = Some(vec![[3; 32], [4; 32]]);
    let txs = vec![
        publication(&later, vec![proofless_slot(&later, &owner)]),
        publication(&earlier, vec![proofless_slot(&earlier, &owner)]),
    ];
    let decoded = decrypt(&keys, &txs, &AssetRegistry::default()).unwrap();
    let requests = vec![
        DeriveRequest::Nullifier {
            utxo_hash: later.utxo_hash,
            blinding: later.utxo.blinding,
        },
        DeriveRequest::Nullifier {
            utxo_hash: earlier.utxo_hash,
            blinding: earlier.utxo.blinding,
        },
    ];
    later.nullifier = [3; 32];
    earlier.nullifier = [4; 32];
    assert_eq!(decoded.utxos, vec![earlier.clone(), later.clone()]);
    assert_eq!(*keys.derive_calls.borrow(), vec![requests]);
    keys.derive_calls.borrow_mut().clear();
    let candidates = DecryptionResult {
        utxos: vec![later.clone(), earlier.clone(), later.clone()],
        spent_nullifiers: HashSet::from([[3; 32]]),
        ..Default::default()
    };
    assert_eq!(
        verify_spendable(&keys, &candidates)
            .unwrap()
            .balances
            .assets,
        vec![balance(vec![earlier], Mint::SOL, 11)]
    );
    assert_eq!(
        *keys.derive_calls.borrow(),
        vec![vec![
            DeriveRequest::Nullifier {
                utxo_hash: later.utxo_hash,
                blinding: later.utxo.blinding
            },
            DeriveRequest::Nullifier {
                utxo_hash: decoded.utxos.first().unwrap().utxo_hash,
                blinding: decoded.utxos.first().unwrap().utxo.blinding
            }
        ]]
    );
}

#[test]
fn retired_viewing_keys_recover_anonymous_and_confidential_slots_with_exact_requests() {
    let owner = keypair(22);
    let retired = keypair(23).viewing_key;
    let tx_key = keypair(24).viewing_key;
    let mut keys = RecordingKeys::new(&owner);
    keys.local = LocalShieldedKeys::new(
        owner.shielded_address().unwrap(),
        vec![owner.viewing_key.clone(), retired.clone()],
        owner.nullifier_key.clone(),
    )
    .unwrap();
    let mut anonymous = wallet_utxo(&owner, Mint::SOL, 17, 6, 1);
    anonymous.slot_index = 1;
    let mut confidential = wallet_utxo(&owner, Mint::SOL, 23, 6, 2);
    confidential.slot_index = 2;
    confidential.slot = anonymous.slot;
    confidential.tx_signature = anonymous.tx_signature;
    let assets = AssetRegistry::default();
    let message = AnonymousRecipient::encode(
        &[anonymous.utxo.clone()],
        &owner_cx(&owner, &assets),
        [0; 32],
        &AnonymousRecipientEncode {
            tx: tx_key.clone(),
            recipient_pubkey: retired.pubkey(),
            sender_pubkey: tx_key.pubkey(),
            salt: [7; 16],
            slot_index: 1,
        },
    )
    .unwrap();
    let OutputDataEncoding::Encrypted(anonymous_blob) =
        borsh::from_slice::<OutputDataEncoding>(&message.data).unwrap()
    else {
        panic!("encrypted envelope")
    };
    let confidential_slot = confidential_slot(&confidential, retired.pubkey(), &tx_key, 2);
    let OutputDataEncoding::Encrypted(confidential_blob) = confidential_slot.output_data().unwrap()
    else {
        panic!("encrypted envelope")
    };
    let mut tx = publication(
        &anonymous,
        vec![
            slot(&anonymous, vec![]),
            slot(&anonymous, message.data),
            confidential_slot,
        ],
    );
    tx.tx_viewing_pk = Some(tx_key.pubkey());
    tx.salt = Some([7; 16]);
    assert_eq!(
        decrypt(&keys, &[tx], &assets).unwrap().utxos,
        vec![anonymous, confidential]
    );
    let request = |viewing_pubkey, ciphertext: &[u8], slot_index| RecordedDecrypt {
        ciphertext: ciphertext.to_vec(),
        viewing_pubkey,
        tx_viewing_pubkey: tx_key.pubkey(),
        salt: [7; 16],
        slot_index,
        label: DecryptLabel::Utxo,
    };
    assert_eq!(
        *keys.decrypt_calls.borrow(),
        vec![
            vec![
                request(owner.viewing_pubkey(), anonymous_blob.get(1..).unwrap(), 1),
                request(retired.pubkey(), anonymous_blob.get(1..).unwrap(), 1)
            ],
            vec![request(
                retired.pubkey(),
                confidential_blob
                    .get(1 + zolana_keypair::x25519::X25519_PUBKEY_LEN..)
                    .unwrap(),
                2
            )]
        ]
    );
}

#[test]
fn anonymous_scanning_skips_noise_and_foreign_owners_then_accepts_first_eligible_plaintext() {
    let owner = keypair(25);
    let other = keypair(26);
    let mut keys = RecordingKeys::new(&owner);
    keys.local = LocalShieldedKeys::new(
        owner.shielded_address().unwrap(),
        vec![
            owner.viewing_key.clone(),
            other.viewing_key.clone(),
            keypair(27).viewing_key,
        ],
        owner.nullifier_key.clone(),
    )
    .unwrap();
    let note = wallet_utxo(&owner, Mint::SOL, 19, 0, 1);
    let assets = AssetRegistry::default();
    let cx = AnonymousRecipientEncode {
        tx: other.viewing_key.clone(),
        recipient_pubkey: owner.viewing_pubkey(),
        sender_pubkey: other.viewing_pubkey(),
        salt: [7; 16],
        slot_index: 0,
    };
    let own = AnonymousRecipient::from_utxos(
        std::slice::from_ref(&note.utxo),
        &owner_cx(&owner, &assets),
        &cx,
    )
    .unwrap();
    let mut foreign = own.clone();
    foreign.owner_pubkey = other.signing_pubkey();
    let mut later_eligible = own.clone();
    later_eligible.amount = 999;
    let output = slot(
        &note,
        borsh::to_vec(&OutputDataEncoding::Encrypted(vec![1, 42])).unwrap(),
    );
    let mut tx = publication(&note, vec![output]);
    tx.tx_viewing_pk = Some(other.viewing_pubkey());
    tx.salt = Some([7; 16]);
    for answers in [
        vec![
            vec![255],
            foreign.serialize().unwrap(),
            own.serialize().unwrap(),
        ],
        vec![
            own.serialize().unwrap(),
            later_eligible.serialize().unwrap(),
            vec![],
        ],
    ] {
        keys.plaintexts = Some(answers);
        assert_eq!(
            decrypt(&keys, &[tx.clone()], &assets).unwrap().utxos,
            vec![note.clone()]
        );
    }
}

#[test]
fn malformed_unsupported_foreign_and_contextless_slots_do_not_hide_valid_notes() {
    let owner = keypair(28);
    let foreign = keypair(29);
    let note = wallet_utxo(&owner, Mint::SOL, 37, 5, 1);
    let foreign_note = wallet_utxo(&foreign, Mint::SOL, 1000, 5, 2);
    let mut invalid = vec![
        slot(&note, vec![]),
        slot(&note, vec![255]),
        proofless_slot(&foreign_note, &foreign),
    ];
    for encoding in [
        OutputDataEncoding::Plaintext(vec![]),
        OutputDataEncoding::Plaintext(vec![255]),
        OutputDataEncoding::Plaintext(vec![0, 255]),
        OutputDataEncoding::Encrypted(vec![]),
        OutputDataEncoding::Encrypted(vec![255]),
        OutputDataEncoding::Encrypted(vec![3]),
        OutputDataEncoding::Encrypted(vec![2]),
        OutputDataEncoding::Encrypted(vec![8]),
        OutputDataEncoding::VerifiablyEncrypted(vec![6]),
    ] {
        invalid.push(slot(&note, borsh::to_vec(&encoding).unwrap()));
    }
    let tx_key = foreign.viewing_key.clone();
    invalid.push(confidential_slot(
        &note,
        foreign.viewing_pubkey(),
        &tx_key,
        0,
    ));
    let valid = publication(&note, vec![proofless_slot(&note, &owner)]);
    let mut malformed = publication(&note, invalid);
    malformed.tx_viewing_pk = Some(tx_key.pubkey());
    malformed.salt = Some([7; 16]);
    let mut missing_key = publication(
        &note,
        vec![confidential_slot(&note, owner.viewing_pubkey(), &tx_key, 0)],
    );
    missing_key.salt = Some([7; 16]);
    let mut missing_salt = missing_key.clone();
    missing_salt.tx_viewing_pk = Some(tx_key.pubkey());
    missing_salt.salt = None;
    let txs = vec![malformed, valid, missing_key, missing_salt];
    assert_eq!(
        decrypt(&owner, &txs, &AssetRegistry::default())
            .unwrap()
            .utxos,
        vec![note.clone()]
    );
    assert_eq!(
        decrypt_spendable(&owner, &txs, &AssetRegistry::default())
            .unwrap()
            .balances
            .assets,
        vec![balance(vec![note], Mint::SOL, 37)]
    );
}

#[test]
fn key_holder_failures_propagate_and_verification_preserves_candidates() {
    let owner = keypair(30);
    let note = wallet_utxo(&owner, Mint::SOL, 43, 1, 1);
    let tx_key = keypair(31).viewing_key;
    let mut tx = publication(
        &note,
        vec![confidential_slot(&note, owner.viewing_pubkey(), &tx_key, 0)],
    );
    tx.tx_viewing_pk = Some(tx_key.pubkey());
    tx.salt = Some([7; 16]);
    let assets = AssetRegistry::default();
    for stage in ["address", "decrypt", "derive"] {
        let mut keys = RecordingKeys::new(&owner);
        keys.fail = Some(stage);
        let error = TransactionError::Authority(stage.into());
        assert_eq!(decrypt(&keys, &[tx.clone()], &assets), Err(error.clone()));
        assert_eq!(decrypt_spendable(&keys, &[tx.clone()], &assets), Err(error));
    }
    for stage in ["address", "derive"] {
        let mut keys = RecordingKeys::new(&owner);
        keys.fail = Some(stage);
        let mut untrusted = note.clone();
        untrusted.nullifier = [255; 32];
        let candidates = DecryptionResult {
            utxos: vec![untrusted],
            spent_nullifiers: HashSet::from([[1; 32]]),
            ..Default::default()
        };
        let before = candidates.clone();
        assert_eq!(
            verify_spendable(&keys, &candidates),
            Err(TransactionError::Authority(stage.into()))
        );
        assert_eq!(candidates, before);
    }
}

#[test]
fn plaintexts_that_rebuild_no_note_skip_their_slot() {
    let owner = keypair(32);
    let note = wallet_utxo(&owner, Mint::SOL, 53, 1, 1);
    let tx_key = keypair(33).viewing_key;
    let mut cases = Vec::new();
    let mut ring = note.clone();
    ring.utxo.data = Data::new(vec![DataRecord::RingData(vec![1])]);
    cases.push(confidential_slot(&ring, owner.viewing_pubkey(), &tx_key, 0));
    let plaintext = TransferPlaintextUtxos {
        type_prefix: TRANSFER_PLAINTEXT,
        blinding_seed: [0; 32],
        sender: None,
        recipient_slots: vec![],
    };
    let mut blob = vec![EncryptedScheme::PlaintextTransfer.as_byte()];
    blob.extend(PlaintextTransfer::serialize(&plaintext).unwrap());
    cases.push(slot(
        &note,
        borsh::to_vec(&OutputDataEncoding::Plaintext(blob)).unwrap(),
    ));
    for output in cases {
        let mut tx = publication(&note, vec![output]);
        tx.tx_viewing_pk = Some(tx_key.pubkey());
        tx.salt = Some([7; 16]);
        let control = publication(&note, vec![proofless_slot(&note, &owner)]);
        let txs = vec![control, tx];
        let spendable = decrypt_spendable(&owner, &txs, &AssetRegistry::default()).unwrap();
        let found: Vec<_> = spendable.utxos().map(|found| &found.utxo).collect();
        assert_eq!(found, [&note.utxo]);
    }
}

#[test]
fn shuffled_multi_asset_publications_recover_unique_balances_and_data_notes() {
    let owner = keypair(35);
    let spl = Mint::new(Address::new_from_array([36; 32]), 9);
    let assets = AssetRegistry::new([(9, spl.asset)]).unwrap();
    let sol = wallet_utxo(&owner, Mint::SOL, 13, 2, 1);
    let token = wallet_utxo(&owner, spl, 17, 2, 2);
    let mut data = wallet_utxo(&owner, Mint::SOL, 19, 2, 3);
    data.utxo.data = Data::new(vec![
        DataRecord::UtxoData(vec![1, 2]),
        DataRecord::Memo(vec![3]),
    ]);
    data.data_hash = Some([1; 32]);
    refresh_commitment(&owner, &mut data);
    let mut ring = wallet_utxo(&owner, Mint::SOL, 23, 2, 4);
    ring.utxo.ring_program_id = Some(Address::new_from_array([37; 32]));
    refresh_commitment(&owner, &mut ring);
    let mut publications: Vec<_> = [&token, &data, &sol, &data, &sol]
        .into_iter()
        .map(|note| publication(note, vec![proofless_slot(note, &owner)]))
        .collect();
    let tx_key = keypair(38).viewing_key;
    let output = confidential_slot(&ring, owner.viewing_pubkey(), &tx_key, 0);
    let OutputDataEncoding::Encrypted(mut blob) = output.output_data().unwrap() else {
        panic!("encrypted envelope")
    };
    *blob.first_mut().unwrap() = 4; // RingConfidential uses the confidential payload codec.
    let mut ring_tx = publication(
        &ring,
        vec![slot(
            &ring,
            borsh::to_vec(&OutputDataEncoding::Encrypted(blob)).unwrap(),
        )],
    );
    ring_tx.tx_viewing_pk = Some(tx_key.pubkey());
    ring_tx.salt = Some([7; 16]);
    publications.push(ring_tx);
    let expected = SpendableDecryptionResult {
        balances: Balances {
            assets: vec![
                balance(vec![sol], Mint::SOL, 13),
                balance(vec![token], spl, 17),
            ],
        },
        utxos_with_data: vec![data, ring],
        ..Default::default()
    };
    for _ in 0..publications.len() {
        let decoded = decrypt(&owner, &publications, &assets).unwrap();
        assert_eq!(decoded.utxos.len(), 6);
        assert_eq!(verify_spendable(&owner, &decoded).unwrap(), expected);
        assert_eq!(
            decrypt_spendable(&owner, &publications, &assets).unwrap(),
            expected
        );
        publications.rotate_left(1);
    }
}

const RING: Address = Address::new_from_array([94; 32]);
const UNREGISTERED_MINT: Address = Address::new_from_array([0xaa; 32]);
const DELIVERY_SALT: [u8; 16] = [7; 16];

/// A ring note delivered as the ring rails derive its blinding and body from the slot secret.
struct Delivery<'a> {
    owner: &'a ShieldedKeypair,
    mint: Mint,
    recipient: X25519Pubkey,
    tx: &'a ViewingKey,
    first_nullifier: [u8; 32],
    slot_index: u32,
    tag: Option<RingTag>,
    nonce: u8,
}

impl Delivery<'_> {
    fn secret(&self) -> SlotSecret {
        DeliveredSlot {
            agreement: &self.tx.ecdh(&self.recipient).unwrap(),
            tx_viewing_pk: self.tx.pubkey().as_bytes(),
            recipient_viewing_pk: self.recipient.as_bytes(),
            salt: &DELIVERY_SALT,
            output_index: self.slot_index,
            first_nullifier: &self.first_nullifier,
        }
        .secret()
        .unwrap()
    }

    fn build(&self) -> (WalletUtxo, OutputSlot) {
        let secret = self.secret();
        let mut note = wallet_utxo(self.owner, self.mint, 17, 2, self.nonce);
        note.utxo.ring_program_id = Some(RING);
        note.slot_index = self.slot_index;
        note.utxo.blinding = RingDeliverySlot {
            ring: RING,
            first_nullifier: self.first_nullifier,
            output_index: self.slot_index,
            tag: self.tag,
        }
        .blinding(&secret)
        .unwrap();
        refresh_commitment(self.owner, &mut note);
        let body = RingDeliveredBody {
            asset_address: self.mint.asset,
            amount: note.utxo.amount,
        }
        .seal(&secret)
        .unwrap();
        let (view_tag, payload) = match self.tag {
            Some(tag) => (
                tag.field(),
                borsh::to_vec(&OutputDataEncoding::Encrypted(
                    [&[EncryptedScheme::RingAnonymous.as_byte()][..], &body].concat(),
                ))
                .unwrap(),
            ),
            None => (
                self.recipient.u(),
                encode_ring_confidential_delivered_output(&body),
            ),
        };
        let mut slot = slot(&note, payload);
        slot.view_tag = view_tag;
        (note, slot)
    }
}

fn delivered<'a>(
    owner: &'a ShieldedKeypair,
    tx: &'a ViewingKey,
    mint: Mint,
    nonce: u8,
) -> Delivery<'a> {
    Delivery {
        owner,
        mint,
        recipient: owner.viewing_pubkey(),
        tx,
        first_nullifier: [0x1f; 32],
        slot_index: 0,
        tag: None,
        nonce,
    }
}

fn ring_tx(note: &WalletUtxo, tx: &ViewingKey, slots: Vec<OutputSlot>) -> ShieldedTransaction {
    let mut publication = publication(note, slots);
    publication.tx_viewing_pk = Some(tx.pubkey());
    publication.salt = Some(DELIVERY_SALT);
    publication.ring_program_id = Some(RING);
    publication.nullifiers = vec![[0x1f; 32]];
    publication
}

#[test]
fn a_confidential_delivered_output_opens_under_the_wallet_key_its_owner_tag_names() {
    let owner = keypair(91);
    let tx_key = keypair(93).viewing_key;
    let (note, slot) = delivered(&owner, &tx_key, Mint::SOL, 1).build();
    let tx = ring_tx(&note, &tx_key, vec![slot]);
    let decoded = decrypt(&owner, &[tx], &AssetRegistry::default()).unwrap();
    assert_eq!(decoded.utxos.len(), 1);
    assert_eq!(decoded.utxos[0].utxo_hash, note.utxo_hash);
    assert_eq!(decoded.utxos[0].utxo.blinding, note.utxo.blinding);
    assert_eq!(decoded.utxos[0].nullifier, note.nullifier);
}

/// The owner tag names the recipient key, a body sealed to another key under it rebuilds nothing.
#[test]
fn a_delivered_body_sealed_to_another_key_under_the_wallet_tag_is_skipped() {
    let owner = keypair(94);
    let other = keypair(95);
    let tx_key = keypair(96).viewing_key;
    let (note, mut slot) = Delivery {
        recipient: other.viewing_pubkey(),
        ..delivered(&owner, &tx_key, Mint::SOL, 2)
    }
    .build();
    slot.view_tag = owner.viewing_pubkey().u();
    let tx = ring_tx(&note, &tx_key, vec![slot]);
    assert!(decrypt(&owner, &[tx], &AssetRegistry::default())
        .unwrap()
        .utxos
        .is_empty());
}

/// A sender picks the transaction key, a low-order one must not hide another sender's output.
#[test]
fn a_low_order_transaction_key_hides_no_other_delivered_output() {
    let owner = keypair(97);
    let tx_key = keypair(98).viewing_key;
    let (note, slot) = delivered(&owner, &tx_key, Mint::SOL, 3).build();
    let mut poisoned = ring_tx(&note, &tx_key, vec![slot.clone()]);
    poisoned.tx_viewing_pk = Some(X25519Pubkey::from_u([0; 32]).unwrap());
    let honest = ring_tx(&note, &tx_key, vec![slot]);
    let decoded = decrypt(&owner, &[poisoned, honest], &AssetRegistry::default()).unwrap();
    assert_eq!(decoded.utxos.len(), 1);
}

/// Only an indexer serves a first nullifier at or above the field modulus.
#[test]
fn a_first_nullifier_off_the_field_hides_no_other_delivered_output() {
    let owner = keypair(97);
    let tx_key = keypair(98).viewing_key;
    let (note, slot) = delivered(&owner, &tx_key, Mint::SOL, 3).build();
    let mut poisoned = ring_tx(&note, &tx_key, vec![slot.clone()]);
    poisoned.nullifiers[0] = [0xff; 32];
    let honest = ring_tx(&note, &tx_key, vec![slot]);
    let decoded = decrypt(&owner, &[poisoned, honest], &AssetRegistry::default()).unwrap();
    assert_eq!(decoded.utxos.len(), 1);
}

#[test]
fn an_anonymous_output_opens_only_under_the_tag_its_blinding_binds() {
    let owner = keypair(99);
    let tx_key = keypair(100).viewing_key;
    let tag = RingTag::from_bytes([0x51; 31]);
    let delivery = Delivery {
        tag: Some(tag),
        ..delivered(&owner, &tx_key, Mint::SOL, 4)
    };
    let (note, slot) = delivery.build();
    let tx = ring_tx(&note, &tx_key, vec![slot]);
    let candidate = |tag| RingDeliveredCandidate {
        tx: &tx,
        slot_index: 0,
        tag: Some(tag),
        slot_secret: delivery.secret(),
    };
    let mut decrypted = DecryptionResult::default();
    let other = RingTag::from_bytes([0x52; 31]);
    let finds = decrypted
        .extend_ring_delivered(
            &owner,
            &AssetRegistry::default(),
            std::slice::from_ref(&tx),
            &[candidate(other), candidate(tag)],
        )
        .unwrap();
    assert_eq!(
        finds,
        [RingDeliveredFind {
            candidate: 1,
            utxo_hash: note.utxo_hash,
            asset_address: Mint::SOL.asset,
            amount: 17,
            pending: false,
        }]
    );
    assert_eq!(decrypted.utxos.len(), 1);
}

#[test]
fn an_unknown_asset_keeps_the_verified_note_pending_until_registered() {
    let owner = keypair(101);
    let tx_key = keypair(102).viewing_key;
    let (note, slot) = delivered(&owner, &tx_key, Mint::new(UNREGISTERED_MINT, 0), 6).build();
    let tx = ring_tx(&note, &tx_key, vec![slot]);
    let mut decrypted = DecryptionResult::default();
    decrypted
        .extend(&owner, &[tx], &AssetRegistry::default())
        .unwrap();
    assert!(decrypted.utxos.is_empty());
    assert_eq!(decrypted.unknown_mints, BTreeSet::from([UNREGISTERED_MINT]));
    assert_eq!(decrypted.pending_assets.len(), 1);
    let pending = &decrypted.pending_assets[0];
    assert_eq!(pending.asset_address, UNREGISTERED_MINT);
    assert_eq!(pending.utxo_hash, note.utxo_hash);
    assert_eq!(pending.blinding, note.utxo.blinding);

    assert!(decrypted
        .resolve_pending(&owner, &AssetRegistry::default())
        .unwrap()
        .is_empty());
    let registered = AssetRegistry::new([(7, UNREGISTERED_MINT)]).unwrap();
    let resolved = decrypted.resolve_pending(&owner, &registered).unwrap();
    assert_eq!(resolved.len(), 1);
    assert!(!resolved[0].spent);
    assert_eq!(resolved[0].utxo.utxo.asset, Mint::new(UNREGISTERED_MINT, 7));
    assert_eq!(resolved[0].utxo.nullifier, note.nullifier);
    assert_eq!(
        verify_spendable(&owner, &decrypted)
            .unwrap()
            .utxos()
            .count(),
        1
    );
}

#[test]
fn a_failed_resolution_keeps_every_pending_note_and_a_success_removes_only_the_resolved() {
    let owner = keypair(107);
    let tx_key = keypair(108).viewing_key;
    let (note, slot) = delivered(&owner, &tx_key, Mint::new(UNREGISTERED_MINT, 0), 11).build();
    let tx = ring_tx(&note, &tx_key, vec![slot]);
    let mut decrypted = DecryptionResult::default();
    decrypted
        .extend(&owner, &[tx], &AssetRegistry::default())
        .unwrap();
    let mut unresolved = decrypted.pending_assets[0].clone();
    unresolved.asset_address = Address::new_from_array([0xbb; 32]);
    decrypted.pending_assets.push(unresolved.clone());
    let pending = decrypted.pending_assets.clone();
    let registered = AssetRegistry::new([(7, UNREGISTERED_MINT)]).unwrap();

    let mut failing = RecordingKeys::new(&owner);
    failing.fail = Some("derive");
    assert_eq!(
        decrypted.resolve_pending(&failing, &registered),
        Err(TransactionError::Authority("derive".into()))
    );
    assert_eq!(decrypted.pending_assets, pending);
    let resolved = decrypted.resolve_pending(&owner, &registered).unwrap();
    assert_eq!(resolved.len(), 1);
    assert_eq!(resolved[0].utxo.utxo_hash, note.utxo_hash);
    assert_eq!(decrypted.pending_assets, [unresolved]);
}

#[test]
fn a_pending_note_resolved_after_its_spend_is_reported_spent() {
    let owner = keypair(105);
    let tx_key = keypair(106).viewing_key;
    let (note, slot) = delivered(&owner, &tx_key, Mint::new(UNREGISTERED_MINT, 0), 10).build();
    let tx = ring_tx(&note, &tx_key, vec![slot]);
    let mut spend = publication(&note, vec![]);
    spend.nullifiers = vec![note.nullifier];
    let mut decrypted = DecryptionResult::default();
    decrypted
        .extend(&owner, &[tx, spend], &AssetRegistry::default())
        .unwrap();
    let registered = AssetRegistry::new([(7, UNREGISTERED_MINT)]).unwrap();
    let resolved = decrypted.resolve_pending(&owner, &registered).unwrap();
    assert_eq!(resolved.len(), 1);
    assert!(resolved[0].spent);
    assert_eq!(
        verify_owned(&owner, &decrypted).unwrap().spent,
        HashSet::from([note.nullifier])
    );
}

#[test]
fn altered_encryption_context_and_ciphertext_cannot_create_spendable_notes() {
    let owner = keypair(39);
    let tx_key = keypair(40).viewing_key;
    let assets = AssetRegistry::default();
    let control = wallet_utxo(&owner, Mint::SOL, 31, 7, 1);
    let note = wallet_utxo(&owner, Mint::SOL, 67, 7, 2);
    let control_tx = publication(&control, vec![proofless_slot(&control, &owner)]);
    let mut original = publication(
        &note,
        vec![confidential_slot(&note, owner.viewing_pubkey(), &tx_key, 0)],
    );
    original.tx_viewing_pk = Some(tx_key.pubkey());
    original.salt = Some([7; 16]);
    // Establish both independently valued outputs before changing one parameter per case.
    assert_eq!(
        decrypt_spendable(&owner, &[control_tx.clone(), original.clone()], &assets).unwrap(),
        SpendableDecryptionResult {
            balances: Balances {
                assets: vec![balance(vec![control.clone(), note.clone()], Mint::SOL, 98)],
            },
            utxos_with_data: vec![],
            ..Default::default()
        }
    );
    let mut wrong_salt = original.clone();
    wrong_salt.salt = Some([8; 16]);
    let mut wrong_key = original.clone();
    wrong_key.tx_viewing_pk = Some(keypair(41).viewing_pubkey());
    let mut wrong_slot = original.clone();
    wrong_slot.output_slots.insert(0, slot(&note, vec![]));
    let mut wrong_ciphertext = original;
    let output = wrong_ciphertext.output_slots.first_mut().unwrap();
    let OutputDataEncoding::Encrypted(mut blob) = output.output_data().unwrap() else {
        panic!("encrypted confidential fixture")
    };
    // Scheme + recipient key precede the ciphertext; its amount follows an LE u64 asset ID.
    // XORing the amount's low bit preserves a parsable payload while changing 67 to 66.
    let amount_offset = 1 + zolana_keypair::x25519::X25519_PUBKEY_LEN + size_of::<u64>();
    *blob.get_mut(amount_offset).unwrap() ^= 1;
    output.payload = borsh::to_vec(&OutputDataEncoding::Encrypted(blob)).unwrap();
    let expected = SpendableDecryptionResult {
        balances: Balances {
            assets: vec![balance(vec![control], Mint::SOL, 31)],
        },
        utxos_with_data: vec![],
        ..Default::default()
    };
    for (case, altered) in [
        ("salt", wrong_salt),
        ("transaction viewing key", wrong_key),
        ("physical slot", wrong_slot),
        ("ciphertext", wrong_ciphertext),
    ] {
        let txs = [control_tx.clone(), altered];
        let decoded = decrypt(&owner, &txs, &assets);
        if case == "ciphertext" {
            let mut forged = note.clone();
            forged.utxo.amount = 66;
            assert_eq!(decoded.as_ref().unwrap().utxos.last(), Some(&forged));
        }
        // A random plaintext can name an asset id the registry lacks. It is
        // reported, never accepted as a UTXO.
        let accepted = |result: SpendableDecryptionResult| SpendableDecryptionResult {
            unknown_asset_ids: BTreeSet::new(),
            ..result
        };
        match decoded {
            Ok(candidates) => {
                assert_eq!(
                    accepted(verify_spendable(&owner, &candidates).unwrap()),
                    expected,
                    "{case}"
                );
                assert_eq!(
                    accepted(decrypt_spendable(&owner, &txs, &assets).unwrap()),
                    expected,
                    "{case}"
                );
            }
            Err(error) => {
                // The cipher is unauthenticated. A random plaintext can parse and then
                // fail semantic conversion; such an error is not an accepted forged note.
                assert!(
                    matches!(error, TransactionError::MissingRingProgramId),
                    "{case}: {error:?}"
                );
                assert_eq!(
                    decrypt_spendable(&owner, &txs, &assets),
                    Err(error),
                    "{case}"
                );
            }
        }
    }
}

/// `note` received in its own transaction, as a confidential slot.
fn received(owner: &ShieldedKeypair, note: &WalletUtxo) -> ShieldedTransaction {
    let tx_key = keypair(200).viewing_key;
    let mut tx = publication(
        note,
        vec![confidential_slot(note, owner.viewing_pubkey(), &tx_key, 0)],
    );
    tx.tx_viewing_pk = Some(tx_key.pubkey());
    tx.salt = Some([7; 16]);
    tx
}

/// The indexer's view of a merge of `inputs`, with the note `owner` should decrypt from it.
fn merge_publication(
    owner: &ShieldedKeypair,
    inputs: &[&WalletUtxo],
    tx_slot: u8,
    ring_data_hash: Option<[u8; 32]>,
) -> (ShieldedTransaction, WalletUtxo) {
    let first_nullifier = inputs[0].nullifier;
    let mut nullifiers: Vec<_> = inputs.iter().map(|input| input.nullifier).collect();
    nullifiers.extend((inputs.len()..MERGE_DEFAULT_INPUT_COUNT).map(|index| {
        merge_dummy_nullifier(&owner.nullifier_key, &first_nullifier, index as u8).unwrap()
    }));
    let utxo = Utxo {
        owner: owner.signing_pubkey(),
        asset: inputs[0].utxo.asset,
        amount: inputs.iter().map(|input| input.utxo.amount).sum(),
        blinding: merge_output_blinding(&owner.nullifier_key, &first_nullifier).unwrap(),
        ring_program_id: inputs[0].utxo.ring_program_id,
        data: Data::default(),
    };
    let nullifier_pubkey = inputs[0].nullifier_pubkey;
    let tree_id = inputs[0].tree_id;
    let utxo_hash = utxo
        .hash(
            &nullifier_pubkey,
            &[0; 32],
            &ring_data_hash.unwrap_or_default(),
            tree_id,
        )
        .unwrap();
    let output = WalletUtxo {
        nullifier: owner.nullifier(&utxo_hash, &utxo.blinding).unwrap(),
        utxo,
        nullifier_pubkey,
        utxo_hash,
        tx_viewing_key: None,
        data_hash: None,
        ring_data_hash,
        tree_id,
        leaf_index: 100 + u64::from(tx_slot),
        latest_tree_id: None,
        slot: u64::from(tx_slot),
        tx_signature: Signature::from([tx_slot; 64]),
        slot_index: 0,
    };
    let salt = [tx_slot; 16];
    let ciphertext = MergeOutputPlaintext {
        amount: output.utxo.amount,
        mint: output.utxo.asset.asset,
    }
    .encrypt(
        &merge_output_key(&owner.nullifier_key, &first_nullifier).unwrap(),
        &salt,
    )
    .unwrap();
    let payload = encode_merge_output_data(MergeOutputDataRef {
        salt: &salt,
        ciphertext: &ciphertext,
        ring_data_hash: ring_data_hash.as_ref(),
    });
    let mut tx = publication(&output, vec![slot(&output, payload)]);
    tx.nullifiers = nullifiers;
    tx.ring_program_id = output.utxo.ring_program_id;
    (tx, output)
}

/// A proofless ring deposit of `amount` of `mint` to `owner`, encrypted to
/// `recipient`. Returns the note the owner should read back.
fn ring_deposit(
    owner: &ShieldedKeypair,
    recipient: X25519Pubkey,
    ring: Address,
    mint: Mint,
    amount: u64,
    nonce: u8,
) -> (ShieldedTransaction, WalletUtxo) {
    let address = owner.shielded_address().unwrap();
    let plaintext = RingDepositPlaintext {
        blinding: [nonce; 32],
        utxo_data: None,
        memo: Some(vec![nonce]),
        ring_data: Vec::new(),
    };
    let ring_data_hash = [0; 32];
    let tree_id = 5;
    let utxo = plaintext
        .clone()
        .into_utxo(address.signing_pubkey, mint, amount, ring);
    let utxo_hash = utxo
        .hash(
            &address.nullifier_pubkey,
            &[0; 32],
            &ring_data_hash,
            tree_id,
        )
        .unwrap();
    let output = EncryptedRingDepositOutput {
        owner_utxo_hash: owner_utxo_hash(&address.owner_hash().unwrap(), &plaintext.blinding)
            .unwrap(),
        asset: *mint.asset.as_array(),
        amount,
        data_hash: None,
        ring_program_id: *ring.as_array(),
        ring_data_hash,
        encrypted: plaintext.encrypt(&recipient).unwrap(),
    };
    let mut blob = vec![EncryptedScheme::RingDeposit.as_byte()];
    blob.extend(borsh::to_vec(&output).unwrap());
    let note = WalletUtxo {
        nullifier: owner.nullifier(&utxo_hash, &utxo.blinding).unwrap(),
        utxo,
        nullifier_pubkey: address.nullifier_pubkey,
        utxo_hash,
        tx_viewing_key: None,
        data_hash: None,
        ring_data_hash: Some(ring_data_hash),
        tree_id,
        leaf_index: u64::from(nonce),
        latest_tree_id: None,
        slot: u64::from(nonce),
        tx_signature: Signature::from([nonce; 64]),
        slot_index: 0,
    };
    let mut tx = publication(
        &note,
        vec![slot(
            &note,
            borsh::to_vec(&OutputDataEncoding::Encrypted(blob)).unwrap(),
        )],
    );
    tx.proofless = true;
    (tx, note)
}

#[test]
fn merge_outputs_decrypt_from_the_batch_in_any_order() {
    let owner = keypair(41);
    let assets = AssetRegistry::default();
    let first = wallet_utxo(&owner, Mint::SOL, 30, 3, 1);
    let second = wallet_utxo(&owner, Mint::SOL, 12, 3, 2);
    let (merge, merged) = merge_publication(&owner, &[&first, &second], 10, None);
    let (chained, chained_output) = merge_publication(&owner, &[&merged], 11, None);
    let txs = vec![
        received(&owner, &first),
        received(&owner, &second),
        merge,
        chained,
    ];

    let candidates = decrypt(&owner, &txs, &assets).unwrap();
    assert_eq!(
        candidates.utxos,
        vec![first, second, merged, chained_output.clone()]
    );
    let expected = SpendableDecryptionResult {
        balances: Balances {
            assets: vec![balance(vec![chained_output], Mint::SOL, 42)],
        },
        utxos_with_data: vec![],
        ..Default::default()
    };
    assert_eq!(decrypt_spendable(&owner, &txs, &assets).unwrap(), expected);
    let reversed: Vec<_> = txs.into_iter().rev().collect();
    assert_eq!(
        decrypt_spendable(&owner, &reversed, &assets).unwrap(),
        expected
    );
}

#[test]
fn a_merge_decrypts_from_its_own_transaction() {
    let owner = keypair(47);
    let assets = AssetRegistry::default();
    let first = wallet_utxo(&owner, Mint::SOL, 30, 3, 1);
    let second = wallet_utxo(&owner, Mint::SOL, 12, 3, 2);
    let (merge, merged) = merge_publication(&owner, &[&first, &second], 10, None);

    // Neither input is in the batch: the output decrypts from its ciphertext.
    let decrypted = decrypt(&owner, std::slice::from_ref(&merge), &assets).unwrap();
    assert_eq!(decrypted.utxos, vec![merged.clone()]);
    assert_eq!(
        verify_spendable(&owner, &decrypted).unwrap(),
        SpendableDecryptionResult {
            balances: Balances {
                assets: vec![balance(vec![merged], Mint::SOL, 42)],
            },
            ..Default::default()
        }
    );
}

/// Certora M-03: a merger holds the owner's nullifier secret and can fold in a
/// note it funded to the owner and never disclosed, even as the first input.
/// The proof binds the ciphertext of the output's amount and mint, so the owner
/// recovers the whole total instead of losing the notes it did hold.
#[test]
fn a_merge_of_a_note_the_owner_never_saw_decrypts_with_the_whole_total() {
    let owner = keypair(53);
    let assets = AssetRegistry::default();
    let held = wallet_utxo(&owner, Mint::SOL, 30, 3, 1);
    let undisclosed = wallet_utxo(&owner, Mint::SOL, 777, 3, 2);
    let (merge, merged) = merge_publication(&owner, &[&undisclosed, &held], 10, None);
    assert_eq!(merged.utxo.amount, 807);

    let spendable = decrypt_spendable(&owner, &[received(&owner, &held), merge], &assets).unwrap();
    assert_eq!(spendable.utxos().collect::<Vec<_>>(), vec![&merged]);
}

#[test]
fn extending_a_result_decrypts_only_the_new_transactions() {
    let owner = keypair(51);
    let keys = RecordingKeys::new(&owner);
    let assets = AssetRegistry::default();
    let first = wallet_utxo(&owner, Mint::SOL, 30, 3, 1);
    let second = wallet_utxo(&owner, Mint::SOL, 12, 3, 2);
    let earlier = vec![received(&owner, &first), received(&owner, &second)];
    let (merge, merged) = merge_publication(&owner, &[&first, &second], 10, None);

    let mut decrypted = decrypt(&keys, &earlier, &assets).unwrap();
    let earlier_decrypts = keys.decrypt_calls.borrow().len();
    decrypted
        .extend(&keys, std::slice::from_ref(&merge), &assets)
        .unwrap();

    // Nothing the earlier call covered was decrypted again, and the merge
    // decrypted under a derived key rather than a viewing-key decryption.
    assert_eq!(keys.decrypt_calls.borrow().len(), earlier_decrypts);
    assert_eq!(decrypted.utxos.last(), Some(&merged));
    let all: Vec<_> = earlier.into_iter().chain([merge]).collect();
    assert_eq!(decrypted, decrypt(&owner, &all, &assets).unwrap());
}

#[test]
fn a_merge_found_before_the_merge_it_spends_decrypts_at_once() {
    let owner = keypair(52);
    let assets = AssetRegistry::default();
    let first = wallet_utxo(&owner, Mint::SOL, 30, 3, 1);
    let second = wallet_utxo(&owner, Mint::SOL, 12, 3, 2);
    // M0 spends `second` into X, M0' spends X into Y, and M1 spends `first`
    // and Y. M1 arrives a round before Y exists and decrypts anyway.
    let (m0, x) = merge_publication(&owner, &[&second], 10, None);
    let (m0_prime, y) = merge_publication(&owner, &[&x], 11, None);
    let (m1, merged) = merge_publication(&owner, &[&first, &y], 12, None);
    let rounds = [
        vec![received(&owner, &first), received(&owner, &second)],
        vec![m0.clone(), m1.clone()],
        vec![m0_prime.clone()],
    ];

    let mut decrypted = DecryptionResult::default();
    decrypted.extend(&owner, &rounds[0], &assets).unwrap();
    decrypted.extend(&owner, &rounds[1], &assets).unwrap();
    assert!(decrypted.utxos.contains(&merged));
    decrypted.extend(&owner, &rounds[2], &assets).unwrap();

    let spendable = verify_spendable(&owner, &decrypted).unwrap();
    assert_eq!(spendable.utxos().collect::<Vec<_>>(), vec![&merged]);
    let all: Vec<_> = rounds.into_iter().flatten().collect();
    assert_eq!(decrypted, decrypt(&owner, &all, &assets).unwrap());
}

#[test]
fn a_merge_output_decrypts_only_under_its_owners_key_and_commitment() {
    let owner = keypair(43);
    let other = keypair(44);
    let assets = AssetRegistry::default();
    let held = wallet_utxo(&owner, Mint::SOL, 30, 3, 1);
    let foreign = wallet_utxo(&other, Mint::SOL, 9, 3, 3);
    let edit_payload = |tx: &mut ShieldedTransaction, edit: &dyn Fn(&mut Vec<u8>)| {
        let slot = tx.output_slots.first_mut().expect("merge output slot");
        edit(&mut slot.payload);
    };

    // Another owner's merge decrypts to noise under this wallet's key.
    let (foreign_merge, _) = merge_publication(&other, &[&foreign], 11, None);
    // A flipped mint ciphertext bit must not trigger an unauthenticated registry lookup.
    let (mut tampered, _) = merge_publication(&owner, &[&held], 12, None);
    edit_payload(&mut tampered, &|payload| {
        *payload.last_mut().expect("ciphertext byte") ^= 1;
    });
    // A published commitment that is not the encrypted output.
    let (mut wrong_commitment, _) = merge_publication(&owner, &[&held], 13, None);
    wrong_commitment
        .output_slots
        .first_mut()
        .expect("merge output slot")
        .output_context
        .hash = wallet_utxo(&owner, Mint::SOL, 31, 3, 5).utxo_hash;
    // A ring data hash on a merge that names no ring program.
    let (mut ring_without_program, _) = merge_publication(&owner, &[&held], 14, Some([4; 32]));
    ring_without_program.ring_program_id = None;
    // A ring program on a merge whose payload carries no ring data hash.
    let (mut program_without_ring, _) = merge_publication(&owner, &[&held], 15, None);
    program_without_ring.ring_program_id = Some(Address::new_from_array([8; 32]));

    for (case, merge, remaining) in [
        ("foreign merge", foreign_merge, vec![&held]),
        ("tampered ciphertext", tampered, vec![]),
        ("wrong commitment", wrong_commitment, vec![]),
        (
            "ring hash without a ring program",
            ring_without_program,
            vec![],
        ),
        (
            "ring program without a ring hash",
            program_without_ring,
            vec![],
        ),
    ] {
        let decrypted = decrypt(&owner, &[received(&owner, &held), merge], &assets).unwrap();
        assert!(decrypted.unknown_asset_ids.is_empty(), "{case}");
        assert!(decrypted.unknown_mints.is_empty(), "{case}");
        let spendable = verify_spendable(&owner, &decrypted).unwrap();
        // No merge output decrypts; this wallet's merges still spend `held`.
        assert_eq!(spendable.utxos().collect::<Vec<_>>(), remaining, "{case}");
    }
}

#[test]
fn merge_mints_are_resolved_only_after_the_output_commitment_matches() {
    let owner = keypair(54);
    let mint = Mint::new(Address::new_from_array([55; 32]), 99);
    for ring in [None, Some([4; 32])] {
        let mut held = wallet_utxo(&owner, mint, 30, 3, 1);
        if ring.is_some() {
            held.utxo.ring_program_id = Some(Address::new_from_array([8; 32]));
            held.utxo_hash = held
                .utxo
                .hash(&held.nullifier_pubkey, &[0; 32], &[0; 32], held.tree_id)
                .unwrap();
            held.nullifier = owner
                .nullifier(&held.utxo_hash, &held.utxo.blinding)
                .unwrap();
        }
        let (merge, merged) = merge_publication(&owner, &[&held], 12, ring);
        let assets = AssetRegistry::default();
        let valid = decrypt(&owner, std::slice::from_ref(&merge), &assets).unwrap();
        assert_eq!(valid.unknown_mints, BTreeSet::from([mint.asset]));
        assert!(valid.utxos.is_empty());

        let mut tampered = merge.clone();
        tampered
            .output_slots
            .first_mut()
            .unwrap()
            .output_context
            .hash = [0; 32];
        let rejected = decrypt(&owner, &[tampered], &assets).unwrap();
        assert!(rejected.utxos.is_empty());
        assert!(rejected.unknown_mints.is_empty());
        assert!(rejected.unknown_asset_ids.is_empty());

        let registered = AssetRegistry::new([(mint.asset_id, mint.asset)]).unwrap();
        let recovered = decrypt(&owner, &[merge], &registered).unwrap();
        assert_eq!(recovered.utxos, vec![merged]);
        assert!(recovered.unknown_mints.is_empty());
    }
}

#[test]
fn outputs_in_unregistered_assets_are_reported_without_failing_the_scan() {
    let owner = keypair(48);
    let assets = AssetRegistry::default();
    let control = wallet_utxo(&owner, Mint::SOL, 53, 1, 1);
    let mut unknown_id = wallet_utxo(&owner, Mint::SOL, 53, 1, 4);
    unknown_id.utxo.asset.asset_id = 99;
    let proofless_mint = Mint::new(Address::new_from_array([49; 32]), 99);
    let proofless = wallet_utxo(&owner, proofless_mint, 53, 1, 2);
    let ring_mint = Mint::new(Address::new_from_array([50; 32]), 98);
    let (ring_tx, _) = ring_deposit(
        &owner,
        owner.viewing_pubkey(),
        Address::new_from_array([9; 32]),
        ring_mint,
        20,
        3,
    );
    let txs = [
        publication(&control, vec![proofless_slot(&control, &owner)]),
        publication(&proofless, vec![proofless_slot(&proofless, &owner)]),
        ring_tx,
        received(&owner, &unknown_id),
    ];
    let unknown_asset_ids = BTreeSet::from([99]);
    let unknown_mints = BTreeSet::from([proofless_mint.asset, ring_mint.asset]);

    let decrypted = decrypt(&owner, &txs, &assets).unwrap();
    assert_eq!(decrypted.utxos, vec![control.clone()]);
    assert_eq!(decrypted.unknown_asset_ids, unknown_asset_ids);
    assert_eq!(decrypted.unknown_mints, unknown_mints);
    let spendable = decrypt_spendable(&owner, &txs, &assets).unwrap();
    assert_eq!(spendable.utxos().collect::<Vec<_>>(), vec![&control]);
    assert_eq!(spendable.unknown_asset_ids, unknown_asset_ids);
    assert_eq!(spendable.unknown_mints, unknown_mints);
}

#[test]
fn ring_deposits_open_for_their_owner_and_feed_a_ring_merge() {
    let owner = keypair(45);
    let other = keypair(46);
    let assets = AssetRegistry::default();
    let ring = Address::new_from_array([9; 32]);
    let (first_deposit, first) =
        ring_deposit(&owner, owner.viewing_pubkey(), ring, Mint::SOL, 20, 1);
    let (second_deposit, second) =
        ring_deposit(&owner, owner.viewing_pubkey(), ring, Mint::SOL, 22, 2);
    assert_eq!(first.utxo.ring_program_id, Some(ring));
    assert_eq!(first.utxo.data.memo(), Some(&[1u8][..]));

    let candidates = decrypt(
        &owner,
        &[first_deposit.clone(), second_deposit.clone()],
        &assets,
    )
    .unwrap();
    assert_eq!(candidates.utxos, vec![first.clone(), second.clone()]);

    // Ring notes are reported apart from the default-ring balances.
    let (merge, merged) = merge_publication(&owner, &[&first, &second], 10, Some([0; 32]));
    assert_eq!(merged.utxo.ring_program_id, Some(ring));
    assert_eq!(
        decrypt_spendable(&owner, &[first_deposit, second_deposit, merge], &assets).unwrap(),
        SpendableDecryptionResult {
            balances: Balances::default(),
            utxos_with_data: vec![merged],
            ..Default::default()
        }
    );

    // Encrypted to someone else, or opened by a key whose owner hash the deposit
    // does not name: the unauthenticated cipher yields noise, never a note.
    let (to_other, _) = ring_deposit(&owner, other.viewing_pubkey(), ring, Mint::SOL, 20, 3);
    let (for_other, _) = ring_deposit(&other, owner.viewing_pubkey(), ring, Mint::SOL, 20, 4);
    assert_eq!(
        decrypt(&owner, &[to_other, for_other], &assets).unwrap(),
        DecryptionResult::default()
    );
}

#[test]
fn merge_unknown_mints_are_reported_only_after_the_commitment_matches() {
    let owner = keypair(47);
    let mint = Mint::new(Address::new_from_array([71; 32]), 2);
    let note = wallet_utxo(&owner, mint, 30, 3, 1);
    let (mut merge, _) = merge_publication(&owner, &[&note], 10, None);
    let assets = AssetRegistry::default();
    let decoded = decrypt(&owner, std::slice::from_ref(&merge), &assets).unwrap();
    assert_eq!(decoded.unknown_mints, BTreeSet::from([mint.asset]));
    assert!(decoded.utxos.is_empty());
    merge.output_slots[0].output_context.hash[0] ^= 1;
    let decoded = decrypt(&owner, &[merge], &assets).unwrap();
    assert!(decoded.unknown_mints.is_empty());
    assert!(decoded.utxos.is_empty());
}

#[test]
fn low_order_transaction_keys_leave_the_scan_intact() {
    let owner = keypair(47);
    let assets = AssetRegistry::default();
    let note = wallet_utxo(&owner, Mint::SOL, 33, 7, 5);
    let ring = Address::new_from_array([9; 32]);
    let (deposit, deposited) = ring_deposit(&owner, owner.viewing_pubkey(), ring, Mint::SOL, 20, 6);
    let mut batch = Vec::new();
    for u in [0, 1] {
        let mut low_order = [0; 32];
        low_order[0] = u;
        let low_order = X25519Pubkey::from_u(low_order).unwrap();

        let mut confidential = received(&owner, &note);
        confidential.tx_viewing_pk = Some(low_order);
        batch.push(confidential);

        let mut ring_deposit = deposit.clone();
        let OutputDataEncoding::Encrypted(blob) =
            borsh::from_slice(&ring_deposit.output_slots[0].payload).unwrap()
        else {
            panic!("ring deposit slot is encrypted");
        };
        let mut output = borsh::from_slice::<EncryptedRingDepositOutput>(&blob[1..]).unwrap();
        output.encrypted.tx_viewing_pk = *low_order.as_bytes();
        let mut blob = vec![EncryptedScheme::RingDeposit.as_byte()];
        blob.extend(borsh::to_vec(&output).unwrap());
        ring_deposit.output_slots[0].payload =
            borsh::to_vec(&OutputDataEncoding::Encrypted(blob)).unwrap();
        batch.push(ring_deposit);
    }
    batch.push(received(&owner, &note));
    batch.push(deposit);

    let candidates = decrypt(&owner, &batch, &assets).unwrap();
    assert_eq!(candidates.utxos, vec![note, deposited]);
}
