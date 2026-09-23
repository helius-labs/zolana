mod common;

use std::{cell::RefCell, collections::HashSet};

use common::{keypair, wallet_utxo};
use solana_signature::Signature;
use zolana_event::OutputDataEncoding;
use zolana_keypair::{P256Pubkey, ShieldedAddress, ShieldedKeypair, ViewingKey};
use zolana_transaction::{
    decrypt, decrypt_spendable,
    serialization::{
        anonymous::{AnonymousRecipient, AnonymousRecipientEncode},
        confidential::{Confidential, ConfidentialEncode},
        plaintext::{PlaintextTransfer, TransferPlaintextUtxos},
        proofless::{Proofless, ProoflessEncode},
    },
    verify_spendable, Address, AssetBalance, AssetRegistry, Balances, Data, DataRecord,
    DecryptLabel, DecryptRequest, DecryptionResult, DeriveRequest, EncryptedScheme,
    LocalShieldedKeys, Mint, OutputContext, OutputSlot, OwnerCx, ShieldedKeys, ShieldedTransaction,
    SpendableDecryptionResult, TransactionError, TransactionKeyRequest, UtxoSerialization,
    WalletUtxo, TRANSFER_PLAINTEXT,
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
    recipient: P256Pubkey,
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
            spent_nullifiers: HashSet::new()
        }
    );
    let expected = SpendableDecryptionResult {
        balances: Balances {
            assets: vec![balance(vec![first.clone(), second.clone()], Mint::SOL, 78)],
        },
        utxos_with_data: vec![],
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
        };
        let before = decrypted.clone();
        assert_eq!(
            verify_spendable(&owner, &decrypted).unwrap(),
            SpendableDecryptionResult {
                balances: Balances {
                    assets: vec![balance(vec![control.clone()], Mint::SOL, 29)],
                },
                utxos_with_data: vec![],
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
                spent_nullifiers: HashSet::new()
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
        }
    );
    assert_eq!(candidates, before);
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RecordedDecrypt {
    ciphertext: Vec<u8>,
    viewing_pubkey: P256Pubkey,
    tx_viewing_pubkey: P256Pubkey,
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
    fn viewing_public_keys(&self) -> Vec<P256Pubkey> {
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
                spent_nullifiers: HashSet::new()
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
                    .get(1 + zolana_keypair::constants::P256_PUBKEY_LEN..)
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
fn parsed_conversion_errors_propagate_instead_of_being_treated_as_cipher_noise() {
    let owner = keypair(32);
    let note = wallet_utxo(&owner, Mint::SOL, 53, 1, 1);
    let tx_key = keypair(33).viewing_key;
    let mut cases = Vec::new();
    let mut unknown = note.clone();
    unknown.utxo.asset.asset_id = 99;
    cases.push((
        confidential_slot(&unknown, owner.viewing_pubkey(), &tx_key, 0),
        TransactionError::UnknownAsset(99),
    ));
    let mut ring = note.clone();
    ring.utxo.data = Data::new(vec![DataRecord::RingData(vec![1])]);
    cases.push((
        confidential_slot(&ring, owner.viewing_pubkey(), &tx_key, 0),
        TransactionError::MissingRingProgramId,
    ));
    let plaintext = TransferPlaintextUtxos {
        type_prefix: TRANSFER_PLAINTEXT,
        blinding_seed: [0; 32],
        sender: None,
        recipient_slots: vec![],
    };
    let mut blob = vec![EncryptedScheme::PlaintextTransfer.as_byte()];
    blob.extend(PlaintextTransfer::serialize(&plaintext).unwrap());
    cases.push((
        slot(
            &note,
            borsh::to_vec(&OutputDataEncoding::Plaintext(blob)).unwrap(),
        ),
        TransactionError::MissingFirstNullifier,
    ));
    let unknown_mint = Mint::new(Address::new_from_array([34; 32]), 99);
    let unknown = wallet_utxo(&owner, unknown_mint, 53, 1, 2);
    cases.push((
        proofless_slot(&unknown, &owner),
        TransactionError::UnknownMint(unknown_mint.asset),
    ));
    for (output, error) in cases {
        let mut tx = publication(&note, vec![output]);
        tx.tx_viewing_pk = Some(tx_key.pubkey());
        tx.salt = Some([7; 16]);
        let control = publication(&note, vec![proofless_slot(&note, &owner)]);
        let txs = vec![control, tx];
        let explicit = decrypt(&owner, &txs, &AssetRegistry::default())
            .and_then(|d| verify_spendable(&owner, &d));
        assert_eq!(explicit, Err(error.clone()));
        assert_eq!(
            decrypt_spendable(&owner, &txs, &AssetRegistry::default()),
            Err(error)
        );
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
    let amount_offset = 1 + zolana_keypair::constants::P256_PUBKEY_LEN + size_of::<u64>();
    *blob.get_mut(amount_offset).unwrap() ^= 1;
    output.payload = borsh::to_vec(&OutputDataEncoding::Encrypted(blob)).unwrap();
    let expected = SpendableDecryptionResult {
        balances: Balances {
            assets: vec![balance(vec![control], Mint::SOL, 31)],
        },
        utxos_with_data: vec![],
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
        match decoded {
            Ok(candidates) => {
                assert_eq!(
                    verify_spendable(&owner, &candidates).unwrap(),
                    expected,
                    "{case}"
                );
                assert_eq!(
                    decrypt_spendable(&owner, &txs, &assets).unwrap(),
                    expected,
                    "{case}"
                );
            }
            Err(error) => {
                // The cipher is unauthenticated. A random plaintext can parse and then
                // fail semantic conversion; such an error is not an accepted forged note.
                assert!(
                    matches!(
                        error,
                        TransactionError::UnknownAsset(_) | TransactionError::MissingRingProgramId
                    ),
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
