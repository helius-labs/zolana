//! `UtxoScan::with_anonymous_ring` against an in-memory indexer.

use std::{
    cell::RefCell,
    collections::{BTreeSet, HashSet},
};

use solana_address::Address;
use solana_signature::Signature;
use zolana_client::{
    rpc::GetShieldedTransactionsByNullifiersResponse, AnonymousRingState, AnonymousStream,
    ClientError, Context, EncryptedUtxoMatch, GetEncryptedUtxosByTagsResponse,
    GetShieldedTransactionsByTagsResponse, IndexerRpcConfig, OutputContext, OutputSlot, Rpc,
    ShieldedTransaction, UtxoScan, ADDRESS_GAP, DECRYPTIONS_PER_INDEX,
};
use zolana_event::{EncryptedRingDepositOutput, OutputDataEncoding};
use zolana_keypair::{viewing_key::ViewTag, ShieldedKeypair, SigningKey, ViewingKey, X25519Pubkey};
use zolana_transaction::{
    owner_utxo_hash,
    serialization::{
        confidential::ConfidentialEncode,
        ring_anonymous::{RingAnonymous, RingAnonymousOutputPlaintext},
    },
    AssetRegistry, Data, DecryptRequest, DeriveRequest, EncryptedScheme, Mint,
    RingDepositPlaintext, RingTagRequest, ShieldedKeys, TransactionError, TransactionKeyRequest,
    Utxo,
};

const TREE: u16 = 2;
const RING: Address = Address::new_from_array([4; 32]);
const SALT: [u8; 16] = [7; 16];

#[derive(Default)]
struct Indexer {
    tagged: Vec<ShieldedTransaction>,
    deposits: Vec<EncryptedUtxoMatch>,
    spends: Vec<ShieldedTransaction>,
    queried_tags: RefCell<Vec<Vec<ViewTag>>>,
}

impl Indexer {
    fn queried(&self, tag: &ViewTag) -> bool {
        self.queried_tags
            .borrow()
            .iter()
            .any(|tags| tags.contains(tag))
    }
}

const CONTEXT: Context = Context {
    block_time: 0,
    slot: 0,
};

impl Rpc for Indexer {
    fn get_shielded_transactions_by_tags(
        &self,
        tags: Vec<ViewTag>,
        _cursor: Option<Vec<u8>>,
        _limit: Option<u32>,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        self.queried_tags.borrow_mut().push(tags.clone());
        Ok(GetShieldedTransactionsByTagsResponse {
            context: CONTEXT,
            output_tree_id: Some(TREE),
            transactions: self
                .tagged
                .iter()
                .filter(|tx| {
                    tx.output_slots
                        .iter()
                        .any(|slot| tags.contains(&slot.view_tag))
                })
                .cloned()
                .collect(),
            next_cursor: None,
            scanned_through: None,
        })
    }

    fn get_encrypted_utxos_by_tags(
        &self,
        tags: Vec<ViewTag>,
        _cursor: Option<Vec<u8>>,
        _limit: Option<u32>,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetEncryptedUtxosByTagsResponse, ClientError> {
        Ok(GetEncryptedUtxosByTagsResponse {
            context: CONTEXT,
            output_tree_id: Some(TREE),
            matches: self
                .deposits
                .iter()
                .filter(|deposit| tags.contains(&deposit.output_slot.view_tag))
                .cloned()
                .collect(),
            next_cursor: None,
            scanned_through: None,
        })
    }

    fn get_shielded_transactions_by_nullifiers(
        &self,
        nullifiers: Vec<[u8; 32]>,
        _cursor: Option<Vec<u8>>,
        _limit: Option<u32>,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByNullifiersResponse, ClientError> {
        Ok(GetShieldedTransactionsByNullifiersResponse {
            context: CONTEXT,
            output_tree_id: Some(TREE),
            transactions: self
                .spends
                .iter()
                .filter(|tx| tx.nullifiers.iter().any(|n| nullifiers.contains(n)))
                .cloned()
                .collect(),
            next_cursor: None,
            scanned_through: None,
        })
    }
}

/// Records which viewing keys each decryption named.
struct CountingKeys<'a> {
    owner: &'a ShieldedKeypair,
    decrypted_under: RefCell<Vec<X25519Pubkey>>,
}

impl ShieldedKeys for CountingKeys<'_> {
    fn address(&self) -> Result<zolana_keypair::ShieldedAddress, TransactionError> {
        self.owner.address()
    }
    fn viewing_public_keys(&self) -> Vec<X25519Pubkey> {
        self.owner.viewing_public_keys()
    }
    fn decrypt(&self, requests: &[DecryptRequest<'_>]) -> Result<Vec<Vec<u8>>, TransactionError> {
        self.decrypted_under
            .borrow_mut()
            .extend(requests.iter().map(|request| request.viewing_pubkey));
        self.owner.decrypt(requests)
    }
    fn derive(&self, requests: &[DeriveRequest]) -> Result<Vec<[u8; 32]>, TransactionError> {
        self.owner.derive(requests)
    }
    fn transaction_keys(
        &self,
        requests: &[TransactionKeyRequest],
    ) -> Result<Vec<ViewingKey>, TransactionError> {
        self.owner.transaction_keys(requests)
    }
    fn ring_view_tags(
        &self,
        requests: &[RingTagRequest],
    ) -> Result<Vec<ViewTag>, TransactionError> {
        self.owner.ring_view_tags(requests)
    }
}

fn keypair(seed: u8) -> ShieldedKeypair {
    ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[seed; 32])).unwrap()
}

/// A ring note of `owner` with its commitment and nullifier.
struct Note {
    utxo: Utxo,
    hash: [u8; 32],
    nullifier: [u8; 32],
}

fn note(owner: &ShieldedKeypair, amount: u64, nonce: u8) -> Note {
    let mut blinding = [0; 32];
    blinding[31] = nonce;
    let utxo = Utxo {
        owner: owner.signing_pubkey(),
        asset: Mint::SOL,
        amount,
        blinding,
        ring_program_id: Some(RING),
        data: Data::default(),
    };
    let nullifier_pubkey = owner.nullifier_key.pubkey().unwrap();
    let hash = utxo
        .hash(&nullifier_pubkey, &[0; 32], &[0; 32], TREE)
        .unwrap();
    Note {
        nullifier: owner.nullifier(&hash, &blinding).unwrap(),
        hash,
        utxo,
    }
}

/// `payer` pays `note` to `recipient` in `slot_index` under `tag`.
fn anonymous_slot(
    payer: &ViewingKey,
    tx: &ViewingKey,
    recipient: X25519Pubkey,
    note: &Note,
    tag: ViewTag,
    slot_index: u32,
) -> OutputSlot {
    let message = RingAnonymous::encode_plaintext(
        &RingAnonymousOutputPlaintext {
            output: note.utxo.to_confidential_output_plaintext(),
            pair_pk: payer.pair_key(&recipient).unwrap().pubkey(),
        },
        tag,
        &ConfidentialEncode {
            tx: tx.clone(),
            recipient_pubkey: recipient,
            salt: SALT,
            slot_index,
        },
    )
    .unwrap();
    OutputSlot {
        view_tag: tag,
        output_context: OutputContext {
            hash: note.hash,
            tree_id: TREE,
            leaf_index: u64::from(slot_index),
        },
        payload: message.data,
    }
}

fn transaction(
    tx: &ViewingKey,
    nonce: u8,
    nullifiers: Vec<[u8; 32]>,
    output_slots: Vec<OutputSlot>,
) -> ShieldedTransaction {
    ShieldedTransaction {
        slot: u64::from(nonce),
        tx_signature: Signature::from([nonce; 64]),
        event_index: Some(0),
        tx_viewing_pk: Some(tx.pubkey()),
        salt: Some(SALT),
        output_slots,
        messages: Vec::new(),
        nullifiers,
        proofless: false,
        ring_config: None,
        ring_program_id: Some(RING),
    }
}

/// A first payment of `amount` from `payer` to `recipient`'s address `i` at inbox index `j`.
fn inbox_payment(
    payer: &ShieldedKeypair,
    recipient: &ShieldedKeypair,
    i: u32,
    j: u64,
    amount: u64,
    nonce: u8,
) -> (ShieldedTransaction, Note) {
    let paid = note(recipient, amount, nonce);
    let tag = recipient
        .viewing_key
        .inbox_secret(i)
        .unwrap()
        .view_tag(j)
        .unwrap();
    let tx_key = keypair(nonce).viewing_key;
    let slot = anonymous_slot(
        &payer.viewing_key,
        &tx_key,
        recipient.viewing_pubkey(),
        &paid,
        tag,
        0,
    );
    (
        transaction(&tx_key, nonce, vec![[nonce; 32]], vec![slot]),
        paid,
    )
}

/// A ring deposit of `amount` to `owner` under the sender tag `n`.
fn ring_deposit(
    owner: &ShieldedKeypair,
    n: u64,
    amount: u64,
    nonce: u8,
) -> (EncryptedUtxoMatch, Note) {
    let address = owner.shielded_address().unwrap();
    let mut blinding = [0; 32];
    blinding[31] = nonce;
    let plaintext = RingDepositPlaintext {
        blinding,
        utxo_data: None,
        memo: None,
        ring_data: Vec::new(),
    };
    let deposited = note(owner, amount, nonce);
    let output = EncryptedRingDepositOutput {
        owner_utxo_hash: owner_utxo_hash(&address.owner_hash().unwrap(), &blinding).unwrap(),
        asset: *Mint::SOL.asset.as_array(),
        amount,
        data_hash: None,
        ring_program_id: *RING.as_array(),
        ring_data_hash: [0; 32],
        encrypted: plaintext.encrypt(&address.viewing_pubkey).unwrap(),
    };
    let blob = [
        &[EncryptedScheme::RingDeposit.as_byte()][..],
        &borsh::to_vec(&output).unwrap(),
    ]
    .concat();
    let matched = EncryptedUtxoMatch {
        slot: u64::from(nonce),
        tx_signature: Signature::from([nonce; 64]),
        output_slot: OutputSlot {
            view_tag: owner.get_sender_view_tag(n).unwrap(),
            output_context: OutputContext {
                hash: deposited.hash,
                tree_id: TREE,
                leaf_index: u64::from(nonce),
            },
            payload: borsh::to_vec(&OutputDataEncoding::Encrypted(blob)).unwrap(),
        },
        tx_viewing_pk: None,
        salt: None,
    };
    (matched, deposited)
}

fn found_hashes(result: &zolana_client::UtxoScanResult) -> BTreeSet<[u8; 32]> {
    result
        .spendable
        .utxos()
        .map(|utxo| utxo.utxo_hash)
        .collect()
}

#[test]
fn two_payers_on_one_inbox_index_are_both_found() {
    let recipient = keypair(1);
    let (first_tx, first) = inbox_payment(&keypair(2), &recipient, 0, 0, 10, 11);
    let (second_tx, second) = inbox_payment(&keypair(3), &recipient, 0, 0, 20, 12);
    let indexer = Indexer {
        tagged: vec![first_tx, second_tx],
        ..Indexer::default()
    };
    let assets = AssetRegistry::default();
    let result = UtxoScan::new(&recipient, &assets)
        .with_anonymous_ring(AnonymousRingState::default())
        .fetch(&indexer)
        .unwrap();

    assert_eq!(
        found_hashes(&result),
        BTreeSet::from([first.hash, second.hash])
    );
    let report = result.anonymous.unwrap();
    let pair_keys: HashSet<_> = [keypair(2), keypair(3)]
        .iter()
        .map(|payer| {
            payer
                .viewing_key
                .pair_key(&recipient.viewing_pubkey())
                .unwrap()
                .pubkey()
        })
        .collect();
    assert_eq!(report.new_counterparties, pair_keys);
    assert_eq!(report.used_addresses, 1);
    assert_eq!(report.inbox_next.get(&0), Some(&1));
    assert!(report.addresses_under_attack.is_empty());
    assert!(report
        .notes
        .iter()
        .all(|note| note.stream == AnonymousStream::Inbox { address_index: 0 }));
    // Both pair streams were opened and read to their first empty window.
    for pair_pk in &pair_keys {
        let pair_tag = recipient
            .viewing_key
            .get_recipient_shared_view_tag(pair_pk, 0)
            .unwrap();
        assert!(indexer.queried(&pair_tag));
    }
}

#[test]
fn a_spammed_inbox_index_advances_the_stream_and_flags_the_address() {
    let recipient = keypair(1);
    let spammer = keypair(4);
    let mut tagged = Vec::new();
    for nonce in 0..=u8::try_from(DECRYPTIONS_PER_INDEX.get()).unwrap() {
        // Sealed to the spammer's own key, so nothing opens, under the recipient's tag.
        let (mut tx, _) = inbox_payment(&spammer, &spammer, 0, 0, 1, 20 + nonce);
        tx.output_slots[0].view_tag = recipient
            .viewing_key
            .inbox_secret(0)
            .unwrap()
            .view_tag(0)
            .unwrap();
        tagged.push(tx);
    }
    let (real_tx, real) = inbox_payment(&keypair(2), &recipient, 0, 1, 10, 11);
    tagged.push(real_tx);
    let indexer = Indexer {
        tagged,
        ..Indexer::default()
    };
    let assets = AssetRegistry::default();
    let result = UtxoScan::new(&recipient, &assets)
        .with_anonymous_ring(AnonymousRingState::default())
        .fetch(&indexer)
        .unwrap();

    assert_eq!(found_hashes(&result), BTreeSet::from([real.hash]));
    let report = result.anonymous.unwrap();
    assert_eq!(report.addresses_under_attack, BTreeSet::from([0]));
    assert_eq!(report.inbox_next.get(&0), Some(&2));
    assert_eq!(report.used_addresses, 1);
}

#[test]
fn change_is_found_from_the_nullifiers_of_a_fresh_wallet() {
    let owner = keypair(1);
    let other = keypair(5);
    let (deposit, deposited) = ring_deposit(&owner, 0, 50, 30);
    let paid = note(&other, 30, 31);
    let change = note(&owner, 20, 32);
    let tx_key = owner
        .viewing_key
        .get_transaction_viewing_key(&deposited.nullifier)
        .unwrap();
    let inbox_tag = other
        .viewing_key
        .inbox_secret(0)
        .unwrap()
        .view_tag(0)
        .unwrap();
    let change_tag = owner
        .viewing_key
        .ring_change_view_tag(&deposited.nullifier, 1)
        .unwrap();
    let spend = transaction(
        &tx_key,
        33,
        vec![deposited.nullifier],
        vec![
            anonymous_slot(
                &owner.viewing_key,
                &tx_key,
                other.viewing_pubkey(),
                &paid,
                inbox_tag,
                0,
            ),
            anonymous_slot(
                &owner.viewing_key,
                &tx_key,
                owner.viewing_pubkey(),
                &change,
                change_tag,
                1,
            ),
        ],
    );
    let indexer = Indexer {
        deposits: vec![deposit],
        spends: vec![spend],
        ..Indexer::default()
    };
    let assets = AssetRegistry::default();
    let keys = CountingKeys {
        owner: &owner,
        decrypted_under: RefCell::new(Vec::new()),
    };
    let result = UtxoScan::new(&keys, &assets)
        .with_anonymous_ring(AnonymousRingState::default())
        .fetch(&indexer)
        .unwrap();

    assert_eq!(found_hashes(&result), BTreeSet::from([change.hash]));
    let owned: BTreeSet<_> = result
        .history
        .utxos
        .iter()
        .map(|utxo| utxo.utxo_hash)
        .collect();
    assert_eq!(owned, BTreeSet::from([deposited.hash, change.hash]));
    let report = result.anonymous.unwrap();
    assert_eq!(report.deposit_next, 1);
    assert_eq!(
        report
            .notes
            .iter()
            .map(|note| (note.utxo_hash, note.stream))
            .collect::<Vec<_>>(),
        [(
            change.hash,
            AnonymousStream::Change {
                first_nullifier: deposited.nullifier
            }
        )]
    );
    assert!(report.new_counterparties.is_empty());
    // The recipient slot carries a tag this wallet never derived, so only the
    // deposit envelope and the change slot were ever opened.
    assert!(!indexer.queried(&inbox_tag));
    assert_eq!(keys.decrypted_under.borrow().len(), 2);
    assert!(result.history.view_tags.contains(&change_tag));
}

#[test]
fn a_spend_paying_the_owners_own_address_opens_each_slot_once() {
    let owner = keypair(1);
    let (deposit, deposited) = ring_deposit(&owner, 0, 50, 40);
    let to_self = note(&owner, 30, 41);
    let change = note(&owner, 20, 42);
    let tx_key = owner
        .viewing_key
        .get_transaction_viewing_key(&deposited.nullifier)
        .unwrap();
    let inbox_tag = owner
        .viewing_key
        .inbox_secret(0)
        .unwrap()
        .view_tag(0)
        .unwrap();
    let change_tag = owner
        .viewing_key
        .ring_change_view_tag(&deposited.nullifier, 1)
        .unwrap();
    let spend = transaction(
        &tx_key,
        43,
        vec![deposited.nullifier],
        vec![
            anonymous_slot(
                &owner.viewing_key,
                &tx_key,
                owner.viewing_pubkey(),
                &to_self,
                inbox_tag,
                0,
            ),
            anonymous_slot(
                &owner.viewing_key,
                &tx_key,
                owner.viewing_pubkey(),
                &change,
                change_tag,
                1,
            ),
        ],
    );
    let indexer = Indexer {
        tagged: vec![spend.clone()],
        deposits: vec![deposit],
        spends: vec![spend],
        ..Indexer::default()
    };
    let assets = AssetRegistry::default();
    let keys = CountingKeys {
        owner: &owner,
        decrypted_under: RefCell::new(Vec::new()),
    };
    let result = UtxoScan::new(&keys, &assets)
        .with_anonymous_ring(AnonymousRingState::default())
        .fetch(&indexer)
        .unwrap();

    assert_eq!(
        found_hashes(&result),
        BTreeSet::from([to_self.hash, change.hash])
    );
    assert_eq!(result.history.utxos.len(), 3);
    assert_eq!(keys.decrypted_under.borrow().len(), 3);
}

#[test]
fn address_discovery_stops_a_gap_past_the_last_used_address() {
    let recipient = keypair(1);
    // Inside the gap after address 0, so the gap moves past it.
    let far = ADDRESS_GAP - 5;
    let (near_tx, near) = inbox_payment(&keypair(2), &recipient, 0, 0, 10, 11);
    let (far_tx, far_note) = inbox_payment(&keypair(3), &recipient, far, 0, 20, 12);
    let indexer = Indexer {
        tagged: vec![near_tx, far_tx],
        ..Indexer::default()
    };
    let assets = AssetRegistry::default();
    let result = UtxoScan::new(&recipient, &assets)
        .with_anonymous_ring(AnonymousRingState::default())
        .fetch(&indexer)
        .unwrap();

    assert_eq!(
        found_hashes(&result),
        BTreeSet::from([near.hash, far_note.hash])
    );
    let report = result.anonymous.unwrap();
    assert_eq!(report.used_addresses, far + 1);
    let inbox_tag = |i: u32| {
        recipient
            .viewing_key
            .inbox_secret(i)
            .unwrap()
            .view_tag(0)
            .unwrap()
    };
    assert!(indexer.queried(&inbox_tag(far + ADDRESS_GAP)));
    assert!(!indexer.queried(&inbox_tag(far + ADDRESS_GAP + 1)));
}

#[test]
fn an_issued_count_is_scanned_whole_and_a_known_counterparty_from_the_start() {
    let recipient = keypair(1);
    let payer = keypair(2);
    let far = 2 * ADDRESS_GAP;
    let (far_tx, far_note) = inbox_payment(&payer, &recipient, far, 0, 20, 12);
    let pair_pk = payer
        .viewing_key
        .pair_key(&recipient.viewing_pubkey())
        .unwrap()
        .pubkey();
    let paired = note(&recipient, 5, 13);
    let pair_tag = payer
        .viewing_key
        .pair_send_view_tag(&recipient.viewing_pubkey(), 0)
        .unwrap();
    let tx_key = keypair(13).viewing_key;
    let pair_tx = transaction(
        &tx_key,
        13,
        vec![[13; 32]],
        vec![anonymous_slot(
            &payer.viewing_key,
            &tx_key,
            recipient.viewing_pubkey(),
            &paired,
            pair_tag,
            0,
        )],
    );
    let indexer = Indexer {
        tagged: vec![far_tx, pair_tx],
        ..Indexer::default()
    };
    let assets = AssetRegistry::default();

    let fresh = UtxoScan::new(&recipient, &assets)
        .with_anonymous_ring(AnonymousRingState::default())
        .fetch(&indexer)
        .unwrap();
    assert!(found_hashes(&fresh).is_empty());

    let result = UtxoScan::new(&recipient, &assets)
        .with_anonymous_ring(AnonymousRingState {
            issued_addresses: far + 1,
            known_counterparties: HashSet::from([pair_pk]),
        })
        .fetch(&indexer)
        .unwrap();
    assert_eq!(
        found_hashes(&result),
        BTreeSet::from([far_note.hash, paired.hash])
    );
    let report = result.anonymous.unwrap();
    assert!(report.new_counterparties.is_empty());
    assert_eq!(report.pair_next.get(&pair_pk), Some(&1));
    assert_eq!(report.used_addresses, far + 1);
}

#[test]
fn a_first_contact_opens_the_pair_stream_in_the_same_scan() {
    let recipient = keypair(1);
    let payer = keypair(2);
    let (inbox_tx, first) = inbox_payment(&payer, &recipient, 0, 0, 10, 11);
    let pair_pk = payer
        .viewing_key
        .pair_key(&recipient.viewing_pubkey())
        .unwrap()
        .pubkey();
    let later = note(&recipient, 7, 14);
    let pair_tag = payer
        .viewing_key
        .pair_send_view_tag(&recipient.viewing_pubkey(), 0)
        .unwrap();
    let tx_key = keypair(14).viewing_key;
    let pair_tx = transaction(
        &tx_key,
        14,
        vec![[14; 32]],
        vec![anonymous_slot(
            &payer.viewing_key,
            &tx_key,
            recipient.viewing_pubkey(),
            &later,
            pair_tag,
            0,
        )],
    );
    let indexer = Indexer {
        tagged: vec![inbox_tx, pair_tx],
        ..Indexer::default()
    };
    let assets = AssetRegistry::default();
    let result = UtxoScan::new(&recipient, &assets)
        .with_anonymous_ring(AnonymousRingState::default())
        .fetch(&indexer)
        .unwrap();

    assert_eq!(
        found_hashes(&result),
        BTreeSet::from([first.hash, later.hash])
    );
    let report = result.anonymous.unwrap();
    assert_eq!(report.new_counterparties, HashSet::from([pair_pk]));
    assert_eq!(report.pair_next.get(&pair_pk), Some(&1));
    let streams: BTreeSet<_> = report
        .notes
        .iter()
        .map(|note| format!("{:?}", note.stream))
        .collect();
    assert_eq!(
        streams,
        BTreeSet::from([
            format!("{:?}", AnonymousStream::Inbox { address_index: 0 }),
            format!(
                "{:?}",
                AnonymousStream::Pair {
                    counterparty: pair_pk
                }
            ),
        ])
    );
}

#[test]
fn a_slot_under_a_tag_the_wallet_did_not_derive_is_never_decrypted() {
    let recipient = keypair(1);
    let payer = keypair(2);
    let (mut tx, first) = inbox_payment(&payer, &recipient, 0, 0, 10, 11);
    let foreign = note(&recipient, 99, 15);
    let tx_key = keypair(11).viewing_key;
    tx.output_slots.push(anonymous_slot(
        &payer.viewing_key,
        &tx_key,
        recipient.viewing_pubkey(),
        &foreign,
        [9; 32],
        1,
    ));
    let indexer = Indexer {
        tagged: vec![tx],
        ..Indexer::default()
    };
    let assets = AssetRegistry::default();
    let keys = CountingKeys {
        owner: &recipient,
        decrypted_under: RefCell::new(Vec::new()),
    };
    let result = UtxoScan::new(&keys, &assets)
        .with_anonymous_ring(AnonymousRingState::default())
        .fetch(&indexer)
        .unwrap();

    assert_eq!(found_hashes(&result), BTreeSet::from([first.hash]));
    assert_eq!(*keys.decrypted_under.borrow(), [recipient.viewing_pubkey()]);
    assert!(!indexer.queried(&[9; 32]));
}

#[test]
fn without_a_state_no_anonymous_stream_is_read() {
    let recipient = keypair(1);
    let (tx, _) = inbox_payment(&keypair(2), &recipient, 0, 0, 10, 11);
    let indexer = Indexer {
        tagged: vec![tx],
        ..Indexer::default()
    };
    let assets = AssetRegistry::default();
    let result = UtxoScan::new(&recipient, &assets).fetch(&indexer).unwrap();
    assert!(result.anonymous.is_none());
    assert!(found_hashes(&result).is_empty());
    assert_eq!(indexer.queried_tags.borrow().len(), 1);
}
