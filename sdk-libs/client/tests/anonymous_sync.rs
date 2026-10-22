//! `AnonymousRingSync` and `TagAllocation` against an in-memory indexer.

use std::{
    collections::{BTreeSet, HashMap, HashSet},
    ops::RangeInclusive,
    sync::Mutex,
};

use async_trait::async_trait;
use custom_ring_interface::{
    stream::{
        DeliveredSlot, InboxKey, PairKey, RingTag, SlotSecret, TagIndex, EPOCH_SLOTS, J_INBOX,
        TAG_LEN,
    },
    RingDepositAuditCapsule, RING_DELIVERED_BODY_LEN,
};
use rand_core::{OsRng, UnwrapErr};
use solana_address::Address;
use solana_signature::Signature;
use zolana_client::{
    rpc::GetShieldedTransactionsByNullifiersResponse, AnonymousRingState, AnonymousRingSync,
    AnonymousStream, AsyncRpc, ClientError, Context, DecoyLeaf, EncryptedUtxoMatch,
    GetEncryptedUtxosByTagsResponse, GetShieldedTransactionsByTagsResponse, IndexerRpcConfig,
    OutputContext, OutputSlot, PairAnchor, PaymentStream, SentFirstContact, ShieldedTransaction,
    TagAllocation, ADDRESS_GAP, ANCHOR_DECOYS, ANONYMOUS_RING_STATE_VERSION, DECOYS_PER_TREE,
    DEPOSIT_GAP, PAIR_IDLE_EPOCHS,
};
use zolana_event::{
    encode_encrypted_ring_deposit_output, encode_merge_output_data, EncryptedRingDepositData,
    EncryptedRingDepositOutput, MergeOutputDataRef, OutputDataEncoding,
};
use zolana_keypair::{
    Pairing, PairingRow, RingAddress, ShieldedAddress, ShieldedKeypair, SigningKey, ViewingKey,
    X25519Pubkey,
};
use zolana_ring_policy::ring_id_field;
use zolana_transaction::{
    instructions::merge::{merge_output_blinding, merge_output_key, MergeOutputPlaintext},
    owner_utxo_hash,
    serialization::{ring_deposit::RingDepositPlaintext, RingDeliveredBody, RingDeliverySlot},
    AssetRegistry, DecryptRequest, DeriveRequest, EncryptedScheme, LocalShieldedKeys, Mint,
    RingDeliveryRequest, ShieldedKeys, TransactionError, TransactionKeyRequest, Utxo, WalletUtxo,
    REDACTED,
};

const RING: Address = Address::new_from_array([4; 32]);
const OTHER_RING: Address = Address::new_from_array([5; 32]);
const TREE: u16 = 2;
const SALT: [u8; 16] = [7; 16];
const CREATION: u64 = 100;

fn keypair(seed: u8) -> ShieldedKeypair {
    ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[seed; 32])).unwrap()
}

fn slot_of(epoch: u64) -> u64 {
    epoch * EPOCH_SLOTS + 17
}

/// A canonical field value distinct per `seed`.
fn nullifier(seed: u64) -> [u8; 32] {
    let mut value = [0x11; 32];
    value[24..].copy_from_slice(&seed.to_be_bytes());
    value
}

fn ring_id() -> [u8; 32] {
    ring_id_field(RING.as_array()).unwrap()
}

fn address_key(wallet: &ShieldedKeypair, index: u32) -> X25519Pubkey {
    wallet
        .viewing_key
        .ring_address_key(&RING, index)
        .unwrap()
        .pubkey()
}

fn inbox_tag(recipient: X25519Pubkey, epoch: u64, index: u8) -> RingTag {
    InboxKey::derive(&ring_id(), recipient.as_bytes())
        .unwrap()
        .tag(epoch, TagIndex::new(index).unwrap())
        .unwrap()
}

struct Payment {
    owner: ShieldedAddress,
    /// The key the body is delivered to.
    recipient: X25519Pubkey,
    tag: RingTag,
    amount: u64,
}

/// Keys each output as the ring rails do.
struct RingTransfer<'a> {
    sender: &'a ShieldedKeypair,
    nullifiers: Vec<[u8; 32]>,
    payments: Vec<Payment>,
    slot: u64,
    leaf: u64,
}

struct Delivered {
    utxo_hash: [u8; 32],
    blinding: [u8; 32],
    slot_secret: SlotSecret,
}

impl RingTransfer<'_> {
    fn build(&self) -> (ShieldedTransaction, Vec<Delivered>) {
        let first_nullifier = self.nullifiers[0];
        let tx = self
            .sender
            .viewing_key
            .get_transaction_viewing_key(&first_nullifier)
            .unwrap();
        let mut output_slots = Vec::new();
        let mut delivered = Vec::new();
        for (index, payment) in self.payments.iter().enumerate() {
            let output_index = index as u32;
            let slot_secret = DeliveredSlot {
                agreement: &tx.ecdh(&payment.recipient).unwrap(),
                tx_viewing_pk: tx.pubkey().as_bytes(),
                recipient_viewing_pk: payment.recipient.as_bytes(),
                salt: &SALT,
                output_index,
                first_nullifier: &first_nullifier,
            }
            .secret()
            .unwrap();
            let blinding = RingDeliverySlot {
                ring: RING,
                first_nullifier,
                output_index,
                tag: Some(payment.tag),
            }
            .blinding(&slot_secret)
            .unwrap();
            let utxo = Utxo {
                owner: payment.owner.signing_pubkey,
                asset: Mint::SOL,
                amount: payment.amount,
                blinding,
                ring_program_id: Some(RING),
                data: Default::default(),
            };
            let utxo_hash = utxo
                .hash(&payment.owner.nullifier_pubkey, &[0; 32], &[0; 32], TREE)
                .unwrap();
            let body = RingDeliveredBody {
                asset_address: Mint::SOL.asset,
                amount: payment.amount,
            }
            .seal(&slot_secret)
            .unwrap();
            output_slots.push(OutputSlot {
                view_tag: payment.tag.field(),
                output_context: OutputContext {
                    hash: utxo_hash,
                    tree_id: TREE,
                    leaf_index: self.leaf + u64::from(output_index),
                },
                payload: borsh::to_vec(&OutputDataEncoding::Encrypted(
                    [&[EncryptedScheme::RingAnonymous.as_byte()][..], &body].concat(),
                ))
                .unwrap(),
            });
            delivered.push(Delivered {
                utxo_hash,
                blinding,
                slot_secret,
            });
        }
        let transaction = ShieldedTransaction {
            slot: self.slot,
            tx_signature: Signature::from([self.leaf as u8 + 1; 64]),
            event_index: Some(0),
            tx_viewing_pk: Some(tx.pubkey()),
            salt: Some(SALT),
            output_slots,
            messages: Vec::new(),
            nullifiers: self.nullifiers.clone(),
            proofless: false,
            ring_config: None,
            ring_program_id: Some(RING),
        };
        (transaction, delivered)
    }
}

#[derive(Default)]
struct Indexer {
    transactions: Mutex<Vec<ShieldedTransaction>>,
    deposits: Mutex<Vec<EncryptedUtxoMatch>>,
    /// The slot every answer reports persisted, `None` once caught up.
    persisted: Mutex<Option<u64>>,
    tag_requests: Mutex<Vec<Vec<[u8; 32]>>>,
    nullifier_requests: Mutex<Vec<Vec<[u8; 32]>>>,
}

impl Indexer {
    fn publish(&self, transaction: ShieldedTransaction) {
        self.transactions.lock().unwrap().push(transaction);
    }

    fn context(&self) -> Context {
        Context {
            block_time: 0,
            slot: self.persisted.lock().unwrap().unwrap_or(u64::MAX),
        }
    }
}

#[async_trait]
impl AsyncRpc for Indexer {
    async fn get_shielded_transactions_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        _cursor: Option<Vec<u8>>,
        _limit: Option<u32>,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        self.tag_requests.lock().unwrap().push(tags.clone());
        let transactions = self.transactions.lock().unwrap();
        Ok(GetShieldedTransactionsByTagsResponse {
            context: self.context(),
            output_tree_id: Some(TREE),
            transactions: transactions
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

    async fn get_encrypted_utxos_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        _cursor: Option<Vec<u8>>,
        _limit: Option<u32>,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetEncryptedUtxosByTagsResponse, ClientError> {
        Ok(GetEncryptedUtxosByTagsResponse {
            context: self.context(),
            output_tree_id: Some(TREE),
            matches: self
                .deposits
                .lock()
                .unwrap()
                .iter()
                .filter(|deposit| tags.contains(&deposit.output_slot.view_tag))
                .cloned()
                .collect(),
            next_cursor: None,
            scanned_through: None,
        })
    }

    async fn get_shielded_transactions_by_nullifiers(
        &self,
        nullifiers: Vec<[u8; 32]>,
        _cursor: Option<Vec<u8>>,
        _limit: Option<u32>,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByNullifiersResponse, ClientError> {
        self.nullifier_requests
            .lock()
            .unwrap()
            .push(nullifiers.clone());
        let transactions = self.transactions.lock().unwrap();
        Ok(GetShieldedTransactionsByNullifiersResponse {
            context: self.context(),
            output_tree_id: Some(TREE),
            transactions: transactions
                .iter()
                .filter(|tx| tx.nullifiers.iter().any(|n| nullifiers.contains(n)))
                .cloned()
                .collect(),
            next_cursor: None,
            scanned_through: None,
        })
    }
}

struct Fixture {
    recipient: ShieldedKeypair,
    sender: ShieldedKeypair,
    indexer: Indexer,
}

impl Fixture {
    fn new() -> Self {
        Self {
            recipient: keypair(1),
            sender: keypair(2),
            indexer: Indexer::default(),
        }
    }

    fn recipient_owner(&self) -> ShieldedAddress {
        self.recipient.shielded_address().unwrap()
    }

    /// The recipient's ring address at `index`, admitting every first contact.
    fn address(&self, index: u32) -> RingAddress {
        RingAddress {
            recipient: ShieldedAddress {
                viewing_pubkey: address_key(&self.recipient, index),
                ..self.recipient_owner()
            },
            ring_program_id: RING,
            pairing: Pairing::default(),
        }
    }

    /// A first contact from `sender` at `tag_index` of address 0's inbox stream.
    fn inbox_payment(
        &self,
        sender: &ShieldedKeypair,
        epoch: u64,
        tag_index: u8,
        amount: u64,
        leaf: u64,
    ) -> Delivered {
        let recipient = address_key(&self.recipient, 0);
        let (tx, mut delivered) = RingTransfer {
            sender,
            nullifiers: vec![nullifier(leaf)],
            payments: vec![Payment {
                owner: self.recipient_owner(),
                recipient,
                tag: inbox_tag(recipient, epoch, tag_index),
                amount,
            }],
            slot: slot_of(epoch),
            leaf,
        }
        .build();
        self.indexer.publish(tx);
        delivered.remove(0)
    }

    fn pair_payment(
        &self,
        first_contact: &SlotSecret,
        epoch: u64,
        amount: u64,
        leaf: u64,
    ) -> Delivered {
        let pair = PairKey::derive(first_contact).unwrap();
        let (tx, mut delivered) = RingTransfer {
            sender: &self.sender,
            nullifiers: vec![nullifier(leaf)],
            payments: vec![Payment {
                owner: self.recipient_owner(),
                recipient: address_key(&self.recipient, 0),
                tag: pair.tag(epoch, TagIndex::new(0).unwrap()).unwrap(),
                amount,
            }],
            slot: slot_of(epoch),
            leaf,
        }
        .build();
        self.indexer.publish(tx);
        delivered.remove(0)
    }

    fn change_from(&self, utxo: &Delivered, epoch: u64, amount: u64, leaf: u64) -> Delivered {
        let nullifier = self
            .recipient
            .nullifier(&utxo.utxo_hash, &utxo.blinding)
            .unwrap();
        let change_key = self
            .recipient
            .viewing_key
            .ring_change_key(&RING)
            .unwrap()
            .pubkey();
        let (tx, mut delivered) = RingTransfer {
            sender: &self.recipient,
            nullifiers: vec![nullifier],
            payments: vec![Payment {
                owner: self.recipient_owner(),
                recipient: change_key,
                tag: RingTag::from_bytes([0x5c; TAG_LEN]),
                amount,
            }],
            slot: slot_of(epoch),
            leaf,
        }
        .build();
        self.indexer.publish(tx);
        delivered.remove(0)
    }

    /// The recipient's merge of `merge.notes`, tagged by its first nullifier as a ring merge is.
    fn merge(&self, merge: Merge<'_>) -> Merged {
        let nullifiers: Vec<[u8; 32]> = merge
            .utxos
            .iter()
            .map(|utxo| {
                self.recipient
                    .nullifier(&utxo.utxo_hash, &utxo.blinding)
                    .unwrap()
            })
            .collect();
        let first = nullifiers[0];
        let owner = self.recipient_owner();
        let nullifier_key = &self.recipient.nullifier_key;
        let utxo = Utxo {
            owner: owner.signing_pubkey,
            asset: Mint::SOL,
            amount: merge.amount,
            blinding: merge_output_blinding(nullifier_key, &first).unwrap(),
            ring_program_id: Some(RING),
            data: Default::default(),
        };
        let utxo_hash = utxo
            .hash(&owner.nullifier_pubkey, &[0; 32], &[0; 32], TREE)
            .unwrap();
        let salt = [merge.leaf as u8; 16];
        let ciphertext = MergeOutputPlaintext {
            amount: merge.amount,
            mint: Mint::SOL.asset,
        }
        .encrypt(&merge_output_key(nullifier_key, &first).unwrap(), &salt)
        .unwrap();
        self.indexer.publish(ShieldedTransaction {
            slot: slot_of(merge.epoch),
            tx_signature: Signature::from([merge.leaf as u8 + 1; 64]),
            event_index: Some(0),
            tx_viewing_pk: None,
            salt: None,
            output_slots: vec![OutputSlot {
                view_tag: first,
                output_context: OutputContext {
                    hash: utxo_hash,
                    tree_id: TREE,
                    leaf_index: merge.leaf,
                },
                payload: encode_merge_output_data(MergeOutputDataRef {
                    salt: &salt,
                    ciphertext: &ciphertext,
                    ring_data_hash: Some(&[0; 32]),
                }),
            }],
            messages: Vec::new(),
            nullifiers,
            proofless: false,
            ring_config: None,
            ring_program_id: Some(RING),
        });
        Merged {
            utxo_hash,
            first_nullifier: first,
        }
    }

    fn state(&self) -> AnonymousRingState {
        let mut state = AnonymousRingState::new(RING, CREATION);
        state.issue(0, Pairing::default()).unwrap();
        state
    }

    /// A ring deposit to the recipient under its deposit tag at `counter`.
    fn deposit(&self, deposit: Deposit) -> Signature {
        let row = self.deposit_row(&deposit);
        let tx_signature = row.tx_signature;
        self.indexer.deposits.lock().unwrap().push(row);
        tx_signature
    }

    /// The row an indexer serves for `deposit`, its hash the deposit's commitment.
    fn deposit_row(&self, deposit: &Deposit) -> EncryptedUtxoMatch {
        let address = self.recipient_owner();
        let tag = self.deposit_tag(deposit.counter);
        let encrypted = RingDepositPlaintext {
            blinding: deposit.blinding,
            utxo_data: None,
            memo: None,
            ring_data: Vec::new(),
        }
        .encrypt(&address.viewing_pubkey)
        .unwrap();
        let ciphertext = match deposit.framing {
            Framing::Capsule => RingDepositAuditCapsule {
                slot_index: 0,
                eph_pk: &[2; 33],
                ciphertext: &[0; 96],
                recipient_ciphertext: &encrypted.ciphertext,
            }
            .encode(),
            Framing::Truncated => b"CRDEP001".to_vec(),
        };
        let owner_hash = address.owner_hash().unwrap();
        let payload = encode_encrypted_ring_deposit_output(EncryptedRingDepositOutput {
            owner_utxo_hash: owner_utxo_hash(&owner_hash, &deposit.blinding).unwrap_or([0x0e; 32]),
            asset: Mint::SOL.asset.to_bytes(),
            amount: 25,
            data_hash: None,
            ring_program_id: deposit.ring.to_bytes(),
            ring_data_hash: [0; 32],
            encrypted: EncryptedRingDepositData {
                ciphertext,
                ..encrypted
            },
        });
        let hash = Utxo {
            owner: address.signing_pubkey,
            asset: Mint::SOL,
            amount: 25,
            blinding: deposit.blinding,
            ring_program_id: Some(deposit.ring),
            data: Default::default(),
        }
        .hash(&address.nullifier_pubkey, &[0; 32], &[0; 32], TREE)
        .unwrap_or(nullifier(500 + deposit.counter));
        EncryptedUtxoMatch {
            slot: slot_of(CREATION),
            tx_signature: Signature::from([(deposit.counter as u8).wrapping_add(0xd0); 64]),
            output_slot: OutputSlot {
                view_tag: tag,
                output_context: OutputContext {
                    hash,
                    tree_id: TREE,
                    leaf_index: 500 + deposit.counter,
                },
                payload,
            },
            tx_viewing_pk: None,
            salt: None,
        }
    }

    fn deposit_tag(&self, counter: u64) -> [u8; 32] {
        self.recipient.sender_view_tags(&[counter]).unwrap()[0]
    }
}

struct Merge<'a> {
    utxos: &'a [&'a Delivered],
    amount: u64,
    epoch: u64,
    leaf: u64,
}

struct Merged {
    utxo_hash: [u8; 32],
    first_nullifier: [u8; 32],
}

struct Deposit {
    counter: u64,
    blinding: [u8; 32],
    framing: Framing,
    ring: Address,
}

/// How the recipient ciphertext sits in the ring's audit capsule.
enum Framing {
    Capsule,
    /// The capsule magic alone.
    Truncated,
}

fn found(scan: &zolana_client::AnonymousRingScan, utxo_hash: [u8; 32]) -> AnonymousStream {
    scan.utxos
        .iter()
        .find(|utxo| utxo.utxo_hash == utxo_hash)
        .map(|utxo| utxo.stream)
        .unwrap_or_else(|| panic!("note {utxo_hash:?} not found"))
}

#[tokio::test]
async fn anonymous_sync_finds_inbox_pair_and_change() {
    let fixture = Fixture::new();
    let first = fixture.inbox_payment(&fixture.sender, CREATION, 0, 70, 10);
    let paired = fixture.pair_payment(&first.slot_secret, CREATION + 1, 30, 20);
    let change = fixture.change_from(&first, CREATION + 1, 50, 30);
    let assets = AssetRegistry::default();
    let scan = AnonymousRingSync::new(&fixture.recipient, &assets)
        .fetch(&fixture.indexer, &fixture.state(), slot_of(CREATION + 2))
        .await
        .unwrap();
    assert!(matches!(
        found(&scan, first.utxo_hash),
        AnonymousStream::Inbox {
            address_index: 0,
            epoch: CREATION,
            ..
        }
    ));
    assert!(matches!(
        found(&scan, paired.utxo_hash),
        AnonymousStream::Pair { address_index: 0, epoch, .. } if epoch == CREATION + 1
    ));
    assert!(matches!(
        found(&scan, change.utxo_hash),
        AnonymousStream::Change { .. }
    ));
    assert_eq!(scan.anchors.len(), 1);
    assert_eq!(
        scan.anchors[0].pair_key,
        *PairKey::derive(&first.slot_secret).unwrap().as_bytes()
    );
    assert_eq!(scan.state.scanned_epoch(), Some(CREATION));
    let spendable =
        zolana_transaction::verify_spendable(&fixture.recipient, &scan.decrypted).unwrap();
    let held: Vec<[u8; 32]> = spendable.utxos().map(|utxo| utxo.utxo_hash).collect();
    assert!(
        !held.contains(&first.utxo_hash),
        "the spent first contact stays out"
    );
    assert!(held.contains(&paired.utxo_hash) && held.contains(&change.utxo_hash));
}

/// A transaction the first round read for its inbox slot still opens its pair slot in the second.
#[tokio::test]
async fn one_transaction_paying_a_pair_and_an_inbox_slot_opens_both() {
    let fixture = Fixture::new();
    let first = fixture.inbox_payment(&fixture.sender, CREATION, 0, 70, 10);
    let pair = PairKey::derive(&first.slot_secret).unwrap();
    let address_1 = address_key(&fixture.recipient, 1);
    let (tx, delivered) = RingTransfer {
        sender: &fixture.sender,
        nullifiers: vec![nullifier(20)],
        payments: vec![
            Payment {
                owner: fixture.recipient_owner(),
                recipient: address_key(&fixture.recipient, 0),
                tag: pair.tag(CREATION + 1, TagIndex::new(0).unwrap()).unwrap(),
                amount: 30,
            },
            Payment {
                owner: fixture.recipient_owner(),
                recipient: address_1,
                tag: inbox_tag(address_1, CREATION + 1, 0),
                amount: 40,
            },
        ],
        slot: slot_of(CREATION + 1),
        leaf: 20,
    }
    .build();
    fixture.indexer.publish(tx);
    let assets = AssetRegistry::default();
    let scan = AnonymousRingSync::new(&fixture.recipient, &assets)
        .fetch(&fixture.indexer, &fixture.state(), slot_of(CREATION + 2))
        .await
        .unwrap();
    assert!(matches!(
        found(&scan, delivered[0].utxo_hash),
        AnonymousStream::Pair {
            address_index: 0,
            ..
        }
    ));
    assert!(matches!(
        found(&scan, delivered[1].utxo_hash),
        AnonymousStream::Inbox {
            address_index: 1,
            ..
        }
    ));
    let held = |utxo_hash| {
        scan.decrypted
            .utxos
            .iter()
            .filter(|utxo| utxo.utxo_hash == utxo_hash)
            .count()
    };
    assert_eq!(
        (held(delivered[0].utxo_hash), held(delivered[1].utxo_hash)),
        (1, 1)
    );
}

/// Only an indexer serves a first nullifier at or above the field modulus.
#[tokio::test]
async fn a_first_nullifier_off_the_field_under_the_wallet_tag_is_skipped() {
    let fixture = Fixture::new();
    let first = fixture.inbox_payment(&fixture.sender, CREATION, 0, 70, 10);
    let mut poisoned = fixture.indexer.transactions.lock().unwrap()[0].clone();
    poisoned.tx_signature = Signature::from([0xee; 64]);
    poisoned.nullifiers[0] = [0xff; 32];
    fixture.indexer.publish(poisoned);
    let assets = AssetRegistry::default();
    let scan = AnonymousRingSync::new(&fixture.recipient, &assets)
        .fetch(&fixture.indexer, &fixture.state(), slot_of(CREATION + 2))
        .await
        .unwrap();
    assert!(matches!(
        found(&scan, first.utxo_hash),
        AnonymousStream::Inbox { .. }
    ));
    assert_eq!(scan.utxos.len(), 1);
}

/// A merge spends the wallet's notes, the next sync opens its output from that spend.
#[tokio::test]
async fn a_merge_of_the_wallets_utxos_is_found_by_the_next_sync() {
    let fixture = Fixture::new();
    let first = fixture.inbox_payment(&fixture.sender, CREATION, 0, 70, 10);
    let second = fixture.inbox_payment(&fixture.sender, CREATION, 1, 30, 20);
    let assets = AssetRegistry::default();
    let held = AnonymousRingSync::new(&fixture.recipient, &assets)
        .fetch(&fixture.indexer, &fixture.state(), slot_of(CREATION + 2))
        .await
        .unwrap();
    let merged = fixture.merge(Merge {
        utxos: &[&first, &second],
        amount: 100,
        epoch: CREATION + 2,
        leaf: 40,
    });
    let next = AnonymousRingSync::new(&fixture.recipient, &assets)
        .with_held_utxos(&held.decrypted.utxos)
        .fetch(&fixture.indexer, &held.state, slot_of(CREATION + 3))
        .await
        .unwrap();
    assert_eq!(
        found(&next, merged.utxo_hash),
        AnonymousStream::Merge {
            first_nullifier: merged.first_nullifier
        }
    );
    let spendable =
        zolana_transaction::verify_spendable(&fixture.recipient, &next.decrypted).unwrap();
    let unspent: Vec<[u8; 32]> = spendable.utxos().map(|utxo| utxo.utxo_hash).collect();
    assert_eq!(unspent, [merged.utxo_hash]);
}

/// An epoch the indexer has not persisted past stays unscanned, its late payment found next time.
#[tokio::test]
async fn a_lagging_indexer_leaves_its_unpersisted_epochs_to_the_next_sync() {
    let fixture = Fixture::new();
    *fixture.indexer.persisted.lock().unwrap() = Some(slot_of(CREATION + 2));
    let assets = AssetRegistry::default();
    let sync = AnonymousRingSync::new(&fixture.recipient, &assets);
    let lagging = sync
        .fetch(&fixture.indexer, &fixture.state(), slot_of(CREATION + 5))
        .await
        .unwrap();
    assert_eq!(lagging.state.scanned_epoch(), Some(CREATION));
    let late = fixture.inbox_payment(&fixture.sender, CREATION + 2, 0, 40, 10);
    *fixture.indexer.persisted.lock().unwrap() = None;
    let caught_up = sync
        .fetch(&fixture.indexer, &lagging.state, slot_of(CREATION + 5))
        .await
        .unwrap();
    found(&caught_up, late.utxo_hash);
    assert_eq!(caught_up.state.scanned_epoch(), Some(CREATION + 3));
}

/// A transfer proven in the epoch before the open one lands after the sync under its tags.
#[tokio::test]
async fn a_payment_landing_under_the_previous_epoch_is_found_next_time() {
    let fixture = Fixture::new();
    let assets = AssetRegistry::default();
    let sync = AnonymousRingSync::new(&fixture.recipient, &assets);
    let first = sync
        .fetch(&fixture.indexer, &fixture.state(), slot_of(CREATION + 2))
        .await
        .unwrap();
    let landed = fixture.inbox_payment(&fixture.sender, CREATION + 1, 0, 40, 10);
    let next = sync
        .fetch(&fixture.indexer, &first.state, slot_of(CREATION + 2))
        .await
        .unwrap();
    found(&next, landed.utxo_hash);
}

/// Any sender can publish under the wallet's tag, a body off the delivered length opens nothing.
#[tokio::test]
async fn a_body_off_the_delivered_length_is_skipped() {
    let fixture = Fixture::new();
    let paid = fixture.inbox_payment(&fixture.sender, CREATION, 1, 70, 10);
    let recipient = address_key(&fixture.recipient, 0);
    let (mut malformed, _) = RingTransfer {
        sender: &fixture.sender,
        nullifiers: vec![nullifier(20)],
        payments: [0, 2]
            .map(|index| Payment {
                owner: fixture.recipient_owner(),
                recipient,
                tag: inbox_tag(recipient, CREATION, index),
                amount: 1,
            })
            .into(),
        slot: slot_of(CREATION),
        leaf: 20,
    }
    .build();
    let bodies = [
        (EncryptedScheme::RingAnonymous, RING_DELIVERED_BODY_LEN - 1),
        (
            EncryptedScheme::RingConfidentialDelivered,
            RING_DELIVERED_BODY_LEN + 1,
        ),
    ];
    for (slot, (scheme, len)) in malformed.output_slots.iter_mut().zip(bodies) {
        let body = [vec![scheme.as_byte()], vec![0x5b; len]].concat();
        slot.payload = borsh::to_vec(&OutputDataEncoding::Encrypted(body)).unwrap();
    }
    fixture.indexer.publish(malformed);
    let assets = AssetRegistry::default();
    let scan = AnonymousRingSync::new(&fixture.recipient, &assets)
        .fetch(&fixture.indexer, &fixture.state(), slot_of(CREATION + 1))
        .await
        .unwrap();
    found(&scan, paid.utxo_hash);
    assert_eq!(scan.utxos.len(), 1);
}

/// The deposit after a malformed capsule is still read.
#[tokio::test]
async fn a_malformed_deposit_capsule_is_skipped() {
    let fixture = Fixture::new();
    fixture.deposit(Deposit {
        counter: 0,
        blinding: nullifier(1),
        framing: Framing::Truncated,
        ring: RING,
    });
    let deposited = fixture.deposit(Deposit {
        counter: 1,
        blinding: nullifier(2),
        framing: Framing::Capsule,
        ring: RING,
    });
    let assets = AssetRegistry::default();
    let scan = AnonymousRingSync::new(&fixture.recipient, &assets)
        .fetch(&fixture.indexer, &fixture.state(), slot_of(CREATION + 1))
        .await
        .unwrap();
    let held: Vec<Signature> = scan
        .decrypted
        .utxos
        .iter()
        .map(|utxo| utxo.tx_signature)
        .collect();
    assert_eq!(held, [deposited]);
    assert_eq!(scan.state.deposit_next(), 2);
}

#[tokio::test]
async fn a_deposit_blinding_outside_the_field_is_skipped() {
    let fixture = Fixture::new();
    fixture.deposit(Deposit {
        counter: 0,
        blinding: [0xff; 32],
        framing: Framing::Capsule,
        ring: RING,
    });
    let deposited = fixture.deposit(Deposit {
        counter: 1,
        blinding: nullifier(2),
        framing: Framing::Capsule,
        ring: RING,
    });
    let assets = AssetRegistry::default();
    let scan = AnonymousRingSync::new(&fixture.recipient, &assets)
        .fetch(&fixture.indexer, &fixture.state(), slot_of(CREATION + 1))
        .await
        .unwrap();
    let held: Vec<Signature> = scan
        .decrypted
        .utxos
        .iter()
        .map(|utxo| utxo.tx_signature)
        .collect();
    assert_eq!(held, [deposited]);
    assert_eq!(scan.state.deposit_next(), 2);
}

/// A restore knows no issued address, each hit widens the gap window up to address 22.
#[tokio::test]
async fn a_restore_from_seed_finds_every_utxo_over_three_epochs() {
    let fixture = Fixture::new();
    let first = fixture.inbox_payment(&fixture.sender, CREATION, 5, 70, 10);
    let paired = fixture.pair_payment(&first.slot_secret, CREATION + 1, 30, 20);
    let change = fixture.change_from(&paired, CREATION + 2, 25, 30);
    let gap_payment = |index: u32, nullifier_seed: u64, leaf: u64| {
        let gap_key = address_key(&fixture.recipient, index);
        let (published, delivered) = RingTransfer {
            sender: &fixture.sender,
            nullifiers: vec![nullifier(nullifier_seed)],
            payments: vec![Payment {
                owner: fixture.recipient_owner(),
                recipient: gap_key,
                tag: inbox_tag(gap_key, CREATION + 2, 0),
                amount: 9,
            }],
            slot: slot_of(CREATION + 2),
            leaf,
        }
        .build();
        fixture.indexer.publish(published);
        delivered
    };
    let far_delivered = gap_payment(3, 99, 40);
    let farther_delivered = gap_payment(22, 98, 50);
    let assets = AssetRegistry::default();
    let scan = AnonymousRingSync::new(&fixture.recipient, &assets)
        .fetch(
            &fixture.indexer,
            &AnonymousRingState::new(RING, CREATION),
            slot_of(CREATION + 3),
        )
        .await
        .unwrap();
    for utxo in [
        &first,
        &paired,
        &change,
        &far_delivered[0],
        &farther_delivered[0],
    ] {
        found(&scan, utxo.utxo_hash);
    }
    let issued: Vec<u32> = scan
        .state
        .issued()
        .iter()
        .map(|issued| issued.index)
        .collect();
    assert_eq!(issued, [0, 3, 22]);
}

#[tokio::test]
async fn two_senders_on_one_inbox_tag_in_one_epoch_are_both_found() {
    let fixture = Fixture::new();
    let one = fixture.inbox_payment(&fixture.sender, CREATION, 0, 11, 10);
    let other = fixture.inbox_payment(&keypair(3), CREATION, 0, 12, 20);
    let assets = AssetRegistry::default();
    let scan = AnonymousRingSync::new(&fixture.recipient, &assets)
        .fetch(&fixture.indexer, &fixture.state(), slot_of(CREATION + 1))
        .await
        .unwrap();
    found(&scan, one.utxo_hash);
    found(&scan, other.utxo_hash);
}

/// The recipient reads no pair stream below its pairing rows, the sender pays its inbox instead.
#[tokio::test]
async fn a_first_contact_below_the_pairing_rows_anchors_no_pair_stream() {
    let fixture = Fixture::new();
    let first = fixture.inbox_payment(&fixture.sender, CREATION, 0, 50, 10);
    let rows = Pairing::new(vec![PairingRow {
        mint: Mint::SOL.asset,
        min_amount: 100,
    }])
    .unwrap();
    let mut state = AnonymousRingState::new(RING, CREATION);
    state.issue(0, rows.clone()).unwrap();
    let assets = AssetRegistry::default();
    let scan = AnonymousRingSync::new(&fixture.recipient, &assets)
        .fetch(&fixture.indexer, &state, slot_of(CREATION + 1))
        .await
        .unwrap();
    found(&scan, first.utxo_hash);
    assert!(scan.anchors.is_empty() && scan.state.received().is_empty());

    let address = RingAddress {
        recipient: ShieldedAddress {
            viewing_pubkey: address_key(&fixture.recipient, 0),
            ..fixture.recipient_owner()
        },
        ring_program_id: RING,
        pairing: rows,
    };
    let mut sender_state = AnonymousRingState::new(RING, CREATION);
    sender_state.record_first_contact(SentFirstContact {
        recipient: address.recipient.viewing_pubkey,
        tree_id: TREE,
        leaf_index: 10,
        utxo_hash: first.utxo_hash,
        slot_secret: *first.slot_secret.as_bytes(),
        first_nullifier: nullifier(10),
        slot_index: 0,
        epoch: CREATION,
        index: TagIndex::new(0).unwrap(),
        asset: Mint::SOL.asset,
        amount: 50,
    });
    let allocated = TagAllocation::new(&sender_state, CREATION + 1)
        .allocate(&address, &mut UnwrapErr(OsRng))
        .unwrap();
    assert_eq!(allocated.stream, PaymentStream::Inbox);
}

/// Anyone holding the address fills its inbox tags with cheap rows, no payment waits on them.
#[tokio::test]
async fn sixty_four_used_inbox_tags_refuse_no_payment() {
    let fixture = Fixture::new();
    for index in 0..J_INBOX {
        fixture.inbox_payment(&fixture.sender, CREATION, index, 1, 100 + u64::from(index));
    }
    let state = AnonymousRingState::new(RING, CREATION);
    let allocated = TagAllocation::new(&state, CREATION)
        .allocate(&fixture.address(0), &mut UnwrapErr(OsRng))
        .unwrap();
    assert_eq!(allocated.stream, PaymentStream::Inbox);
    assert_eq!(
        allocated.tag,
        inbox_tag(
            address_key(&fixture.recipient, 0),
            CREATION,
            allocated.index.get()
        )
    );
}

/// Holds the keys out of reach, every answer is one of the trait's per-request values.
struct RemoteKeys {
    holder: LocalShieldedKeys,
    calls: Mutex<Vec<&'static str>>,
}

impl RemoteKeys {
    fn record(&self, call: &'static str) {
        self.calls.lock().unwrap().push(call);
    }
}

impl ShieldedKeys for RemoteKeys {
    fn address(&self) -> Result<ShieldedAddress, TransactionError> {
        self.holder.address()
    }
    fn viewing_public_keys(&self) -> Vec<X25519Pubkey> {
        self.holder.viewing_public_keys()
    }
    fn decrypt(&self, requests: &[DecryptRequest<'_>]) -> Result<Vec<Vec<u8>>, TransactionError> {
        self.record("decrypt");
        self.holder.decrypt(requests)
    }
    fn derive(&self, requests: &[DeriveRequest]) -> Result<Vec<[u8; 32]>, TransactionError> {
        self.record("derive");
        self.holder.derive(requests)
    }
    fn transaction_keys(
        &self,
        requests: &[TransactionKeyRequest],
    ) -> Result<Vec<ViewingKey>, TransactionError> {
        self.record("transaction_keys");
        self.holder.transaction_keys(requests)
    }
    fn ring_address_keys(
        &self,
        ring: &Address,
        indexes: &[u32],
    ) -> Result<Vec<X25519Pubkey>, TransactionError> {
        self.record("ring_address_keys");
        self.holder.ring_address_keys(ring, indexes)
    }
    fn ring_delivery_secrets(
        &self,
        requests: &[RingDeliveryRequest],
    ) -> Result<Vec<[u8; 32]>, TransactionError> {
        self.record("ring_delivery_secrets");
        self.holder.ring_delivery_secrets(requests)
    }
    fn ring_change_key(&self, ring: &Address) -> Result<X25519Pubkey, TransactionError> {
        self.record("ring_change_key");
        self.holder.ring_change_key(ring)
    }
    fn sender_view_tags(&self, counters: &[u64]) -> Result<Vec<[u8; 32]>, TransactionError> {
        self.record("sender_view_tags");
        self.holder.sender_view_tags(counters)
    }
}

/// Any holder of the address publishes under its inbox tags.
#[tokio::test]
async fn a_slot_without_an_anonymous_body_asks_the_key_holder_nothing() {
    let fixture = Fixture::new();
    fixture.inbox_payment(&fixture.sender, CREATION, 0, 70, 10);
    {
        let mut published = fixture.indexer.transactions.lock().unwrap();
        published[0].output_slots[0].payload =
            borsh::to_vec(&OutputDataEncoding::Encrypted(vec![3, 1, 2, 3])).unwrap();
    }
    let keys = RemoteKeys {
        holder: LocalShieldedKeys::from_keypair(&fixture.recipient).unwrap(),
        calls: Mutex::new(Vec::new()),
    };
    let assets = AssetRegistry::default();
    let scan = AnonymousRingSync::new(&keys, &assets)
        .fetch(&fixture.indexer, &fixture.state(), slot_of(CREATION + 2))
        .await
        .unwrap();
    assert!(scan.utxos.is_empty());
    assert!(!keys
        .calls
        .lock()
        .unwrap()
        .contains(&"ring_delivery_secrets"));
}

#[tokio::test]
async fn a_remote_holder_that_never_exports_a_viewing_secret_completes_the_sync() {
    let fixture = Fixture::new();
    let first = fixture.inbox_payment(&fixture.sender, CREATION, 0, 70, 10);
    let paired = fixture.pair_payment(&first.slot_secret, CREATION, 30, 20);
    let change = fixture.change_from(&paired, CREATION, 10, 30);
    let remote = RemoteKeys {
        holder: LocalShieldedKeys::from_keypair(&fixture.recipient).unwrap(),
        calls: Mutex::new(Vec::new()),
    };
    let assets = AssetRegistry::default();
    let scan = AnonymousRingSync::new(&remote, &assets)
        .fetch(&fixture.indexer, &fixture.state(), slot_of(CREATION + 1))
        .await
        .unwrap();
    for utxo in [&first, &paired, &change] {
        found(&scan, utxo.utxo_hash);
    }
    let calls = remote.calls.lock().unwrap();
    for needed in [
        "ring_address_keys",
        "ring_delivery_secrets",
        "ring_change_key",
        "transaction_keys",
    ] {
        assert!(calls.contains(&needed), "{needed} carries the sync");
    }
}

#[test]
fn a_store_of_another_version_rescans_and_a_v1_count_migrates_to_issued_addresses() {
    let fixture = Fixture::new();
    let mut state = fixture.state();
    state.issue(4, Pairing::off()).unwrap();
    let restored = AnonymousRingState::from_json(&state.to_json()).unwrap();
    assert_eq!(restored, state);
    let older = state.to_json().replace(
        &format!("\"version\":{ANONYMOUS_RING_STATE_VERSION}"),
        "\"version\":1",
    );
    assert!(matches!(
        AnonymousRingState::from_json(&older),
        Err(ClientError::AnonymousRingStateVersion { version: 1 })
    ));
    let migrated = AnonymousRingState::migrate_v1(RING, CREATION, 3).unwrap();
    let issued: Vec<u32> = migrated
        .issued()
        .iter()
        .map(|issued| issued.index)
        .collect();
    assert_eq!((issued, migrated.scanned_epoch()), (vec![0, 1, 2], None));
}

/// Slot secrets and pair keys link payments, neither a print nor a parse error shows one.
#[test]
fn a_state_prints_and_refuses_without_its_secrets() {
    let secret: [u8; 32] = core::array::from_fn(|i| 0xa0 + i as u8);
    let contact = SentFirstContact {
        recipient: address_key(&keypair(3), 0),
        tree_id: TREE,
        leaf_index: 1,
        utxo_hash: nullifier(1),
        slot_secret: secret,
        first_nullifier: nullifier(2),
        slot_index: 0,
        epoch: CREATION,
        index: TagIndex::new(0).unwrap(),
        asset: Mint::SOL.asset,
        amount: 1,
    };
    let mut state = Fixture::new().state();
    state.record_first_contact(contact);
    let anchor = zolana_client::ReceivedAnchor {
        address_index: 0,
        pair_key: secret,
        epoch: CREATION,
        last_epoch: CREATION,
        asset: Mint::SOL.asset,
        amount: 1,
    };
    let printed = format!("{contact:?} {anchor:?} {state:?} {state:#?}");
    for form in [format!("{:?}", &secret[..2]), hex::encode(&secret[..2])] {
        let form = form.trim_matches(['[', ']']);
        assert!(!printed.contains(form), "{printed}");
    }
    let text = hex::encode(&secret[..31]);
    let json: serde_json::Value = serde_json::from_str(&state.to_json()).unwrap();
    for field in ["slotSecret", "epoch"] {
        let mut corrupt = json.clone();
        corrupt["sent"][0][field] = text.clone().into();
        let error = AnonymousRingState::from_json(&corrupt.to_string())
            .unwrap_err()
            .to_string();
        assert!(!error.contains(&text), "{error}");
    }
    // A stored secret off the field is refused by name.
    let off_field = hex::encode([0xff; 32]);
    let mut corrupt = json.clone();
    corrupt["sent"][0]["slotSecret"] = off_field.clone().into();
    let error = AnonymousRingState::from_json(&corrupt.to_string())
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("slotSecret is not a field element"),
        "{error}"
    );
    assert!(!error.contains(&off_field), "{error}");
}

/// A stored epoch no fetch could reach would stop every later read without an error.
#[test]
fn a_stored_epoch_outside_the_ring_is_refused() {
    let json: serde_json::Value = serde_json::from_str(&Fixture::new().state().to_json()).unwrap();
    for (field, epoch) in [
        ("scannedEpoch", u64::MAX),
        ("scannedEpoch", CREATION - 1),
        ("creationEpoch", u64::MAX),
    ] {
        let mut corrupt = json.clone();
        corrupt[field] = epoch.into();
        assert!(matches!(
            AnonymousRingState::from_json(&corrupt.to_string()),
            Err(ClientError::AnonymousRingEpoch { epoch: refused }) if refused == epoch
        ));
    }
}

/// A UTXO the wallet holds, `ring` `None` on the default ring.
fn held(utxo_hash: [u8; 32], nullifier: [u8; 32], ring: Option<Address>) -> WalletUtxo {
    let owner = keypair(1).shielded_address().unwrap();
    WalletUtxo {
        utxo: Utxo {
            owner: owner.signing_pubkey,
            asset: Mint::SOL,
            amount: 1,
            blinding: [0; 32],
            ring_program_id: ring,
            data: Default::default(),
        },
        nullifier_pubkey: owner.nullifier_pubkey,
        utxo_hash,
        nullifier,
        tx_viewing_key: None,
        data_hash: None,
        ring_data_hash: None,
        tree_id: TREE,
        leaf_index: 0,
        latest_tree_id: None,
        slot: 0,
        tx_signature: Signature::default(),
        slot_index: 0,
    }
}

fn inbox_stream(
    wallet: &ShieldedKeypair,
    index: u32,
    epochs: RangeInclusive<u64>,
) -> Vec<[u8; 32]> {
    let key = address_key(wallet, index);
    epochs
        .flat_map(|epoch| (0..J_INBOX).map(move |j| inbox_tag(key, epoch, j).field()))
        .collect()
}

fn tags_asked(indexer: &Indexer) -> usize {
    indexer
        .tag_requests
        .lock()
        .unwrap()
        .iter()
        .map(Vec::len)
        .sum()
}

fn held_signatures(scan: &zolana_client::AnonymousRingScan) -> Vec<Signature> {
    scan.decrypted
        .utxos
        .iter()
        .map(|utxo| utxo.tx_signature)
        .collect()
}

/// A proofless row of any rail, what anyone holding the address publishes under its tags.
fn outsider_row(seed: u8, view_tags: &[[u8; 32]], first_leaf: u64) -> ShieldedTransaction {
    ShieldedTransaction {
        slot: slot_of(CREATION),
        tx_signature: Signature::from([seed; 64]),
        event_index: Some(0),
        tx_viewing_pk: None,
        salt: None,
        output_slots: view_tags
            .iter()
            .zip(first_leaf..)
            .map(|(tag, leaf_index)| OutputSlot {
                view_tag: *tag,
                output_context: OutputContext {
                    hash: nullifier(70_000 + leaf_index),
                    tree_id: TREE,
                    leaf_index,
                },
                payload: Vec::new(),
            })
            .collect(),
        messages: Vec::new(),
        nullifiers: Vec::new(),
        proofless: true,
        ring_config: None,
        ring_program_id: None,
    }
}

#[test]
fn payment_indexes_are_uniform_and_distinct_within_a_transaction() {
    let fixture = Fixture::new();
    let state = AnonymousRingState::new(RING, CREATION);
    let to = fixture.address(0);
    let rng = &mut UnwrapErr(OsRng);
    let mut allocation = TagAllocation::new(&state, CREATION);
    let taken: HashSet<u8> = (0..J_INBOX)
        .map(|_| allocation.allocate(&to, rng).unwrap().index.get())
        .collect();
    assert_eq!(taken.len(), usize::from(J_INBOX));
    let firsts: HashSet<u8> = (0..32)
        .map(|_| {
            TagAllocation::new(&state, CREATION)
                .allocate(&to, rng)
                .unwrap()
                .index
                .get()
        })
        .collect();
    assert!(firsts.len() > 1, "{firsts:?}");
}

/// An anonymous spend of a default-ring UTXO carries ring change, found without its nullifier.
#[tokio::test]
async fn the_change_scan_asks_for_ring_nullifiers_alone() {
    let fixture = Fixture::new();
    let default_nullifier = nullifier(4242);
    let change_key = fixture
        .recipient
        .viewing_key
        .ring_change_key(&RING)
        .unwrap()
        .pubkey();
    let (entry, delivered) = RingTransfer {
        sender: &fixture.recipient,
        nullifiers: vec![default_nullifier],
        payments: vec![Payment {
            owner: fixture.recipient_owner(),
            recipient: change_key,
            tag: RingTag::from_bytes([0x5c; TAG_LEN]),
            amount: 40,
        }],
        slot: slot_of(CREATION),
        leaf: 30,
    }
    .build();
    fixture.indexer.publish(entry.clone());
    let default_utxo = held(nullifier(4243), default_nullifier, None);
    let other_ring_nullifier = nullifier(4244);
    let other_ring_utxo = held(nullifier(4245), other_ring_nullifier, Some(OTHER_RING));
    let assets = AssetRegistry::default();
    let blind = AnonymousRingSync::new(&fixture.recipient, &assets)
        .with_held_utxos([&default_utxo, &other_ring_utxo])
        .fetch(&fixture.indexer, &fixture.state(), slot_of(CREATION + 2))
        .await
        .unwrap();
    assert!(blind.utxos.is_empty());
    let scan = AnonymousRingSync::new(&fixture.recipient, &assets)
        .with_held_utxos([&default_utxo, &other_ring_utxo])
        .with_default_ring_spends(vec![entry])
        .fetch(&fixture.indexer, &fixture.state(), slot_of(CREATION + 2))
        .await
        .unwrap();
    assert!(matches!(
        found(&scan, delivered[0].utxo_hash),
        AnonymousStream::Change { .. }
    ));
    let asked = fixture.indexer.nullifier_requests.lock().unwrap();
    assert!(!asked.is_empty());
    assert!(asked
        .iter()
        .flatten()
        .all(|asked| ![default_nullifier, other_ring_nullifier].contains(asked)));
}

/// Holders of two addresses never meet in one request, nor does a pair stream meet another address.
#[tokio::test]
async fn one_request_names_the_tags_of_one_address() {
    let fixture = Fixture::new();
    let first = fixture.inbox_payment(&fixture.sender, CREATION, 0, 70, 10);
    fixture.pair_payment(&first.slot_secret, CREATION + 1, 30, 20);
    let address_1 = address_key(&fixture.recipient, 1);
    fixture.indexer.publish(
        RingTransfer {
            sender: &fixture.sender,
            nullifiers: vec![nullifier(40)],
            payments: vec![Payment {
                owner: fixture.recipient_owner(),
                recipient: address_1,
                tag: inbox_tag(address_1, CREATION + 1, 3),
                amount: 9,
            }],
            slot: slot_of(CREATION + 1),
            leaf: 40,
        }
        .build()
        .0,
    );
    let mut state = fixture.state();
    state.issue(1, Pairing::default()).unwrap();
    let assets = AssetRegistry::default();
    let scan = AnonymousRingSync::new(&fixture.recipient, &assets)
        .fetch(&fixture.indexer, &state, slot_of(CREATION + 2))
        .await
        .unwrap();
    assert_eq!((scan.utxos.len(), scan.anchors.len()), (3, 2));
    let epochs = CREATION..=CREATION + 2;
    let mut address_of: HashMap<[u8; 32], u32> = HashMap::new();
    for index in 0..2 + ADDRESS_GAP {
        for tag in inbox_stream(&fixture.recipient, index, epochs.clone()) {
            address_of.insert(tag, index);
        }
    }
    for anchor in &scan.anchors {
        let pair = PairKey::from_bytes(anchor.pair_key).unwrap();
        for epoch in epochs.clone() {
            for j in TagIndex::all() {
                address_of.insert(pair.tag(epoch, j).unwrap().field(), anchor.address_index);
            }
        }
    }
    for request in fixture.indexer.tag_requests.lock().unwrap().iter() {
        let addresses: HashSet<u32> = request.iter().map(|tag| address_of[tag]).collect();
        assert_eq!(addresses.len(), 1, "{addresses:?}");
    }
}

#[tokio::test]
async fn a_deposit_past_an_empty_window_is_found_within_the_gap() {
    let assets = AssetRegistry::default();
    let deposit = |counter| Deposit {
        counter,
        blinding: nullifier(2),
        framing: Framing::Capsule,
        ring: RING,
    };
    let fixture = Fixture::new();
    let past = fixture.deposit(deposit(64));
    let scan = AnonymousRingSync::new(&fixture.recipient, &assets)
        .fetch(&fixture.indexer, &fixture.state(), slot_of(CREATION + 1))
        .await
        .unwrap();
    assert_eq!(held_signatures(&scan), [past]);
    assert_eq!(scan.state.deposit_next(), 65);

    let fixture = Fixture::new();
    fixture.deposit(deposit(DEPOSIT_GAP));
    let scan = AnonymousRingSync::new(&fixture.recipient, &assets)
        .fetch(&fixture.indexer, &fixture.state(), slot_of(CREATION + 1))
        .await
        .unwrap();
    assert!(scan.decrypted.utxos.is_empty());
    assert_eq!(scan.state.deposit_next(), 0);
}

/// Rows a lying indexer serves under the wallet's deposit tags open to no deposit and move nothing.
#[tokio::test]
async fn rows_that_open_to_no_deposit_of_the_wallet_move_no_counter() {
    let fixture = Fixture::new();
    fixture.deposit(Deposit {
        counter: 3,
        blinding: nullifier(1),
        framing: Framing::Truncated,
        ring: RING,
    });
    let mut altered = fixture.deposit_row(&Deposit {
        counter: 7,
        blinding: nullifier(2),
        framing: Framing::Capsule,
        ring: RING,
    });
    altered.output_slot.output_context.hash = nullifier(9_999);
    fixture.indexer.deposits.lock().unwrap().push(altered);
    let assets = AssetRegistry::default();
    let scan = AnonymousRingSync::new(&fixture.recipient, &assets)
        .fetch(&fixture.indexer, &fixture.state(), slot_of(CREATION + 1))
        .await
        .unwrap();
    assert_eq!(scan.state.deposit_next(), 0);
}

#[tokio::test]
async fn a_replayed_deposit_counts_at_its_first_counter() {
    let fixture = Fixture::new();
    let deposit = Deposit {
        counter: 1,
        blinding: nullifier(2),
        framing: Framing::Capsule,
        ring: RING,
    };
    let replay = |counter| {
        let mut row = fixture.deposit_row(&deposit);
        row.output_slot.view_tag = fixture.deposit_tag(counter);
        fixture.indexer.deposits.lock().unwrap().push(row);
    };
    replay(1);
    replay(70);
    let assets = AssetRegistry::default();
    let scan = AnonymousRingSync::new(&fixture.recipient, &assets)
        .fetch(&fixture.indexer, &fixture.state(), slot_of(CREATION + 1))
        .await
        .unwrap();
    assert_eq!(scan.state.deposit_next(), 2);
    replay(5);
    let next = AnonymousRingSync::new(&fixture.recipient, &assets)
        .with_held_utxos(&scan.decrypted.utxos)
        .fetch(&fixture.indexer, &scan.state, slot_of(CREATION + 1))
        .await
        .unwrap();
    assert_eq!(next.state.deposit_next(), 2);
}

/// The deposit stream is the keypair's, another ring's deposit moves the counter and stays out.
#[tokio::test]
async fn a_deposit_into_another_ring_moves_the_counter_alone() {
    let fixture = Fixture::new();
    fixture.deposit(Deposit {
        counter: 0,
        blinding: nullifier(2),
        framing: Framing::Capsule,
        ring: OTHER_RING,
    });
    let assets = AssetRegistry::default();
    let scan = AnonymousRingSync::new(&fixture.recipient, &assets)
        .fetch(&fixture.indexer, &fixture.state(), slot_of(CREATION + 1))
        .await
        .unwrap();
    assert!(scan.decrypted.utxos.is_empty());
    assert_eq!(scan.state.deposit_next(), 1);
}

#[tokio::test]
async fn outsider_rows_under_the_wallets_tags_join_no_decoy_set() {
    let fixture = Fixture::new();
    let own = fixture.inbox_payment(&fixture.sender, CREATION, 0, 70, 10);
    let tag = inbox_tag(address_key(&fixture.recipient, 0), CREATION, 5).field();
    for row in 0..10u8 {
        let mut tags = vec![[0x33; 32]; 10];
        tags[0] = tag;
        fixture
            .indexer
            .publish(outsider_row(0x40 + row, &tags, 5_000 + 10 * u64::from(row)));
    }
    let assets = AssetRegistry::default();
    let scan = AnonymousRingSync::new(&fixture.recipient, &assets)
        .fetch(&fixture.indexer, &fixture.state(), slot_of(CREATION + 2))
        .await
        .unwrap();
    found(&scan, own.utxo_hash);
    let decoys: Vec<[u8; 32]> = scan
        .state
        .decoys(TREE)
        .iter()
        .map(|leaf| leaf.hash)
        .collect();
    assert_eq!(decoys, [own.utxo_hash]);
}

/// Dust first contacts cost pair tags for `PAIR_IDLE_EPOCHS`, then the state forgets them.
#[tokio::test]
async fn dust_first_contacts_stop_costing_tags_once_idle() {
    let fixture = Fixture::new();
    let dust = 8u8;
    for n in 0..dust {
        fixture.inbox_payment(&keypair(60 + n), CREATION, n, 1, 100 + u64::from(n));
    }
    let assets = AssetRegistry::default();
    let sync = AnonymousRingSync::new(&fixture.recipient, &assets);
    let first = sync
        .fetch(&fixture.indexer, &fixture.state(), slot_of(CREATION + 2))
        .await
        .unwrap();
    assert_eq!(first.state.received().len(), usize::from(dust));
    let addresses = u64::from(1 + ADDRESS_GAP);
    let tags = u64::from(J_INBOX);

    fixture.indexer.tag_requests.lock().unwrap().clear();
    let idle = sync
        .fetch(
            &fixture.indexer,
            &first.state,
            slot_of(CREATION + PAIR_IDLE_EPOCHS + 2),
        )
        .await
        .unwrap();
    let inbox = addresses * tags * (PAIR_IDLE_EPOCHS + 2);
    let pairs = u64::from(dust) * tags * (PAIR_IDLE_EPOCHS - 1);
    assert_eq!(tags_asked(&fixture.indexer) as u64, inbox + pairs);
    assert!(idle.state.received().is_empty() && idle.anchors.is_empty());

    fixture.indexer.tag_requests.lock().unwrap().clear();
    sync.fetch(
        &fixture.indexer,
        &idle.state,
        slot_of(CREATION + PAIR_IDLE_EPOCHS + 3),
    )
    .await
    .unwrap();
    assert_eq!(tags_asked(&fixture.indexer) as u64, addresses * tags * 3);
}

/// Each pair payment keeps the stream live `PAIR_IDLE_EPOCHS` longer, an idle pair is dead.
#[tokio::test]
async fn a_paid_pair_outlives_the_idle_window_of_its_first_contact() {
    let fixture = Fixture::new();
    let first = fixture.inbox_payment(&fixture.sender, CREATION, 0, 70, 10);
    let kept = [6, 12]
        .map(|after| fixture.pair_payment(&first.slot_secret, CREATION + after, 5, 20 + after));
    let dead = fixture.pair_payment(&first.slot_secret, CREATION + 12 + PAIR_IDLE_EPOCHS, 5, 60);
    let assets = AssetRegistry::default();
    let scan = AnonymousRingSync::new(&fixture.recipient, &assets)
        .fetch(
            &fixture.indexer,
            &fixture.state(),
            slot_of(CREATION + 14 + PAIR_IDLE_EPOCHS),
        )
        .await
        .unwrap();
    for paid in &kept {
        found(&scan, paid.utxo_hash);
    }
    assert!(scan
        .utxos
        .iter()
        .all(|utxo| utxo.utxo_hash != dead.utxo_hash));
    assert!(scan.state.received().is_empty());
}

/// The sender's own pair payment, read by its change scan, keeps its pair live as the recipient's.
#[tokio::test]
async fn the_sender_keeps_a_pair_live_on_its_confirmed_pair_payments() {
    let fixture = Fixture::new();
    let first = fixture.inbox_payment(&fixture.sender, CREATION, 0, 70, 10);
    let mut sender_state = AnonymousRingState::new(RING, CREATION);
    sender_state.record_first_contact(SentFirstContact {
        recipient: address_key(&fixture.recipient, 0),
        tree_id: TREE,
        leaf_index: 10,
        utxo_hash: first.utxo_hash,
        slot_secret: *first.slot_secret.as_bytes(),
        first_nullifier: nullifier(10),
        slot_index: 0,
        epoch: CREATION,
        index: TagIndex::new(0).unwrap(),
        asset: Mint::SOL.asset,
        amount: 70,
    });
    let to = fixture.address(0);
    let stream = |state: &AnonymousRingState, epoch| {
        TagAllocation::new(state, epoch)
            .allocate(&to, &mut UnwrapErr(OsRng))
            .unwrap()
            .stream
    };
    let assets = AssetRegistry::default();
    let sender_state = AnonymousRingSync::new(&fixture.sender, &assets)
        .fetch(
            &fixture.indexer,
            &pooled(&sender_state, decoy_pool(ANCHOR_DECOYS)),
            slot_of(CREATION),
        )
        .await
        .unwrap()
        .state;
    assert!(matches!(
        stream(&sender_state, CREATION + PAIR_IDLE_EPOCHS - 1),
        PaymentStream::Pair(_)
    ));
    assert_eq!(
        stream(&sender_state, CREATION + PAIR_IDLE_EPOCHS),
        PaymentStream::Inbox
    );
    fixture.pair_payment(&first.slot_secret, CREATION + 5, 30, 20);
    let spent = held(nullifier(21), nullifier(20), Some(RING));
    let synced = AnonymousRingSync::new(&fixture.sender, &assets)
        .with_held_utxos([&spent])
        .fetch(&fixture.indexer, &sender_state, slot_of(CREATION + 6))
        .await
        .unwrap();
    assert!(matches!(
        stream(&synced.state, CREATION + PAIR_IDLE_EPOCHS),
        PaymentStream::Pair(_)
    ));
    assert_eq!(
        stream(&synced.state, CREATION + 5 + PAIR_IDLE_EPOCHS),
        PaymentStream::Inbox
    );
}

/// `count` leaves of `TREE` a scan could hold, none of them the anchor.
fn decoy_pool(count: usize) -> Vec<DecoyLeaf> {
    (0..count as u64)
        .map(|leaf| DecoyLeaf {
            leaf_index: 200 + leaf,
            hash: nullifier(9_000 + leaf),
        })
        .collect()
}

/// `state` holding `leaves` of `TREE` as its decoy pool, as a scan leaves it.
fn pooled(
    state: &AnonymousRingState,
    leaves: impl IntoIterator<Item = DecoyLeaf>,
) -> AnonymousRingState {
    let mut json: serde_json::Value = serde_json::from_str(&state.to_json()).unwrap();
    json["decoys"] = serde_json::json!([{
        "treeId": TREE,
        "leaves": leaves_json(leaves),
    }]);
    AnonymousRingState::from_json(&json.to_string()).unwrap()
}

fn leaves_json(leaves: impl IntoIterator<Item = DecoyLeaf>) -> serde_json::Value {
    leaves
        .into_iter()
        .map(|leaf| {
            serde_json::json!({
                "leafIndex": leaf.leaf_index,
                "hash": hex::encode(leaf.hash),
            })
        })
        .collect()
}

/// A sender whose first contact to address 0 landed at leaf 10 in `CREATION`.
struct Contacted {
    state: AnonymousRingState,
    contact: SentFirstContact,
}

impl Contacted {
    fn new(fixture: &Fixture) -> Self {
        let first = fixture.inbox_payment(&fixture.sender, CREATION, 0, 70, 10);
        let contact = SentFirstContact {
            recipient: address_key(&fixture.recipient, 0),
            tree_id: TREE,
            leaf_index: 10,
            utxo_hash: first.utxo_hash,
            slot_secret: *first.slot_secret.as_bytes(),
            first_nullifier: nullifier(10),
            slot_index: 0,
            epoch: CREATION,
            index: TagIndex::new(0).unwrap(),
            asset: Mint::SOL.asset,
            amount: 70,
        };
        let mut state = AnonymousRingState::new(RING, CREATION);
        state.record_first_contact(contact);
        Self { state, contact }
    }
}

async fn scanned(fixture: &Fixture, state: &AnonymousRingState) -> AnonymousRingState {
    let assets = AssetRegistry::default();
    AnonymousRingSync::new(&fixture.sender, &assets)
        .fetch(&fixture.indexer, state, slot_of(CREATION))
        .await
        .unwrap()
        .state
}

fn pays(fixture: &Fixture, state: &AnonymousRingState) -> PaymentStream {
    TagAllocation::new(state, CREATION)
        .allocate(&fixture.address(0), &mut UnwrapErr(OsRng))
        .unwrap()
        .stream
}

/// A pool short of a full set beside the anchor pins nothing, the sender pays the inbox.
#[tokio::test]
async fn a_contact_pins_its_decoys_once_the_pool_holds_a_full_set() {
    let fixture = Fixture::new();
    let Contacted { state, contact } = Contacted::new(&fixture);
    let anchor_leaf = DecoyLeaf {
        leaf_index: 10,
        hash: contact.utxo_hash,
    };
    let short = scanned(
        &fixture,
        &pooled(
            &state,
            decoy_pool(ANCHOR_DECOYS - 1)
                .into_iter()
                .chain([anchor_leaf]),
        ),
    )
    .await;
    assert_eq!(short.pair_anchor(&contact.recipient, CREATION), None);
    assert_eq!(pays(&fixture, &short), PaymentStream::Inbox);

    let full = scanned(&fixture, &pooled(&short, decoy_pool(ANCHOR_DECOYS))).await;
    let anchor = full.pair_anchor(&contact.recipient, CREATION).unwrap();
    let leaves: BTreeSet<[u8; 32]> = anchor.leaves.into_iter().collect();
    let expected: BTreeSet<[u8; 32]> = decoy_pool(ANCHOR_DECOYS)
        .into_iter()
        .map(|leaf| leaf.hash)
        .chain([contact.utxo_hash])
        .collect();
    assert_eq!(leaves, expected);
    assert_eq!(pays(&fixture, &full), PaymentStream::Pair(Box::new(anchor)));
}

/// Leaves a later scan adds rank anywhere, the pinned set and its order stay.
#[tokio::test]
async fn pinned_decoys_hold_while_the_pool_grows() {
    let fixture = Fixture::new();
    let Contacted { state, contact } = Contacted::new(&fixture);
    let pinned = scanned(&fixture, &pooled(&state, decoy_pool(ANCHOR_DECOYS))).await;
    let anchor = pinned.pair_anchor(&contact.recipient, CREATION).unwrap();
    let grown = scanned(&fixture, &pooled(&pinned, decoy_pool(40))).await;
    let restored = AnonymousRingState::from_json(&grown.to_json()).unwrap();
    for state in [&grown, &restored] {
        assert_eq!(
            state.pair_anchor(&contact.recipient, CREATION),
            Some(anchor)
        );
    }
    let mut rerecorded = restored;
    rerecorded.record_first_contact(contact);
    assert_eq!(
        rerecorded.pair_anchor(&contact.recipient, CREATION),
        Some(anchor)
    );
}

#[tokio::test]
async fn a_retired_first_contact_pays_the_inbox_until_a_fresh_one_lands() {
    let fixture = Fixture::new();
    let Contacted { state, contact } = Contacted::new(&fixture);
    let mut retired = scanned(&fixture, &pooled(&state, decoy_pool(ANCHOR_DECOYS))).await;
    retired.retire_first_contact(&contact.recipient);
    assert_eq!(retired.first_contact(&contact.recipient, CREATION), None);
    assert_eq!(pays(&fixture, &retired), PaymentStream::Inbox);
    let mut rescanned = scanned(&fixture, &retired).await;
    assert_eq!(rescanned.first_contact(&contact.recipient, CREATION), None);

    let second = fixture.inbox_payment(&fixture.sender, CREATION, 1, 70, 11);
    let fresh = SentFirstContact {
        leaf_index: 11,
        utxo_hash: second.utxo_hash,
        slot_secret: *second.slot_secret.as_bytes(),
        first_nullifier: nullifier(11),
        index: TagIndex::new(1).unwrap(),
        ..contact
    };
    rescanned.record_first_contact(fresh);
    let repinned = scanned(&fixture, &rescanned).await;
    let anchor = repinned.pair_anchor(&contact.recipient, CREATION).unwrap();
    assert_eq!(anchor.contact, fresh);
    assert!(anchor.leaves.contains(&fresh.utxo_hash));
    assert_eq!(
        pays(&fixture, &repinned),
        PaymentStream::Pair(Box::new(anchor))
    );
}

#[tokio::test]
async fn kept_first_contacts_follow_the_stored_state_with_their_pins_and_pair_payments() {
    let fixture = Fixture::new();
    let Contacted { state, contact } = Contacted::new(&fixture);
    let edited = |state: &AnonymousRingState, edit: &dyn Fn(&mut serde_json::Value)| {
        let mut json: serde_json::Value = serde_json::from_str(&state.to_json()).unwrap();
        edit(&mut json);
        AnonymousRingState::from_json(&json.to_string()).unwrap()
    };
    let pinned = scanned(&fixture, &pooled(&state, decoy_pool(ANCHOR_DECOYS))).await;
    let stored = edited(&pinned, &|json| {
        json["sent"][0]["lastEpoch"] = (CREATION + 5).into();
    });
    let late = CREATION + PAIR_IDLE_EPOCHS + 2;
    let anchor = stored.pair_anchor(&contact.recipient, late);
    assert!(anchor.is_some());

    let mut fresh = AnonymousRingState::new(RING, CREATION);
    fresh.keep_first_contacts(&stored);
    assert_eq!(fresh.pair_anchor(&contact.recipient, late), anchor);

    let mut scan = stored.clone();
    scan.keep_first_contacts(&state);
    assert_eq!(scan.pair_anchor(&contact.recipient, late), anchor);

    let mut scan = edited(&stored, &|json| {
        json["sent"][0]["decoys"] = decoy_pool(ANCHOR_DECOYS + 1)[1..]
            .iter()
            .map(|leaf| hex::encode(leaf.hash))
            .collect();
    });
    scan.keep_first_contacts(&stored);
    assert_eq!(scan.pair_anchor(&contact.recipient, late), anchor);

    let after = |scanned_epoch: u64| {
        let mut scan = edited(&AnonymousRingState::new(RING, CREATION), &|json| {
            json["scannedEpoch"] = scanned_epoch.into();
        });
        scan.keep_first_contacts(&stored);
        scan.sent().count()
    };
    assert_eq!(after(CREATION + 3), 1);
    assert_eq!(after(CREATION + 20), 0);

    let mut retired = stored.clone();
    retired.retire_first_contact(&contact.recipient);
    let mut scan = stored;
    scan.keep_first_contacts(&retired);
    assert_eq!(scan.sent().count(), 0);
}

#[tokio::test]
async fn a_stored_pin_must_be_a_full_set_beside_the_anchor() {
    let fixture = Fixture::new();
    let Contacted { state, contact } = Contacted::new(&fixture);
    let pinned = scanned(&fixture, &pooled(&state, decoy_pool(ANCHOR_DECOYS))).await;
    let json: serde_json::Value = serde_json::from_str(&pinned.to_json()).unwrap();
    let stored: Vec<serde_json::Value> = json["sent"][0]["decoys"].as_array().unwrap().clone();
    let short = stored[1..].to_vec();
    let repeated = [&stored[1..], &stored[1..2]].concat();
    let with_anchor = [&stored[1..], &[hex::encode(contact.utxo_hash).into()]].concat();
    for decoys in [short, repeated, with_anchor] {
        let mut corrupt = json.clone();
        corrupt["sent"][0]["decoys"] = decoys.into();
        assert!(matches!(
            AnonymousRingState::from_json(&corrupt.to_string()),
            Err(ClientError::AnonymousRingState(_))
        ));
    }
}

/// The TS SDK refuses the same stores.
#[test]
fn a_stored_state_repeating_an_entry_or_overfilling_a_decoy_pool_is_refused() {
    let fixture = Fixture::new();
    let Contacted { mut state, .. } = Contacted::new(&fixture);
    state.issue(0, Pairing::default()).unwrap();
    let json: serde_json::Value =
        serde_json::from_str(&pooled(&state, decoy_pool(2)).to_json()).unwrap();
    let refusal = |corrupt: fn(&mut serde_json::Value)| {
        let mut stored = json.clone();
        corrupt(&mut stored);
        match AnonymousRingState::from_json(&stored.to_string()) {
            Err(ClientError::AnonymousRingState(message)) => message,
            other => panic!("{other:?}"),
        }
    };
    fn repeat(list: &mut serde_json::Value) {
        let list = list.as_array_mut().unwrap();
        list.push(list[0].clone());
    }
    assert!(refusal(|json| repeat(&mut json["issued"])).contains("issued names index 0 twice"));
    assert!(refusal(|json| repeat(&mut json["sent"]))
        .contains("sent holds two first contacts for one recipient"));
    assert!(refusal(|json| repeat(&mut json["decoys"])).contains("decoys name tree"));
    assert!(refusal(|json| {
        json["decoys"][0]["leaves"] = leaves_json(decoy_pool(DECOYS_PER_TREE + 1))
    })
    .contains("hold more than"));
}

/// The TS SDK asserts the same vector.
#[tokio::test]
async fn the_pin_and_its_read_order_match_the_shared_vector() {
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../test-vectors/anonymous-ring-state.json"
    ))
    .unwrap();
    let bytes = |value: &serde_json::Value| -> [u8; 32] {
        hex::decode(value.as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    };
    let fixture = Fixture::new();
    let contact = SentFirstContact {
        recipient: address_key(&fixture.recipient, 0),
        tree_id: TREE,
        leaf_index: vector["anchor"]["leaf_index"].as_u64().unwrap(),
        utxo_hash: bytes(&vector["anchor"]["hash"]),
        slot_secret: bytes(&vector["slot_secret"]),
        first_nullifier: nullifier(10),
        slot_index: 0,
        epoch: CREATION,
        index: TagIndex::new(0).unwrap(),
        asset: Mint::SOL.asset,
        amount: 70,
    };
    let mut state = AnonymousRingState::new(RING, CREATION);
    state.record_first_contact(contact);
    let pool = vector["pool"]
        .as_array()
        .unwrap()
        .iter()
        .map(|leaf| DecoyLeaf {
            leaf_index: leaf["leaf_index"].as_u64().unwrap(),
            hash: bytes(&leaf["hash"]),
        });
    let pinned = scanned(&fixture, &pooled(&state, pool)).await;
    let stored: serde_json::Value = serde_json::from_str(&pinned.to_json()).unwrap();
    assert_eq!(stored["sent"][0]["decoys"], vector["pinned"]);
    let leaves: Vec<String> = pinned
        .pair_anchor(&contact.recipient, CREATION)
        .unwrap()
        .leaves
        .iter()
        .map(hex::encode)
        .collect();
    assert_eq!(serde_json::json!(leaves), vector["leaves"]);
}

#[test]
fn a_first_contact_and_its_anchor_print_no_recipient_leaf_or_secret() {
    let fixture = Fixture::new();
    let contact = SentFirstContact {
        recipient: address_key(&fixture.recipient, 0),
        tree_id: TREE,
        leaf_index: 1234,
        utxo_hash: [0xa1; 32],
        slot_secret: [0xb2; 32],
        first_nullifier: [0xc3; 32],
        slot_index: 0,
        epoch: CREATION,
        index: TagIndex::new(0).unwrap(),
        asset: Mint::SOL.asset,
        amount: 70,
    };
    let printed = format!(
        "{:?}",
        PairAnchor {
            contact,
            leaves: [[0xd4; 32]; ANCHOR_DECOYS + 1],
        }
    );
    for field in [
        "recipient",
        "leaf_index",
        "utxo_hash",
        "slot_secret",
        "first_nullifier",
        "leaves",
    ] {
        assert!(
            printed.contains(&format!("{field}: {REDACTED:?}")),
            "{printed}"
        );
    }
    for value in [
        format!("{:?}", contact.recipient),
        "1234".to_owned(),
        format!("{:?}", [0xa1u8; 32]),
        format!("{:?}", [0xb2u8; 32]),
        format!("{:?}", [0xc3u8; 32]),
        format!("{:?}", [0xd4u8; 32]),
    ] {
        assert!(!printed.contains(&value), "{value} in {printed}");
    }
}

#[tokio::test]
async fn a_pinned_state_prints_neither_its_pins_nor_its_decoy_pool() {
    let fixture = Fixture::new();
    let Contacted { state, .. } = Contacted::new(&fixture);
    let pinned = scanned(&fixture, &pooled(&state, decoy_pool(ANCHOR_DECOYS))).await;
    let printed = format!("{pinned:?}");
    assert!(
        printed.contains(&format!("decoys: {REDACTED:?}")),
        "{printed}"
    );
    for leaf in decoy_pool(ANCHOR_DECOYS) {
        assert!(!printed.contains(&format!("{:?}", leaf.hash)), "{printed}");
    }
}
