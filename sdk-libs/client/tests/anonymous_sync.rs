//! `AnonymousRingSync` and `TagAllocation` against an in-memory indexer.

use std::sync::Mutex;

use async_trait::async_trait;
use custom_ring_interface::{
    stream::{
        DeliveredSlot, InboxKey, PairKey, RingTag, SlotSecret, TagIndex, EPOCH_SLOTS, J_INBOX,
    },
    RingDepositAuditCapsule, RING_DELIVERED_BODY_LEN,
};
use solana_address::Address;
use solana_signature::Signature;
use zolana_client::{
    rpc::GetShieldedTransactionsByNullifiersResponse, AnonymousRingState, AnonymousRingSync,
    AnonymousStream, AsyncRpc, ClientError, Context, EncryptedUtxoMatch,
    GetEncryptedUtxosByTagsResponse, GetShieldedTransactionsByTagsResponse, IndexerRpcConfig,
    OutputContext, OutputSlot, PaymentStream, SentFirstContact, ShieldedTransaction, TagAllocation,
    ANONYMOUS_RING_STATE_VERSION,
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
    RingDeliveryRequest, ShieldedKeys, TransactionError, TransactionKeyRequest, Utxo,
};

const RING: Address = Address::new_from_array([4; 32]);
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

    fn change_from(&self, note: &Delivered, epoch: u64, amount: u64, leaf: u64) -> Delivered {
        let nullifier = self
            .recipient
            .nullifier(&note.utxo_hash, &note.blinding)
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
                tag: RingTag::from_bytes([0x5c; 31]),
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
            .notes
            .iter()
            .map(|note| {
                self.recipient
                    .nullifier(&note.utxo_hash, &note.blinding)
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
        let address = self.recipient_owner();
        let tag = self.recipient.sender_view_tags(&[deposit.counter]).unwrap()[0];
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
        let tx_signature = Signature::from([0xd0 + deposit.counter as u8; 64]);
        let payload = encode_encrypted_ring_deposit_output(EncryptedRingDepositOutput {
            owner_utxo_hash: owner_utxo_hash(&owner_hash, &deposit.blinding).unwrap_or([0x0e; 32]),
            asset: Mint::SOL.asset.to_bytes(),
            amount: 25,
            data_hash: None,
            ring_program_id: RING.to_bytes(),
            ring_data_hash: [0; 32],
            encrypted: EncryptedRingDepositData {
                ciphertext,
                ..encrypted
            },
        });
        self.indexer
            .deposits
            .lock()
            .unwrap()
            .push(EncryptedUtxoMatch {
                slot: slot_of(CREATION),
                tx_signature,
                output_slot: OutputSlot {
                    view_tag: tag,
                    output_context: OutputContext {
                        hash: nullifier(500 + deposit.counter),
                        tree_id: TREE,
                        leaf_index: 500 + deposit.counter,
                    },
                    payload,
                },
                tx_viewing_pk: None,
                salt: None,
            });
        tx_signature
    }
}

struct Merge<'a> {
    notes: &'a [&'a Delivered],
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
}

/// How the recipient ciphertext sits in the ring's audit capsule.
enum Framing {
    Capsule,
    /// The capsule magic alone.
    Truncated,
}

fn found(scan: &zolana_client::AnonymousRingScan, utxo_hash: [u8; 32]) -> AnonymousStream {
    scan.notes
        .iter()
        .find(|note| note.utxo_hash == utxo_hash)
        .map(|note| note.stream)
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
    assert_eq!(scan.notes.len(), 1);
}

/// A merge spends the wallet's notes, the next sync opens its output from that spend.
#[tokio::test]
async fn a_merge_of_the_wallets_notes_is_found_by_the_next_sync() {
    let fixture = Fixture::new();
    let first = fixture.inbox_payment(&fixture.sender, CREATION, 0, 70, 10);
    let second = fixture.inbox_payment(&fixture.sender, CREATION, 1, 30, 20);
    let assets = AssetRegistry::default();
    let held = AnonymousRingSync::new(&fixture.recipient, &assets)
        .fetch(&fixture.indexer, &fixture.state(), slot_of(CREATION + 2))
        .await
        .unwrap();
    let merged = fixture.merge(Merge {
        notes: &[&first, &second],
        amount: 100,
        epoch: CREATION + 2,
        leaf: 40,
    });
    let next = AnonymousRingSync::new(&fixture.recipient, &assets)
        .with_known_nullifiers(
            held.decrypted
                .utxos
                .iter()
                .map(|utxo| utxo.nullifier)
                .collect(),
        )
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
    assert_eq!(scan.notes.len(), 1);
}

/// The deposit after a malformed capsule is still read.
#[tokio::test]
async fn a_malformed_deposit_capsule_is_skipped() {
    let fixture = Fixture::new();
    fixture.deposit(Deposit {
        counter: 0,
        blinding: nullifier(1),
        framing: Framing::Truncated,
    });
    let deposited = fixture.deposit(Deposit {
        counter: 1,
        blinding: nullifier(2),
        framing: Framing::Capsule,
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
    });
    let deposited = fixture.deposit(Deposit {
        counter: 1,
        blinding: nullifier(2),
        framing: Framing::Capsule,
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
async fn a_restore_from_seed_finds_every_note_over_three_epochs() {
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
    for note in [
        &first,
        &paired,
        &change,
        &far_delivered[0],
        &farther_delivered[0],
    ] {
        found(&scan, note.utxo_hash);
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
    let allocated = TagAllocation::new(&fixture.indexer, &sender_state, CREATION + 1)
        .allocate(&address)
        .await
        .unwrap();
    assert_eq!(allocated.stream, PaymentStream::Inbox);
}

#[tokio::test]
async fn sixty_four_used_inbox_tags_refuse_the_payment_until_the_next_epoch() {
    let fixture = Fixture::new();
    for index in 0..J_INBOX {
        fixture.inbox_payment(&fixture.sender, CREATION, index, 1, 100 + u64::from(index));
    }
    let address = RingAddress {
        recipient: ShieldedAddress {
            viewing_pubkey: address_key(&fixture.recipient, 0),
            ..fixture.recipient_owner()
        },
        ring_program_id: RING,
        pairing: Pairing::default(),
    };
    let state = AnonymousRingState::new(RING, CREATION);
    assert!(matches!(
        TagAllocation::new(&fixture.indexer, &state, CREATION)
            .allocate(&address)
            .await,
        Err(ClientError::InboxStreamFull { epoch: CREATION })
    ));
    let next = TagAllocation::new(&fixture.indexer, &state, CREATION + 1)
        .allocate(&address)
        .await
        .unwrap();
    assert_eq!((next.stream, next.index.get()), (PaymentStream::Inbox, 0));
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
    assert!(scan.notes.is_empty());
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
    for note in [&first, &paired, &change] {
        found(&scan, note.utxo_hash);
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

/// Slot secrets and pair keys link the wallet's payments, neither a print nor a parse error shows one.
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
}

/// A corrupt store's last epoch at the integer maximum reads no epoch instead of overflowing.
#[tokio::test]
async fn a_scanned_epoch_at_the_maximum_reads_no_epoch() {
    let fixture = Fixture::new();
    fixture.inbox_payment(&fixture.sender, CREATION, 0, 70, 10);
    let mut json: serde_json::Value = serde_json::from_str(&fixture.state().to_json()).unwrap();
    json["scannedEpoch"] = u64::MAX.into();
    let state = AnonymousRingState::from_json(&json.to_string()).unwrap();
    let assets = AssetRegistry::default();
    let scan = AnonymousRingSync::new(&fixture.recipient, &assets)
        .fetch(&fixture.indexer, &state, slot_of(CREATION + 2))
        .await
        .unwrap();
    assert!(scan.notes.is_empty());
}
