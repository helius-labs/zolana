//! The anonymous half of `WalletScan` against an in-memory indexer.

use std::{collections::HashSet, ops::Range, sync::Mutex};

use custom_ring_interface::stream::{
    DeliveredSlot, InboxKey, RingTag, TagIndex, EPOCH_SLOTS, J_INBOX, TAG_LEN,
};
use solana_signature::Signature;
use zolana_client::{
    rpc::GetShieldedTransactionsByNullifiersResponse, ClientError, Context as Page,
    EncryptedUtxoMatch, GetEncryptedUtxosByTagsResponse, GetShieldedTransactionsByTagsResponse,
    OutputContext, OutputSlot, ProverClient, ShieldedTransaction, WitnessReader,
};
use zolana_event::encode_ring_anonymous_output;
use zolana_keypair::{Pairing, ShieldedAddress};
use zolana_ring_policy::ring_id_field;
use zolana_transaction::{
    serialization::{
        proofless::{Proofless, ProoflessEncode},
        RingDeliveredBody, RingDeliverySlot,
    },
    Data, Mint, OwnerCx, Utxo, UtxoSerialization,
};

use super::{
    fixtures::{keypair, Member, EPOCH, RING},
    *,
};

const TREE: u16 = 2;
const SALT: [u8; 16] = [7; 16];
const CAUGHT_UP: Page = Page {
    block_time: 0,
    slot: u64::MAX,
};

fn slot_of(epoch: u64) -> u64 {
    epoch * EPOCH_SLOTS + 17
}

/// Serves what the asked tags or nullifiers reach, in one page.
#[derive(Default)]
struct Ledger {
    transactions: Vec<ShieldedTransaction>,
    deposits: Vec<EncryptedUtxoMatch>,
    queried: Mutex<Vec<[u8; 32]>>,
}

struct DepositedUtxo {
    hash: [u8; 32],
    nullifier: [u8; 32],
}

struct Payment {
    owner: ShieldedAddress,
    recipient: X25519Pubkey,
    tag: RingTag,
    amount: u64,
}

/// Each payment delivered as the anonymous rail delivers it.
struct RingTransfer<'a> {
    sender: &'a ShieldedKeypair,
    nullifiers: Vec<[u8; 32]>,
    payments: Vec<Payment>,
    slot: u64,
    leaf: u64,
}

impl Ledger {
    /// A default-ring note, the plain scan finds it under the owner's viewing tag.
    fn deposit(&mut self, owner: &ShieldedKeypair, amount: u64) -> DepositedUtxo {
        let address = owner.shielded_address().unwrap();
        let mut blinding = [0; 32];
        blinding[31] = 9;
        let utxo = Utxo {
            owner: address.signing_pubkey,
            asset: Mint::SOL,
            amount,
            blinding,
            ring_program_id: None,
            data: Data::default(),
        };
        let hash = utxo
            .hash(&address.nullifier_pubkey, &[0; 32], &[0; 32], TREE)
            .unwrap();
        let assets = AssetRegistry::default();
        let message = Proofless::encode(
            std::slice::from_ref(&utxo),
            &OwnerCx {
                owner: address.signing_pubkey,
                assets: &assets,
                ring_program_id: None,
                first_nullifier: None,
            },
            [0; 32],
            &ProoflessEncode {
                owner_hash: address.owner_hash().unwrap(),
                data_hash: None,
                ring_data_hash: None,
            },
        )
        .unwrap();
        self.deposits.push(EncryptedUtxoMatch {
            slot: 1,
            tx_signature: Signature::from([0xd0; 64]),
            output_slot: OutputSlot {
                view_tag: address.viewing_pubkey.u(),
                output_context: OutputContext {
                    hash,
                    tree_id: TREE,
                    leaf_index: 1,
                },
                payload: message.data,
            },
            tx_viewing_pk: None,
            salt: None,
        });
        DepositedUtxo {
            hash,
            nullifier: owner.nullifier(&hash, &utxo.blinding).unwrap(),
        }
    }

    /// The commitment of each payment, in payment order.
    fn transfer(&mut self, transfer: RingTransfer<'_>) -> Vec<[u8; 32]> {
        let first_nullifier = transfer.nullifiers[0];
        let tx = transfer
            .sender
            .viewing_key
            .get_transaction_viewing_key(&first_nullifier)
            .unwrap();
        let mut output_slots = Vec::new();
        let mut hashes = Vec::new();
        for (output_index, payment) in (0u32..).zip(&transfer.payments) {
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
            let hash = Utxo {
                owner: payment.owner.signing_pubkey,
                asset: Mint::SOL,
                amount: payment.amount,
                blinding,
                ring_program_id: Some(RING),
                data: Data::default(),
            }
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
                    hash,
                    tree_id: TREE,
                    leaf_index: transfer.leaf + u64::from(output_index),
                },
                payload: encode_ring_anonymous_output(&body),
            });
            hashes.push(hash);
        }
        self.transactions.push(ShieldedTransaction {
            slot: transfer.slot,
            tx_signature: Signature::from([transfer.leaf as u8 + 1; 64]),
            event_index: Some(0),
            tx_viewing_pk: Some(tx.pubkey()),
            salt: Some(SALT),
            output_slots,
            messages: Vec::new(),
            nullifiers: transfer.nullifiers,
            proofless: false,
            ring_config: None,
            ring_program_id: Some(RING),
        });
        hashes
    }

    /// A first contact from another member to the wallet's address 0, landed in `epoch`.
    fn inbox_payment(&mut self, wallet: &Member, epoch: u64) -> [u8; 32] {
        self.transfer(RingTransfer {
            sender: &keypair(2),
            nullifiers: vec![[0x11; 32]],
            payments: vec![Payment {
                owner: wallet.keys.shielded_address().unwrap(),
                recipient: wallet.address_key(),
                tag: wallet.inbox_tag(epoch, 0),
                amount: 70,
            }],
            slot: slot_of(epoch),
            leaf: 10,
        })[0]
    }

    fn client(self) -> ZolanaClient<NoRpc, Self> {
        ZolanaClient::new(NoRpc, self, ProverClient::local())
    }

    fn queried_any(&self, tags: &HashSet<[u8; 32]>) -> bool {
        self.queried
            .lock()
            .unwrap()
            .iter()
            .any(|tag| tags.contains(tag))
    }
}

impl WitnessReader for Ledger {}

impl Rpc for Ledger {
    fn get_shielded_transactions_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        _cursor: Option<Vec<u8>>,
        _limit: Option<u32>,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        self.queried.lock().unwrap().extend(&tags);
        Ok(GetShieldedTransactionsByTagsResponse {
            context: CAUGHT_UP,
            output_tree_id: Some(TREE),
            transactions: self
                .transactions
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
        tags: Vec<[u8; 32]>,
        _cursor: Option<Vec<u8>>,
        _limit: Option<u32>,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetEncryptedUtxosByTagsResponse, ClientError> {
        Ok(GetEncryptedUtxosByTagsResponse {
            context: CAUGHT_UP,
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
            context: CAUGHT_UP,
            output_tree_id: Some(TREE),
            transactions: self
                .transactions
                .iter()
                .filter(|tx| tx.nullifiers.iter().any(|spent| nullifiers.contains(spent)))
                .cloned()
                .collect(),
            next_cursor: None,
            scanned_through: None,
        })
    }
}

struct NoRpc;

impl Rpc for NoRpc {}

impl Member {
    fn address_key(&self) -> X25519Pubkey {
        self.keys
            .viewing_key
            .ring_address_key(&RING, 0)
            .unwrap()
            .pubkey()
    }

    fn inbox_tag(&self, epoch: u64, index: u8) -> RingTag {
        InboxKey::derive(
            &ring_id_field(RING.as_array()).unwrap(),
            self.address_key().as_bytes(),
        )
        .unwrap()
        .tag(epoch, TagIndex::new(index).unwrap())
        .unwrap()
    }

    fn inbox_tags(&self, epochs: Range<u64>) -> HashSet<[u8; 32]> {
        epochs
            .flat_map(|epoch| (0..J_INBOX).map(move |index| self.inbox_tag(epoch, index).field()))
            .collect()
    }

    fn scan(&self, zolana: &ZolanaClient<NoRpc, Ledger>, slot: u64) -> Vec<[u8; 32]> {
        let registry = AssetRegistry::default();
        ScanAt {
            keys: &self.keys,
            registry: &registry,
            ring: RING,
            slot,
            store: Some(&self.store),
        }
        .fetch(zolana)
        .unwrap()
        .utxos()
        .map(|utxo| utxo.utxo_hash)
        .collect()
    }
}

#[test]
fn an_anonymous_scan_adds_inbox_payments_and_the_change_of_a_default_ring_spend() {
    let wallet = Member::new(1, "anonymous-scan");
    wallet
        .store
        .update(|state| Ok(state.issue(0, Pairing::default())?))
        .unwrap();
    let mut ledger = Ledger::default();
    let paid = ledger.inbox_payment(&wallet, EPOCH);
    let deposited = ledger.deposit(&wallet.keys, 40);
    let change = ledger.transfer(RingTransfer {
        sender: &wallet.keys,
        nullifiers: vec![deposited.nullifier],
        payments: vec![Payment {
            owner: wallet.keys.shielded_address().unwrap(),
            recipient: wallet
                .keys
                .viewing_key
                .ring_change_key(&RING)
                .unwrap()
                .pubkey(),
            tag: RingTag::from_bytes([0x5c; TAG_LEN]),
            amount: 30,
        }],
        slot: slot_of(EPOCH + 1),
        leaf: 20,
    });
    let held = wallet.scan(&ledger.client(), slot_of(EPOCH + 2));
    assert!(held.contains(&paid), "the inbox payment");
    // Only the plain scan finds the deposit, its nullifier leads the sync to the change.
    assert!(
        held.contains(&change[0]),
        "the change of the deposit's spend"
    );
    assert!(!held.contains(&deposited.hash), "the spent deposit");
    assert_eq!(held.len(), 2);
    let stored = wallet.store.load().unwrap();
    let issued: Vec<u32> = stored.issued().iter().map(|issued| issued.index).collect();
    assert_eq!(issued, [0]);
    assert!(stored.scanned_epoch().is_some());
}

#[test]
fn a_restored_wallet_scans_from_the_rings_creation_epoch() {
    let wallet = Member::new(1, "restored-scan");
    // A state written after the payment, as a restore on another machine leaves it.
    let path = wallet.state_file();
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, AnonymousRingState::new(RING, EPOCH + 5).to_json()).unwrap();
    let mut ledger = Ledger::default();
    let paid = ledger.inbox_payment(&wallet, EPOCH);
    let held = wallet.scan(&ledger.client(), slot_of(EPOCH + 9));
    assert_eq!(held, [paid]);
    assert_eq!(wallet.store.load().unwrap().creation_epoch(), EPOCH);
}

#[test]
fn a_second_scan_resumes_from_the_saved_epoch_and_keeps_its_utxos() {
    let wallet = Member::new(1, "resumed-scan");
    let mut ledger = Ledger::default();
    let paid = ledger.inbox_payment(&wallet, EPOCH);
    let zolana = ledger.client();
    assert_eq!(wallet.scan(&zolana, slot_of(EPOCH + 9)), [paid]);
    let scanned = wallet.store.load().unwrap().scanned_epoch().unwrap();
    let early = wallet.inbox_tags(EPOCH..scanned - 2);
    assert!(
        zolana.indexer().queried_any(&early),
        "a new store reads from the ring's creation"
    );
    zolana.indexer().queried.lock().unwrap().clear();
    assert_eq!(
        wallet.scan(&zolana, slot_of(EPOCH + 11)),
        [paid],
        "the kept note"
    );
    assert!(!zolana.indexer().queried_any(&early));
}
