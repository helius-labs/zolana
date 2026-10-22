#[path = "common/deposit.rs"]
mod deposit_fixture;
#[path = "common/origin.rs"]
mod origin_fixture;
#[path = "common/transfer.rs"]
pub mod transfer;

use custom_ring_interface::{RingDepositAuditCapsule, RingMode};
use std::{cell::Cell, sync::Mutex};

use solana_address::Address;
use solana_signature::Signature;
use zolana_client::{
    rpc::GetShieldedTransactionsByNullifiersResponse, AsyncRpc, ClientError, Context,
    GetShieldedTransactionsByTagsResponse, IndexerRpcConfig,
};
use zolana_event::{
    encode_encrypted_ring_deposit_output, encode_merge_output_data, EncryptedRingDepositOutput,
    MergeOutputDataRef,
};
use zolana_hasher::primitives::right_align;
use zolana_keypair::{ShieldedAddress, ShieldedKeypair, ViewingKey, X25519Keypair};
use zolana_ring_client::{
    seal_deposits, AuditError, DepositOpening, MemberRecovery, RecoveredNotes, RingOrigin,
    RingRecovery, SourceMember, TransactionOrigin,
};
use zolana_transaction::{
    derive_output_blinding_seed, instructions::merge::MergeTransaction,
    serialization::ring_deposit::RingDepositPlaintext, AssetRegistry, Data, DataRecord, Mint,
    OutputContext, OutputSlot, ShieldedTransaction, SppProofOutputUtxo, Utxo, WalletUtxo, SOL_MINT,
};

use transfer::{data_free, field, x25519_u, Frame, Output, Publish, Rail, Transfer, UtxoFields};

const RING: Address = Address::new_from_array([42; 32]);
const SALT: [u8; 16] = [7; 16];

struct Fixture {
    member: ShieldedKeypair,
    address: ShieldedAddress,
    auditor: X25519Keypair,
    sequence: Cell<u8>,
    confirmed: Mutex<Vec<(Signature, Vec<zolana_ring_client::ConfirmedDeposit>)>>,
    frames: Mutex<Vec<(Signature, Vec<u8>)>>,
}

impl Fixture {
    fn new() -> Self {
        let member = ShieldedKeypair::new_ed25519().expect("member");
        Self {
            address: member.shielded_address().expect("address"),
            member,
            auditor: X25519Keypair::new(),
            sequence: Cell::new(0),
            confirmed: Mutex::new(Vec::new()),
            frames: Mutex::new(Vec::new()),
        }
    }

    fn signature(&self) -> Signature {
        let next = self.sequence.get() + 1;
        self.sequence.set(next);
        Signature::from([next; 64])
    }

    fn recovery(&self) -> MemberRecovery<'_> {
        RingRecovery::new(RING, &self.auditor).for_member(SourceMember {
            address: &self.address,
            nullifier_key: &self.member.nullifier_key,
        })
    }

    async fn run(
        &self,
        recovery: MemberRecovery<'_>,
        history: &History,
    ) -> Result<RecoveredNotes, AuditError> {
        *history.confirmed.lock().unwrap() = self.confirmed.lock().unwrap().clone();
        *history.frames.lock().unwrap() = self.frames.lock().unwrap().clone();
        recovery
            .run(history, history, &AssetRegistry::default())
            .await
    }

    fn output(&self, amount: u64) -> SppProofOutputUtxo {
        SppProofOutputUtxo::new(Mint::SOL, amount, self.address)
            .expect("output")
            .with_ring_program_id(RING)
    }

    fn held(&self, output: &SppProofOutputUtxo, tree_id: u16) -> WalletUtxo {
        let hash = output.hash(tree_id).expect("commitment");
        let utxo = Utxo {
            owner: self.address.signing_pubkey,
            asset: output.asset,
            amount: output.amount,
            blinding: output.blinding,
            ring_program_id: output.ring_program_id,
            data: output.data.clone(),
        };
        WalletUtxo {
            nullifier_pubkey: self.address.nullifier_pubkey,
            utxo_hash: hash,
            nullifier: utxo
                .nullifier(&hash, &self.member.nullifier_key)
                .expect("nullifier"),
            tx_viewing_key: None,
            utxo,
            data_hash: output.data_hash,
            ring_data_hash: output.ring_data_hash,
            tree_id,
            leaf_index: u64::from(self.sequence.get()),
            latest_tree_id: None,
            slot: u64::from(self.sequence.get()),
            tx_signature: Signature::from([0; 64]),
            slot_index: 0,
        }
    }

    fn encrypt(
        &self,
        output: SppProofOutputUtxo,
        tree_id: u16,
    ) -> (WalletUtxo, ShieldedTransaction) {
        self.encrypt_beside(output, tree_id, Beside::Alone)
    }

    /// A packed transfer of `output` to the member, its blinding the one the ring derives.
    fn encrypt_beside(
        &self,
        mut output: SppProofOutputUtxo,
        tree_id: u16,
        beside: Beside,
    ) -> (WalletUtxo, ShieldedTransaction) {
        let signature = self.signature();
        let first_nullifier = right_align(&[0x70, self.sequence.get()]);
        let blinding_seed = right_align(&[0x5e, self.sequence.get()]);
        let transfer = Transfer {
            tx_key: ViewingKey::new(),
            ring: RING,
            first_nullifier,
            salt: SALT,
            blinding_seed,
            seed_out: derive_output_blinding_seed(&first_nullifier, &blinding_seed).unwrap(),
            tree_id,
            nullifiers: vec![first_nullifier],
        };
        let ring_output = Output::Ring {
            utxo: UtxoFields {
                owner_key: self.address.confidential_view_tag().expect("owner key"),
                nullifier_pk: self.address.nullifier_pubkey,
                asset_address: output.asset.asset,
                amount: output.amount,
                data_hash: output.data_hash.unwrap_or_default(),
                ring_data_hash: output.ring_data_hash.unwrap_or_default(),
            },
            recipient_u: self.address.viewing_pubkey.u(),
            tag: None,
        };
        let slot = transfer.slot(Rail::Packed, 0, &ring_output);
        output.blinding = slot.blinding;
        let mut held = self.held(&output, tree_id);
        held.tx_signature = signature;
        let mut published = slot.output;
        published.output_context = output_context(&held);
        let (outputs, slots, key_escrow) = match beside {
            Beside::Alone => (vec![ring_output], vec![published], false),
            Beside::EscrowedMember(other) => {
                let other = Output::Ring {
                    utxo: UtxoFields {
                        asset_address: output.asset.asset,
                        amount: 1,
                        ..other
                    },
                    recipient_u: x25519_u(0x77),
                    tag: None,
                };
                let mut paid = transfer.slot(Rail::Packed, 1, &other).output;
                paid.output_context.leaf_index = held.leaf_index + 1;
                (vec![ring_output, other], vec![published, paid], true)
            }
        };
        let disclosure = transfer.disclosure(Rail::Packed, &outputs, key_escrow);
        let mut transaction = transfer.publish(Publish {
            slots,
            disclosure: &disclosure,
            auditor: &self.auditor.pubkey(),
        });
        transaction.slot = u64::from(self.sequence.get());
        transaction.tx_signature = signature;
        let frame = transfer.frame(Frame {
            tx: &transaction,
            layout: disclosure.layout(),
            data_free: data_free(&outputs),
        });
        self.frames.lock().unwrap().push((signature, frame));
        (held, transaction)
    }

    fn merge(&self, inputs: &[WalletUtxo], tree_id: u16) -> (WalletUtxo, ShieldedTransaction) {
        let prepared = MergeTransaction::new_with_ring(inputs.to_vec(), RING, None)
            .expect("merge")
            .with_output_tree_id(tree_id)
            .encrypt(&self.member)
            .expect("encrypt merge");
        let first = prepared
            .input_utxos
            .first()
            .expect("merge input")
            .nullifier();
        let nullifiers = prepared
            .input_utxos
            .iter()
            .filter(|input| !input.is_compact())
            .map(|input| input.nullifier())
            .collect();
        let signature = self.signature();
        let mut held = self.held(&prepared.output_utxo, tree_id);
        held.ring_data_hash = Some(held.ring_data_hash.unwrap_or_default());
        held.tx_signature = signature;
        let transaction = ShieldedTransaction {
            slot: u64::from(self.sequence.get()),
            tx_signature: signature,
            event_index: Some(0),
            tx_viewing_pk: None,
            salt: None,
            output_slots: vec![OutputSlot {
                view_tag: first,
                output_context: output_context(&held),
                payload: encode_merge_output_data(MergeOutputDataRef {
                    salt: &prepared.output_ciphertext_salt,
                    ciphertext: &prepared.output_ciphertext,
                    ring_data_hash: Some(&prepared.output_utxo.ring_data_hash.unwrap_or_default()),
                }),
            }],
            messages: Vec::new(),
            nullifiers,
            proofless: false,
            ring_config: None,
            ring_program_id: Some(RING),
        };
        (held, transaction)
    }

    fn deposit(
        &self,
        output: SppProofOutputUtxo,
        tree_id: u16,
    ) -> (WalletUtxo, ShieldedTransaction) {
        let (mut held, mut transaction) = self.encrypt(output, tree_id);
        held.ring_data_hash = Some(held.ring_data_hash.unwrap_or_default());
        let opening = DepositOpening {
            owner_hash: self.address.owner_hash().unwrap(),
            blinding: zeroize::Zeroizing::new(held.utxo.blinding),
            owner_key: None,
        };
        let owner_utxo_hash =
            zolana_transaction::owner_utxo_hash(&opening.owner_hash, &opening.blinding).unwrap();
        let sealed = seal_deposits(&[opening], &self.auditor.pubkey()).unwrap();
        let mut encrypted = RingDepositPlaintext {
            blinding: held.utxo.blinding,
            utxo_data: None,
            memo: None,
            ring_data: Vec::new(),
        }
        .encrypt(&self.address.viewing_pubkey)
        .unwrap();
        encrypted.ciphertext = RingDepositAuditCapsule {
            slot_index: 0,
            eph_pk: sealed.ephemeral_pk.as_bytes(),
            ciphertext: &sealed.ciphertexts[0],
            recipient_ciphertext: &encrypted.ciphertext,
        }
        .encode();
        let group = deposit_fixture::group(
            RING,
            true,
            vec![(owner_utxo_hash, encrypted.ciphertext.clone())],
        );
        let origin = zolana_ring_client::ring_event_origin_in(&[group], 0, RING).unwrap();
        self.confirmed
            .lock()
            .unwrap()
            .push((transaction.tx_signature, origin.deposits));
        transaction.proofless = true;
        transaction.tx_viewing_pk = None;
        transaction.salt = None;
        transaction.messages.clear();
        transaction.output_slots[0].view_tag = self.address.viewing_pubkey.u();
        transaction.output_slots[0].payload =
            encode_encrypted_ring_deposit_output(EncryptedRingDepositOutput {
                owner_utxo_hash,
                asset: held.utxo.asset.asset.to_bytes(),
                amount: held.utxo.amount,
                data_hash: held.data_hash,
                ring_program_id: RING.to_bytes(),
                ring_data_hash: held.ring_data_hash.unwrap(),
                encrypted,
            });
        (held, transaction)
    }
}

/// Who else the transfer pays.
#[derive(Clone, Copy)]
enum Beside {
    Alone,
    /// Another member of a key-escrow ring, whose record the recovery does not hold.
    EscrowedMember(UtxoFields),
}

fn output_context(note: &WalletUtxo) -> OutputContext {
    OutputContext {
        hash: note.utxo_hash,
        tree_id: note.tree_id,
        leaf_index: note.leaf_index,
    }
}

#[derive(Default)]
struct History {
    transactions: Vec<ShieldedTransaction>,
    queried: Mutex<Vec<Vec<[u8; 32]>>>,
    confirmed: Mutex<Vec<(Signature, Vec<zolana_ring_client::ConfirmedDeposit>)>>,
    frames: Mutex<Vec<(Signature, Vec<u8>)>>,
    foreign: Vec<Signature>,
    confirmed_events: std::collections::HashMap<Signature, zolana_ring_client::ConfirmedEvent>,
    required_slots: Mutex<Vec<Option<u64>>>,
}

const INDEXED: u64 = 100;

impl History {
    fn read(&self, config: Option<IndexerRpcConfig>) -> Result<(), ClientError> {
        let required = config.and_then(|config| config.require_slot);
        self.required_slots.lock().unwrap().push(required);
        match required {
            Some(required) if required > INDEXED => Err(ClientError::IndexerNotCaughtUp {
                required,
                indexed: INDEXED,
                attempts: 1,
            }),
            _ => Ok(()),
        }
    }
}

#[async_trait::async_trait]
impl AsyncRpc for History {
    async fn get_shielded_transactions_by_ring(
        &self,
        options: zolana_client::RingHistoryOptions,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        self.read(config)?;
        assert_eq!(options.ring_program_id, RING);
        Ok(GetShieldedTransactionsByTagsResponse {
            context: Context {
                block_time: 0,
                slot: INDEXED,
            },
            transactions: self.transactions.clone(),
            output_tree_id: None,
            next_cursor: None,
            scanned_through: Some(Vec::new()),
        })
    }
    async fn get_shielded_transactions_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        _cursor: Option<Vec<u8>>,
        _limit: Option<u32>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        self.read(config)?;
        Ok(GetShieldedTransactionsByTagsResponse {
            context: Context {
                block_time: 0,
                slot: INDEXED,
            },
            transactions: self
                .transactions
                .iter()
                .filter(|tx| {
                    tx.messages
                        .iter()
                        .any(|message| tags.contains(&message.view_tag))
                        || tx
                            .output_slots
                            .iter()
                            .any(|slot| tags.contains(&slot.view_tag))
                })
                .cloned()
                .collect(),
            output_tree_id: None,
            next_cursor: None,
            scanned_through: Some(Vec::new()),
        })
    }

    async fn get_shielded_transactions_by_nullifiers(
        &self,
        nullifiers: Vec<[u8; 32]>,
        _cursor: Option<Vec<u8>>,
        _limit: Option<u32>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByNullifiersResponse, ClientError> {
        self.read(config)?;
        self.queried.lock().unwrap().push(nullifiers.clone());
        Ok(GetShieldedTransactionsByNullifiersResponse {
            context: Context {
                block_time: 0,
                slot: INDEXED,
            },
            transactions: self
                .transactions
                .iter()
                .filter(|tx| {
                    tx.nullifiers
                        .iter()
                        .any(|nullifier| nullifiers.contains(nullifier))
                })
                .cloned()
                .collect(),
            output_tree_id: None,
            next_cursor: Some(vec![1]),
            scanned_through: Some(vec![1]),
        })
    }
}

impl TransactionOrigin for History {
    async fn origin(
        &self,
        signature: Signature,
        _event_index: u16,
        _ring: Address,
    ) -> Result<RingOrigin, AuditError> {
        Ok(RingOrigin {
            event: self
                .confirmed_events
                .get(&signature)
                .cloned()
                .unwrap_or_else(|| {
                    origin_fixture::event(
                        self.transactions
                            .iter()
                            .find(|tx| tx.tx_signature == signature)
                            .expect("confirmed event"),
                    )
                }),
            ring_invoked: !self.foreign.contains(&signature),
            signers: Vec::new(),
            withdrawals: Vec::new(),
            deposits: self
                .confirmed
                .lock()
                .unwrap()
                .iter()
                .find(|(key, _)| *key == signature)
                .map(|(_, bindings)| bindings.clone())
                .unwrap_or_default(),
            merge_disclosure: None,
            transact: self
                .frames
                .lock()
                .unwrap()
                .iter()
                .find(|(key, _)| *key == signature)
                .map(|(_, frame)| frame.clone()),
        })
    }
}

#[tokio::test]
async fn a_key_escrow_ring_recovers_the_member_beside_other_owners() {
    let fixture = Fixture::new();
    let other = UtxoFields {
        owner_key: [0x66; 32],
        nullifier_pk: field(0x67),
        ..UtxoFields::default()
    };
    let (held, tx) = fixture.encrypt_beside(fixture.output(4), 2, Beside::EscrowedMember(other));
    let history = History {
        transactions: vec![tx],
        ..Default::default()
    };
    let recovery = RingRecovery::new(RING, &fixture.auditor)
        .with_mode(RingMode::Registry)
        .for_member(SourceMember {
            address: &fixture.address,
            nullifier_key: &fixture.member.nullifier_key,
        });
    let recovered = fixture.run(recovery, &history).await.unwrap();
    assert_eq!(recovered.utxos, [held]);
}

#[tokio::test]
async fn deposit_and_merge_tag_collisions_do_not_require_transfer_disclosure() {
    let fixture = Fixture::new();
    let (first, first_tx) = fixture.encrypt(fixture.output(4), 2);
    let (second, second_tx) = fixture.encrypt(fixture.output(5), 2);
    let (merged, mut merge_tx) = fixture.merge(&[first, second], 7);
    let (deposited, mut deposit_tx) = fixture.deposit(fixture.output(6), 3);
    let auditor_tag = zolana_ring_client::auditor_view_tag(&fixture.auditor.pubkey());
    for tx in [&mut merge_tx, &mut deposit_tx] {
        tx.output_slots[0].view_tag = auditor_tag;
        assert!(tx.messages.is_empty());
    }
    let history = History {
        transactions: vec![first_tx, second_tx, merge_tx, deposit_tx],
        ..Default::default()
    };
    let recovered = fixture.run(fixture.recovery(), &history).await.unwrap();
    assert_eq!(recovered.utxos.len(), 2);
    assert!(recovered.utxos.contains(&merged));
    assert!(recovered.utxos.contains(&deposited));
    assert!(recovered.unopened.is_empty());
    assert!(recovered.unsupported_deposits.is_empty());
}

#[tokio::test]
async fn missing_or_invalid_mandatory_disclosure_never_returns_a_partial_balance() {
    for missing in [true, false] {
        let fixture = Fixture::new();
        let (_, mut tx) = fixture.encrypt(fixture.output(4), 2);
        tx.output_slots[0].view_tag =
            zolana_ring_client::auditor_view_tag(&fixture.auditor.pubkey());
        if missing {
            tx.messages.clear();
        } else {
            // The last byte of slot 0's published asset field.
            tx.messages[0].data[65 + 63] ^= 1;
        }
        let history = History {
            transactions: vec![tx],
            ..Default::default()
        };
        let error = fixture
            .run(fixture.recovery(), &history)
            .await
            .err()
            .expect("mandatory disclosure failure");
        assert!(matches!(
            error,
            AuditError::MissingAuditorMessage | AuditError::UnopenedOutput { slot: 0, .. }
        ));
    }
}

#[tokio::test]
async fn follows_chained_merges_across_trees_and_keeps_only_the_live_successor() {
    let fixture = Fixture::new();
    let (first, first_tx) = fixture.encrypt(fixture.output(4), 2);
    let (second, second_tx) = fixture.encrypt(fixture.output(5), 2);
    let (third, third_tx) = fixture.encrypt(fixture.output(6), 7);
    let (merged, merge_tx) = fixture.merge(&[first, second], 7);
    let (successor, successor_tx) = fixture.merge(&[merged, third], 9);
    let history = History {
        transactions: vec![successor_tx, merge_tx, third_tx, second_tx, first_tx],
        ..Default::default()
    };
    let recovered = fixture
        .run(fixture.recovery(), &history)
        .await
        .expect("recover");
    assert_eq!(recovered.utxos, vec![successor.clone()]);
    assert!(recovered.unopened.is_empty());
    assert!(history
        .queried
        .lock()
        .unwrap()
        .iter()
        .any(|query| query.contains(&successor.nullifier)));
}

#[tokio::test]
async fn checks_whether_a_rebuilt_successor_was_spent_without_an_auditor_message() {
    let fixture = Fixture::new();
    let (first, first_tx) = fixture.encrypt(fixture.output(4), 2);
    let (second, second_tx) = fixture.encrypt(fixture.output(5), 2);
    let (merged, merge_tx) = fixture.merge(&[first, second], 7);
    let mut burn = merge_tx.clone();
    burn.tx_signature = fixture.signature();
    burn.nullifiers = vec![merged.nullifier];
    burn.output_slots.clear();
    let history = History {
        transactions: vec![first_tx, second_tx, merge_tx, burn],
        ..Default::default()
    };
    let recovered = fixture
        .run(fixture.recovery(), &history)
        .await
        .expect("recover");
    assert!(recovered.utxos.is_empty());
    assert!(recovered.unopened.is_empty());
}

#[tokio::test]
async fn a_merge_found_through_one_held_input_decrypts_with_the_whole_total() {
    let fixture = Fixture::new();
    let (first, first_tx) = fixture.encrypt(fixture.output(4), 2);
    let (second, second_tx) = fixture.encrypt(fixture.output(5), 2);
    let (merged, merge_tx) = fixture.merge(&[first, second], 7);
    for known in [first_tx, second_tx] {
        let history = History {
            transactions: vec![known, merge_tx.clone()],
            ..Default::default()
        };
        let recovered = fixture
            .run(fixture.recovery(), &history)
            .await
            .expect("recover");
        assert_eq!(recovered.utxos, vec![merged.clone()]);
        assert_eq!(merged.utxo.amount, 9);
        assert!(recovered.unopened.is_empty());
    }
}

#[tokio::test]
async fn a_forged_merge_leaf_never_becomes_a_spendable_note() {
    let fixture = Fixture::new();
    let (first, first_tx) = fixture.encrypt(fixture.output(4), 2);
    let (second, second_tx) = fixture.encrypt(fixture.output(5), 2);
    let (_, mut merge_tx) = fixture.merge(&[first, second], 7);
    merge_tx.output_slots[0].output_context.hash = [8; 32];
    let history = History {
        transactions: vec![first_tx, second_tx, merge_tx],
        ..Default::default()
    };
    let recovered = fixture
        .run(fixture.recovery(), &history)
        .await
        .expect("recover");
    assert!(recovered.utxos.is_empty());
    assert_eq!(recovered.unopened, vec![[8; 32]]);
}

#[tokio::test]
async fn a_merge_from_another_program_cannot_supply_recovery_outputs() {
    let fixture = Fixture::new();
    let (first, first_tx) = fixture.encrypt(fixture.output(4), 2);
    let (second, second_tx) = fixture.encrypt(fixture.output(5), 2);
    let (_, merge_tx) = fixture.merge(&[first.clone(), second.clone()], 7);
    let history = History {
        foreign: vec![merge_tx.tx_signature],
        transactions: vec![first_tx, second_tx, merge_tx],
        ..Default::default()
    };
    let recovered = fixture
        .run(fixture.recovery(), &history)
        .await
        .expect("recover");
    assert_eq!(recovered.utxos, vec![first, second]);
}

#[tokio::test]
async fn proof_bound_hash_metadata_is_recovered_without_a_caller_resolver() {
    let fixture = Fixture::new();
    let output = fixture
        .output(9)
        .with_ring_data(RING, vec![1, 2, 3], [4; 32])
        .with_utxo_data(vec![5, 6], [7; 32]);
    let (mut held, transaction) = fixture.encrypt(output, 7);
    held.utxo.data = Data::default();
    let history = History {
        transactions: vec![transaction],
        ..Default::default()
    };
    let recovered = fixture
        .run(fixture.recovery(), &history)
        .await
        .expect("recover");
    assert!(recovered.unopened.is_empty());
    assert_eq!(recovered.utxos, vec![held]);
}

#[tokio::test]
async fn recovery_uses_disclosed_ownership_even_when_recipient_delivery_is_unusable() {
    for mutation in 0..3 {
        let fixture = Fixture::new();
        let (held, mut transaction) = fixture.encrypt(fixture.output(9), 7);
        match mutation {
            0 => *transaction.output_slots[0].payload.last_mut().unwrap() ^= 1,
            1 => transaction.output_slots[0].view_tag = [0x5a; 32],
            _ => transaction.output_slots[0].payload = vec![0xff],
        }
        let history = History {
            transactions: vec![transaction],
            ..Default::default()
        };
        let recovered = fixture.run(fixture.recovery(), &history).await.unwrap();
        assert_eq!(recovered.utxos, vec![held]);
        assert!(recovered.unopened.is_empty());
    }
}

#[tokio::test]
async fn an_unknown_disclosed_asset_is_unopened_until_its_utxo_is_confirmed_spent() {
    let fixture = Fixture::new();
    let mut output = fixture.output(9);
    output.asset = Mint::new(Address::new_from_array([0x5a; 32]), 99);
    let (held, transaction) = fixture.encrypt(output, 7);
    let mut history = History {
        transactions: vec![transaction.clone()],
        ..Default::default()
    };
    let recovered = fixture.run(fixture.recovery(), &history).await.unwrap();
    assert!(recovered.utxos.is_empty());
    assert_eq!(recovered.unopened, vec![held.utxo_hash]);
    let mut spend = transaction;
    spend.tx_signature = fixture.signature();
    spend.messages.clear();
    spend.output_slots.clear();
    spend.nullifiers = vec![held.nullifier];
    history.transactions.push(spend);
    let recovered = fixture.run(fixture.recovery(), &history).await.unwrap();
    assert!(recovered.utxos.is_empty());
    assert!(recovered.unopened.is_empty());
}

#[tokio::test]
async fn spent_notes_with_missing_hash_metadata_do_not_block_live_recovery() {
    let fixture = Fixture::new();
    let (held, transaction) =
        fixture.encrypt(fixture.output(9).with_ring_data_hash(RING, [4; 32]), 7);
    let mut spend = transaction.clone();
    spend.tx_signature = fixture.signature();
    spend.messages.clear();
    spend.output_slots.clear();
    spend.nullifiers = vec![held.nullifier];
    let history = History {
        transactions: vec![transaction, spend],
        ..Default::default()
    };
    let recovered = fixture
        .run(fixture.recovery(), &history)
        .await
        .expect("recover");
    assert!(recovered.utxos.is_empty());
    assert!(recovered.unopened.is_empty());
    assert!(history
        .queried
        .lock()
        .unwrap()
        .iter()
        .any(|query| query.contains(&held.nullifier)));
}

#[tokio::test]
async fn direct_deposits_are_reported_separately_without_claiming_they_are_unspent() {
    let fixture = Fixture::new();
    let (held, mut transaction) = fixture.encrypt(fixture.output(9), 7);
    transaction.proofless = true;
    transaction.tx_viewing_pk = None;
    transaction.salt = None;
    transaction.messages.clear();
    transaction.output_slots[0].view_tag = fixture.address.viewing_pubkey.u();
    let deposit = EncryptedRingDepositOutput {
        owner_utxo_hash: zolana_transaction::owner_utxo_hash(
            &fixture.address.owner_hash().expect("owner"),
            &held.utxo.blinding,
        )
        .expect("owner hash"),
        asset: SOL_MINT.to_bytes(),
        amount: held.utxo.amount,
        data_hash: None,
        ring_program_id: RING.to_bytes(),
        ring_data_hash: [0; 32],
        encrypted: RingDepositPlaintext {
            blinding: held.utxo.blinding,
            utxo_data: None,
            memo: None,
            ring_data: Vec::new(),
        }
        .encrypt(&fixture.address.viewing_pubkey)
        .expect("deposit encryption"),
    };
    transaction.output_slots[0].payload = encode_encrypted_ring_deposit_output(deposit.clone());
    let mut foreign_ring = transaction.clone();
    foreign_ring.tx_signature = fixture.signature();
    let mut foreign = deposit;
    foreign.ring_program_id = [33; 32];
    foreign_ring.output_slots[0].payload = encode_encrypted_ring_deposit_output(foreign);
    foreign_ring.output_slots[0].output_context.hash = [33; 32];
    let mut wrong_origin = transaction.clone();
    wrong_origin.tx_signature = fixture.signature();
    wrong_origin.output_slots[0].output_context.hash = [44; 32];
    let history = History {
        foreign: vec![wrong_origin.tx_signature],
        transactions: vec![transaction, foreign_ring, wrong_origin],
        ..Default::default()
    };
    let recovered = fixture
        .run(fixture.recovery(), &history)
        .await
        .expect("recover");
    assert!(recovered.utxos.is_empty());
    assert!(recovered.unopened.is_empty());
    assert_eq!(recovered.unsupported_deposits, vec![held.utxo_hash]);
}

#[tokio::test]
async fn every_read_requires_the_slot_and_an_indexer_behind_it_fails_the_recovery() {
    let fixture = Fixture::new();
    let (first, first_tx) = fixture.encrypt(fixture.output(4), 2);
    let (second, second_tx) = fixture.encrypt(fixture.output(5), 2);
    let (merged, merge_tx) = fixture.merge(&[first, second], 7);
    let history = History {
        transactions: vec![first_tx, second_tx, merge_tx],
        ..Default::default()
    };
    let recovery = |slot| {
        RingRecovery::new(RING, &fixture.auditor)
            .with_indexer_config(IndexerRpcConfig::at_slot(slot))
            .for_member(SourceMember {
                address: &fixture.address,
                nullifier_key: &fixture.member.nullifier_key,
            })
    };

    let recovered = fixture
        .run(recovery(INDEXED), &history)
        .await
        .expect("recover");
    assert_eq!(recovered.utxos, vec![merged]);
    let required = std::mem::take(&mut *history.required_slots.lock().unwrap());
    assert!(required.len() >= 3, "{required:?}");
    assert!(required.iter().all(|slot| *slot == Some(INDEXED)));

    assert!(matches!(
        fixture.run(recovery(INDEXED + 1), &history).await,
        Err(AuditError::Client(ClientError::IndexerNotCaughtUp { .. }))
    ));
}

#[tokio::test]
async fn a_query_bound_never_returns_an_unchecked_merge_successor() {
    let fixture = Fixture::new();
    let (first, first_tx) = fixture.encrypt(fixture.output(4), 2);
    let (second, second_tx) = fixture.encrypt(fixture.output(5), 2);
    let (_, merge_tx) = fixture.merge(&[first, second], 7);
    let history = History {
        transactions: vec![first_tx, second_tx, merge_tx],
        ..Default::default()
    };
    let recovery = RingRecovery::new(RING, &fixture.auditor)
        .with_max_pages(std::num::NonZeroUsize::MIN)
        .for_member(SourceMember {
            address: &fixture.address,
            nullifier_key: &fixture.member.nullifier_key,
        });
    assert!(matches!(
        fixture.run(recovery, &history).await,
        Err(AuditError::IncompleteScan)
    ));
}

#[tokio::test]
async fn audited_deposit_recovery_preserves_committed_data_hashes() {
    let fixture = Fixture::new();
    let output = SppProofOutputUtxo {
        data_hash: Some([3; 32]),
        ..fixture.output(9).with_ring_data_hash(RING, [4; 32])
    };
    let (held, mut transaction) = fixture.deposit(output, 7);
    transaction.output_slots[0].view_tag = [88; 32];
    let history = History {
        transactions: vec![transaction],
        ..Default::default()
    };
    let recovered = fixture.run(fixture.recovery(), &history).await.unwrap();
    assert_eq!(recovered.utxos, vec![held]);
    assert!(recovered.unopened.is_empty());
    assert!(recovered.unsupported_deposits.is_empty());
}

#[tokio::test]
async fn unknown_audited_deposit_mints_remain_unresolved_without_hiding_other_utxos() {
    let fixture = Fixture::new();
    let mint = Mint::new(Address::new_from_array([71; 32]), 2);
    let (known, known_tx) = fixture.deposit(fixture.output(4), 2);
    let mut unknown_output = fixture.output(9);
    unknown_output.asset = mint;
    let (unknown, unknown_tx) = fixture.deposit(unknown_output, 7);
    let mut history = History {
        transactions: vec![known_tx, unknown_tx.clone()],
        ..Default::default()
    };

    let recovered = fixture.run(fixture.recovery(), &history).await.unwrap();
    assert_eq!(recovered.utxos, vec![known.clone()]);
    assert_eq!(recovered.unopened, vec![unknown.utxo_hash]);
    assert!(recovered.unsupported_deposits.is_empty());
    assert_eq!(recovered.unknown_mints, [mint.asset].into_iter().collect());
    assert!(history
        .queried
        .lock()
        .unwrap()
        .iter()
        .any(|batch| batch.contains(&unknown.nullifier)));

    let assets = AssetRegistry::new([(mint.asset_id, mint.asset)]).unwrap();
    let recovered = fixture
        .recovery()
        .run(&history, &history, &assets)
        .await
        .unwrap();
    assert_eq!(recovered.utxos, vec![known.clone(), unknown.clone()]);
    assert!(recovered.unopened.is_empty());
    assert!(recovered.unknown_mints.is_empty());

    let mut spent = unknown_tx;
    spent.tx_signature = fixture.signature();
    spent.proofless = false;
    spent.nullifiers = vec![unknown.nullifier];
    spent.output_slots.clear();
    history.transactions.push(spent);
    let recovered = fixture.run(fixture.recovery(), &history).await.unwrap();
    assert_eq!(recovered.utxos, vec![known]);
    assert!(recovered.unopened.is_empty());
}

#[tokio::test]
async fn audited_deposits_seed_merge_recovery_and_successor_spend_checks() {
    let fixture = Fixture::new();
    let (first, first_tx) = fixture.deposit(fixture.output(4), 2);
    let (second, second_tx) = fixture.deposit(fixture.output(5), 2);
    let (merged, merge_tx) = fixture.merge(&[first, second], 7);
    let mut history = History {
        transactions: vec![first_tx, second_tx, merge_tx.clone()],
        ..Default::default()
    };
    let recovered = fixture.run(fixture.recovery(), &history).await.unwrap();
    assert_eq!(recovered.utxos, vec![merged.clone()]);
    assert!(recovered.unsupported_deposits.is_empty());
    let mut spent = merge_tx;
    spent.tx_signature = fixture.signature();
    spent.nullifiers = vec![merged.nullifier];
    spent.output_slots.clear();
    history.transactions.push(spent);
    let recovered = fixture.run(fixture.recovery(), &history).await.unwrap();
    assert!(recovered.utxos.is_empty());
    assert!(recovered.unopened.is_empty());
}

#[tokio::test]
async fn invalid_deposit_openings_remain_unknown_and_a_forged_owned_leaf_fails() {
    let fixture = Fixture::new();
    let (_, transaction) = fixture.deposit(fixture.output(9), 7);
    let mut wrong_leaf = transaction.clone();
    wrong_leaf.output_slots[0].output_context.hash = [1; 32];
    let mut wrong_ciphertext = transaction;
    let slot = &mut wrong_ciphertext.output_slots[0];
    let mut output =
        zolana_event_parser::decode_encrypted_ring_deposit_output_data(&slot.payload).unwrap();
    output.encrypted.ciphertext[50] ^= 1;
    slot.payload = encode_encrypted_ring_deposit_output(output);
    let history = History {
        transactions: vec![wrong_leaf],
        ..Default::default()
    };
    assert!(matches!(
        fixture.run(fixture.recovery(), &history).await,
        Err(AuditError::DepositOpeningMismatch)
    ));
    let commitment = wrong_ciphertext.output_slots[0].output_context.hash;
    let history = History {
        transactions: vec![wrong_ciphertext],
        ..Default::default()
    };
    let result = fixture.run(fixture.recovery(), &history).await.unwrap();
    assert!(result.utxos.is_empty());
    assert_eq!(result.unsupported_deposits, vec![commitment]);
}

#[tokio::test]
async fn an_unconfirmed_anonymous_deposit_remains_explicitly_unsupported() {
    let fixture = Fixture::new();
    let (held, mut indexed) = fixture.deposit(fixture.output(9), 7);
    indexed.output_slots[0].view_tag = [0; 32];
    fixture.confirmed.lock().unwrap().clear();
    let history = History {
        transactions: vec![indexed],
        ..Default::default()
    };
    let recovered = fixture.run(fixture.recovery(), &history).await.unwrap();
    assert!(recovered.utxos.is_empty());
    assert_eq!(recovered.unsupported_deposits, vec![held.utxo_hash]);
}

#[tokio::test]
async fn indexed_owner_key_tampering_is_rejected_against_confirmed_deposit() {
    let fixture = Fixture::new();
    let (_, mut indexed) = fixture.deposit(fixture.output(9), 7);
    let slot = &mut indexed.output_slots[0];
    let mut output =
        zolana_event_parser::decode_encrypted_ring_deposit_output_data(&slot.payload).unwrap();
    output.encrypted.ciphertext[42 + 64] ^= 1;
    slot.payload = encode_encrypted_ring_deposit_output(output);
    let commitment = indexed.output_slots[0].output_context.hash;
    let history = History {
        transactions: vec![indexed],
        ..Default::default()
    };
    let result = fixture.run(fixture.recovery(), &history).await.unwrap();
    assert!(result.utxos.is_empty());
    assert_eq!(result.unsupported_deposits, vec![commitment]);
}

#[tokio::test]
async fn an_indexer_cannot_attach_a_new_valid_disclosure_to_a_confirmed_transfer() {
    let fixture = Fixture::new();
    let (_, confirmed) = fixture.encrypt(fixture.output(4), 2);
    let (_, mut forged) = fixture.encrypt(fixture.output(999), 2);
    forged.tx_signature = confirmed.tx_signature;
    let history = History {
        transactions: vec![forged],
        confirmed_events: std::collections::HashMap::from([(
            confirmed.tx_signature,
            origin_fixture::event(&confirmed),
        )]),
        ..Default::default()
    };
    assert!(matches!(
        fixture.run(fixture.recovery(), &history).await,
        Err(AuditError::ConfirmedEventMismatch)
    ));
}

#[tokio::test]
async fn an_indexer_cannot_invent_a_spend_of_a_recoverable_utxo() {
    let fixture = Fixture::new();
    let (held, transaction) = fixture.encrypt(fixture.output(4), 2);
    let mut unrelated = transaction.clone();
    unrelated.tx_signature = fixture.signature();
    unrelated.messages.clear();
    unrelated.output_slots.clear();
    unrelated.tx_viewing_pk = None;
    unrelated.salt = None;
    unrelated.nullifiers = vec![[55; 32]];
    let confirmed = origin_fixture::event(&unrelated);
    unrelated.nullifiers = vec![held.nullifier];
    let history = History {
        confirmed_events: std::collections::HashMap::from([(unrelated.tx_signature, confirmed)]),
        transactions: vec![unrelated, transaction],
        ..Default::default()
    };
    assert!(matches!(
        fixture.run(fixture.recovery(), &history).await,
        Err(AuditError::ConfirmedEventMismatch)
    ));
}

#[tokio::test]
async fn an_indexer_cannot_relabel_a_confirmed_deposit_or_move_its_output() {
    let fixture = Fixture::new();
    let (_, confirmed) = fixture.deposit(fixture.output(4), 2);
    for alter_kind in [false, true] {
        let mut forged = confirmed.clone();
        if alter_kind {
            forged.proofless = false;
        } else {
            forged.output_slots[0].output_context.leaf_index += 1;
        }
        let history = History {
            transactions: vec![forged],
            confirmed_events: std::collections::HashMap::from([(
                confirmed.tx_signature,
                origin_fixture::event(&confirmed),
            )]),
            ..Default::default()
        };
        assert!(matches!(
            fixture.run(fixture.recovery(), &history).await,
            Err(AuditError::ConfirmedEventMismatch)
        ));
    }
}

#[tokio::test]
async fn a_foreign_invocation_cannot_mark_a_ring_utxo_spent() {
    let fixture = Fixture::new();
    let (held, transaction) = fixture.encrypt(fixture.output(4), 2);
    let mut forged = transaction.clone();
    forged.tx_signature = fixture.signature();
    forged.messages.clear();
    forged.output_slots.clear();
    forged.tx_viewing_pk = None;
    forged.salt = None;
    forged.nullifiers = vec![held.nullifier];
    let history = History {
        foreign: vec![forged.tx_signature],
        transactions: vec![forged, transaction],
        ..Default::default()
    };
    let recovered = fixture.run(fixture.recovery(), &history).await.unwrap();
    assert_eq!(recovered.utxos, vec![held]);
}

#[tokio::test]
async fn unknown_merge_mints_remain_unresolved_and_still_follow_spends() {
    let fixture = Fixture::new();
    let mint = Mint::new(Address::new_from_array([71; 32]), 2);
    let mut output = fixture.output(4);
    output.asset = mint;
    let (first, first_tx) = fixture.encrypt(output.clone(), 2);
    output.amount = 5;
    let (second, _) = fixture.encrypt(output, 2);
    let (merged, merge_tx) = fixture.merge(&[first, second], 7);
    let mut history = History {
        transactions: vec![first_tx, merge_tx.clone()],
        ..Default::default()
    };
    let recovered = fixture.run(fixture.recovery(), &history).await.unwrap();
    assert!(recovered.utxos.is_empty());
    assert_eq!(recovered.unopened, vec![merged.utxo_hash]);
    assert_eq!(recovered.unknown_mints, [mint.asset].into_iter().collect());
    assert!(history
        .queried
        .lock()
        .unwrap()
        .iter()
        .any(|batch| batch.contains(&merged.nullifier)));
    let assets = AssetRegistry::new([(mint.asset_id, mint.asset)]).unwrap();
    let recovered = fixture
        .recovery()
        .run(&history, &history, &assets)
        .await
        .unwrap();
    assert_eq!(recovered.utxos, vec![merged.clone()]);
    assert!(recovered.unopened.is_empty());
    assert!(recovered.unknown_mints.is_empty());

    let mut spent = merge_tx;
    spent.tx_signature = fixture.signature();
    spent.nullifiers = vec![merged.nullifier];
    spent.output_slots.clear();
    history.transactions.push(spent);
    let recovered = fixture.run(fixture.recovery(), &history).await.unwrap();
    assert!(recovered.utxos.is_empty());
    assert!(recovered.unopened.is_empty());
}

#[tokio::test]
async fn unproved_recipient_metadata_cannot_block_plain_utxo_recovery_or_merge() {
    let fixture = Fixture::new();
    let mut output = fixture.output(9);
    output.data = Data::new(vec![
        DataRecord::UtxoData(vec![8]),
        DataRecord::Memo(vec![9]),
    ]);
    let (mut held, transaction) = fixture.encrypt(output, 7);
    assert!(MergeTransaction::new_with_ring(vec![held.clone()], RING, None).is_err());
    let history = History {
        transactions: vec![transaction],
        ..Default::default()
    };
    let recovered = fixture.run(fixture.recovery(), &history).await.unwrap();
    held.utxo.data = Data::default();
    assert_eq!(recovered.utxos, vec![held]);
    assert!(recovered.unopened.is_empty());
    assert!(recovered.utxos[0].data_hash.is_none());
    assert!(MergeTransaction::new_with_ring(recovered.utxos, RING, None).is_ok());
}
