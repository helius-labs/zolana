use custom_ring_interface::RingDepositAuditCapsule;
use std::cell::{Cell, RefCell};

use solana_address::Address;
use solana_signature::Signature;
use zolana_client::{
    rpc::GetShieldedTransactionsByNullifiersResponse, ClientError, Context,
    GetShieldedTransactionsByTagsResponse, IndexerRpcConfig, ProofInputUtxo, Rpc,
};
use zolana_event::{encode_encrypted_ring_deposit_output, EncryptedRingDepositOutput};
use zolana_keypair::{ShieldedAddress, ShieldedKeypair, ViewingKey};
use zolana_ring_client::{
    AuditedOutput, AuditorEncryption, DepositOpening, DepositSeal, MemberRecovery, NoteDataHashes,
    OriginError, RecoveredNotes, RecoveryEnvironment, RecoveryError, RingEnvironment, RingOrigin,
    RingRecovery, SourceMember, TransactionOrigin,
};
use zolana_transaction::{
    instructions::merge::MergeTransaction,
    serialization::confidential::{Confidential, ConfidentialEncode, ConfidentialOutputPlaintext},
    serialization::ring_deposit::RingDepositPlaintext,
    AssetRegistry, Mint, OutputContext, OutputSlot, ShieldedTransaction, SppProofOutputUtxo, Utxo,
    UtxoSerialization, WalletUtxo, SOL_ASSET_ID, SOL_MINT,
};

const RING: Address = Address::new_from_array([42; 32]);
const SALT: [u8; 16] = [7; 16];

struct Fixture {
    member: ShieldedKeypair,
    address: ShieldedAddress,
    auditor: ViewingKey,
    sequence: Cell<u8>,
}

impl Fixture {
    fn new() -> Self {
        let member = ShieldedKeypair::new_ed25519().expect("member");
        Self {
            address: member.shielded_address().expect("address"),
            member,
            auditor: ViewingKey::new(),
            sequence: Cell::new(0),
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

    fn run(
        &self,
        recovery: MemberRecovery<'_>,
        history: &History,
    ) -> Result<RecoveredNotes, RecoveryError> {
        recovery.run(RecoveryEnvironment {
            ring: RingEnvironment {
                indexer: history,
                origin: history,
            },
            assets: &AssetRegistry::default(),
        })
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
            utxo,
            data_hash: output.data_hash,
            ring_data_hash: output.ring_data_hash,
            tree_id,
            leaf_index: u64::from(self.sequence.get()),
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
        let tx_key = ViewingKey::new();
        let signature = self.signature();
        let mut held = self.held(&output, tree_id);
        held.tx_signature = signature;
        let proof_output =
            ProofInputUtxo::try_from((&output, tree_id)).expect("proof output opening");
        let encoded = Confidential::encode_plaintext(
            &ConfidentialOutputPlaintext {
                asset_id: SOL_ASSET_ID,
                amount: output.amount,
                blinding: output.blinding,
                ring_program_id: output.ring_program_id,
                data: output.data,
            },
            self.address.confidential_view_tag().expect("tag"),
            &ConfidentialEncode {
                tx: tx_key.clone(),
                recipient_pubkey: self.address.viewing_pubkey,
                salt: SALT,
                slot_index: 0,
            },
        )
        .expect("encrypt");
        let message = AuditorEncryption::new_with_outputs(
            &tx_key,
            &self.auditor.pubkey(),
            SALT,
            &[proof_output],
        )
        .expect("audit encryption")
        .message
        .to_message_data(&self.auditor.pubkey());
        let transaction = ShieldedTransaction {
            slot: u64::from(self.sequence.get()),
            tx_signature: signature,
            event_index: Some(0),
            tx_viewing_pk: Some(tx_key.pubkey()),
            salt: Some(SALT),
            output_slots: vec![OutputSlot {
                view_tag: encoded.view_tag,
                output_context: output_context(&held),
                payload: encoded.data,
            }],
            messages: vec![message],
            nullifiers: Vec::new(),
            proofless: false,
            ring_config: None,
            ring_program_id: Some(RING),
        };
        (held, transaction)
    }

    fn merge(&self, inputs: &[WalletUtxo], tree_id: u16) -> (WalletUtxo, ShieldedTransaction) {
        let prepared = MergeTransaction::new_with_ring(inputs.to_vec(), RING, Some([6; 32]))
            .expect("merge")
            .with_output_tree_id(tree_id)
            .encrypt(&self.member)
            .expect("encrypt merge");
        let first = prepared.input_utxos[0].nullifier();
        let nullifiers = prepared
            .input_utxos
            .iter()
            .map(|input| input.nullifier())
            .collect();
        let signature = self.signature();
        let mut held = self.held(&prepared.output_utxo, tree_id);
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
                payload: prepared
                    .output_utxo
                    .ring_data_hash
                    .expect("ring hash")
                    .to_vec(),
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
        };
        let owner_utxo_hash =
            zolana_transaction::owner_utxo_hash(&opening.owner_hash, &opening.blinding).unwrap();
        let sealed = DepositSeal {
            openings: &[opening],
            auditor_pk: &self.auditor.pubkey(),
        }
        .seal()
        .unwrap();
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
        transaction.proofless = true;
        transaction.tx_viewing_pk = None;
        transaction.salt = None;
        transaction.messages.clear();
        transaction.output_slots[0].view_tag = self.address.viewing_pubkey.x();
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
    queried: RefCell<Vec<Vec<[u8; 32]>>>,
    foreign: Vec<Signature>,
}

impl Rpc for History {
    fn get_shielded_transactions_by_ring(
        &self,
        options: zolana_client::RingHistoryOptions,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        assert_eq!(options.ring_program_id, RING);
        Ok(GetShieldedTransactionsByTagsResponse {
            context: Context {
                block_time: 0,
                slot: 100,
            },
            transactions: self.transactions.clone(),
            output_tree_id: None,
            next_cursor: None,
            scanned_through: Some(Vec::new()),
        })
    }
    fn get_shielded_transactions_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        _cursor: Option<Vec<u8>>,
        _limit: Option<u32>,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        Ok(GetShieldedTransactionsByTagsResponse {
            context: Context {
                block_time: 0,
                slot: 100,
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

    fn get_shielded_transactions_by_nullifiers(
        &self,
        nullifiers: Vec<[u8; 32]>,
        _cursor: Option<Vec<u8>>,
        _limit: Option<u32>,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByNullifiersResponse, ClientError> {
        self.queried.borrow_mut().push(nullifiers.clone());
        Ok(GetShieldedTransactionsByNullifiersResponse {
            context: Context {
                block_time: 0,
                slot: 100,
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
    fn origin(
        &self,
        signature: Signature,
        _event_index: u16,
        _ring: Address,
    ) -> Result<RingOrigin, OriginError> {
        Ok(RingOrigin {
            ring_invoked: !self.foreign.contains(&signature),
            signers: Vec::new(),
            withdrawals: Vec::new(),
        })
    }
}

#[test]
fn follows_chained_merges_across_trees_and_keeps_only_the_live_successor() {
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
    let recovered = fixture.run(fixture.recovery(), &history).expect("recover");
    assert_eq!(recovered.utxos, vec![successor.clone()]);
    assert!(recovered.unopened.is_empty());
    assert!(history
        .queried
        .borrow()
        .iter()
        .any(|query| query.contains(&successor.nullifier)));
}

#[test]
fn checks_whether_a_rebuilt_successor_was_spent_without_an_auditor_message() {
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
    let recovered = fixture.run(fixture.recovery(), &history).expect("recover");
    assert!(recovered.utxos.is_empty());
    assert!(recovered.unopened.is_empty());
}

#[test]
fn incomplete_merge_history_reports_the_successor_without_restoring_spent_inputs() {
    let fixture = Fixture::new();
    let (first, first_tx) = fixture.encrypt(fixture.output(4), 2);
    let (second, second_tx) = fixture.encrypt(fixture.output(5), 2);
    let (merged, merge_tx) = fixture.merge(&[first, second], 7);
    for known in [first_tx, second_tx] {
        let history = History {
            transactions: vec![known, merge_tx.clone()],
            ..Default::default()
        };
        let recovered = fixture.run(fixture.recovery(), &history).expect("recover");
        assert!(recovered.utxos.is_empty());
        assert_eq!(recovered.unopened, vec![merged.utxo_hash]);
    }
}

#[test]
fn a_forged_merge_leaf_never_becomes_a_spendable_note() {
    let fixture = Fixture::new();
    let (first, first_tx) = fixture.encrypt(fixture.output(4), 2);
    let (second, second_tx) = fixture.encrypt(fixture.output(5), 2);
    let (_, mut merge_tx) = fixture.merge(&[first, second], 7);
    merge_tx.output_slots[0].output_context.hash = [8; 32];
    let history = History {
        transactions: vec![first_tx, second_tx, merge_tx],
        ..Default::default()
    };
    let recovered = fixture.run(fixture.recovery(), &history).expect("recover");
    assert!(recovered.utxos.is_empty());
    assert_eq!(recovered.unopened, vec![[8; 32]]);
}

#[test]
fn a_merge_from_another_program_cannot_supply_recovery_outputs() {
    let fixture = Fixture::new();
    let (first, first_tx) = fixture.encrypt(fixture.output(4), 2);
    let (second, second_tx) = fixture.encrypt(fixture.output(5), 2);
    let (_, merge_tx) = fixture.merge(&[first, second], 7);
    let history = History {
        foreign: vec![merge_tx.tx_signature],
        transactions: vec![first_tx, second_tx, merge_tx],
        ..Default::default()
    };
    let recovered = fixture.run(fixture.recovery(), &history).expect("recover");
    assert!(recovered.utxos.is_empty());
}

#[test]
fn proof_bound_hash_metadata_is_recovered_without_a_caller_resolver() {
    let fixture = Fixture::new();
    let output = fixture
        .output(9)
        .with_ring_data(RING, vec![1, 2, 3], [4; 32])
        .with_utxo_data(vec![5, 6], [7; 32]);
    let (held, transaction) = fixture.encrypt(output, 7);
    let history = History {
        transactions: vec![transaction],
        ..Default::default()
    };
    let recovered = fixture.run(fixture.recovery(), &history).expect("recover");
    assert!(recovered.unopened.is_empty());
    assert_eq!(recovered.utxos, vec![held]);
}

#[test]
fn caller_hash_metadata_cannot_override_the_proof_bound_opening() {
    let fixture = Fixture::new();
    let (held, transaction) =
        fixture.encrypt(fixture.output(9).with_ring_data_hash(RING, [4; 32]), 7);
    let history = History {
        transactions: vec![transaction],
        ..Default::default()
    };
    let resolver = |output: &AuditedOutput, context: &OutputContext| {
        assert_eq!(output.data, held.utxo.data);
        assert_eq!(context.hash, held.utxo_hash);
        Ok(Some(NoteDataHashes {
            ring_data_hash: Some([5; 32]),
            ..Default::default()
        }))
    };
    let recovered = fixture
        .run(fixture.recovery().with_data_hashes(&resolver), &history)
        .expect("recover");
    assert!(recovered.unopened.is_empty());
    assert_eq!(recovered.utxos, vec![held]);
}

#[test]
fn spent_notes_with_missing_hash_metadata_do_not_block_live_recovery() {
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
    let recovered = fixture.run(fixture.recovery(), &history).expect("recover");
    assert!(recovered.utxos.is_empty());
    assert!(recovered.unopened.is_empty());
    assert!(history
        .queried
        .borrow()
        .iter()
        .any(|query| query.contains(&held.nullifier)));
}

#[test]
fn direct_deposits_are_reported_separately_without_claiming_they_are_unspent() {
    let fixture = Fixture::new();
    let (held, mut transaction) = fixture.encrypt(fixture.output(9), 7);
    transaction.proofless = true;
    transaction.tx_viewing_pk = None;
    transaction.salt = None;
    transaction.messages.clear();
    transaction.output_slots[0].view_tag = fixture.address.viewing_pubkey.x();
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
    let recovered = fixture.run(fixture.recovery(), &history).expect("recover");
    assert!(recovered.utxos.is_empty());
    assert!(recovered.unopened.is_empty());
    assert_eq!(recovered.unsupported_deposits, vec![held.utxo_hash]);
}

#[test]
fn a_query_bound_never_returns_an_unchecked_merge_successor() {
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
        fixture.run(recovery, &history),
        Err(RecoveryError::IncompleteScan)
    ));
}

#[test]
fn audited_deposit_recovery_preserves_committed_data_hashes() {
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
    let recovered = fixture.run(fixture.recovery(), &history).unwrap();
    assert_eq!(recovered.utxos, vec![held]);
    assert!(recovered.unopened.is_empty());
    assert!(recovered.unsupported_deposits.is_empty());
}

#[test]
fn audited_deposits_seed_merge_recovery_and_successor_spend_checks() {
    let fixture = Fixture::new();
    let (first, first_tx) = fixture.deposit(fixture.output(4), 2);
    let (second, second_tx) = fixture.deposit(fixture.output(5), 2);
    let (merged, merge_tx) = fixture.merge(&[first, second], 7);
    let mut history = History {
        transactions: vec![first_tx, second_tx, merge_tx.clone()],
        ..Default::default()
    };
    let recovered = fixture.run(fixture.recovery(), &history).unwrap();
    assert_eq!(recovered.utxos, vec![merged.clone()]);
    assert!(recovered.unsupported_deposits.is_empty());
    let mut spent = merge_tx;
    spent.tx_signature = fixture.signature();
    spent.nullifiers = vec![merged.nullifier];
    spent.output_slots.clear();
    history.transactions.push(spent);
    let recovered = fixture.run(fixture.recovery(), &history).unwrap();
    assert!(recovered.utxos.is_empty());
    assert!(recovered.unopened.is_empty());
}

#[test]
fn invalid_deposit_openings_remain_unknown_and_a_forged_owned_leaf_fails() {
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
        fixture.run(fixture.recovery(), &history),
        Err(RecoveryError::DepositOpeningMismatch)
    ));
    let commitment = wrong_ciphertext.output_slots[0].output_context.hash;
    let history = History {
        transactions: vec![wrong_ciphertext.clone()],
        ..Default::default()
    };
    let result = fixture.run(fixture.recovery(), &history).unwrap();
    assert!(result.utxos.is_empty());
    assert_eq!(result.unsupported_deposits, vec![commitment]);
    wrong_ciphertext.output_slots[0].view_tag = [99; 32];
    let history = History {
        transactions: vec![wrong_ciphertext],
        ..Default::default()
    };
    let result = fixture.run(fixture.recovery(), &history).unwrap();
    assert!(result.utxos.is_empty());
    assert!(result.unsupported_deposits.is_empty());
}
