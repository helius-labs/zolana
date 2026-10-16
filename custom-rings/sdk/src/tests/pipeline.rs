//! A child of `pipeline`, both rails stage through private items.

use std::num::NonZeroU64;

use custom_ring_interface::KeyEscrow;
use solana_address::Address;
use zolana_client::Shape;
use zolana_interface::{
    instruction::{
        instruction_data::transact::{
            confidential_encrypted_output_body, ring_confidential_encrypted_output_body, OwnerTag,
            TransactOutput,
        },
        tag::{RING_AUTHORITY_TRANSACT, RING_TRANSACT},
        MessageData,
    },
    MAX_INPUT_TREES,
};
use zolana_keypair::{random_blinding, ShieldedAddress, ShieldedKeypair, ViewingKey, X25519Secret};
use zolana_program::instruction::TransactSolTransferAccounts;
use zolana_ring_policy::{RuleTable, VelocityRow};
use zolana_transaction::{
    instructions::transact::{ConfidentialTransaction, ResolvedOwnerTag},
    keys::{LocalShieldedKeys, TransactionKeyRequest},
    serialization::{
        confidential::{Confidential, ConfidentialOutputPlaintext},
        DecodeCx,
    },
    utxo::{derive_output_blinding_seed, derive_transact_output_blinding},
    AssetRegistry, Data, Mint, ShieldedKeys, TransactionError, UtxoSerialization, SOL_MINT,
};

use super::{
    delegate::{check_balance, pad},
    owner::{
        append_record, check_membership, check_record_tree_count, money_shape, place_record_input,
    },
    *,
};
use crate::{
    entry::zero_nullifier_key,
    tests::support::{account, input, no_witnesses, note, pinned, ring, Accounts},
    velocity::{record_shape, transaction_key, VelocityPlan},
    CustomRingConfig, PoolTree, SpendRecordProofInput,
};

fn program() -> Address {
    ring().program_id()
}

fn audit_only() -> CustomRingConfig {
    CustomRingConfig {
        authority: Address::new_from_array([3; 32]),
        auditor_pubkey: X25519Secret::new().pubkey(),
        has_policy: false,
        key_escrow: KeyEscrow::Off,
    }
}

fn escrowed() -> CustomRingConfig {
    CustomRingConfig {
        has_policy: true,
        key_escrow: KeyEscrow::Registry,
        ..audit_only()
    }
}

#[test]
fn a_note_spent_twice_is_refused_before_proving() {
    let owner = ShieldedKeypair::new_ed25519().unwrap();
    let spent = input(&owner, 5, 0, Some(program()));
    let other = input(&owner, 5, 0, Some(program()));
    check_distinct(&[spent.clone(), other.clone()]).unwrap();
    assert!(matches!(
        check_distinct(&[spent.clone(), other, spent.clone()]),
        Err(RingError::DuplicateInput { nullifier }) if nullifier == spent.nullifier
    ));
    let dummy = SppProofInputUtxo::dummy_with_blinding([7; 32], 0).unwrap();
    check_distinct(&[spent, dummy.clone(), dummy]).unwrap();
}

#[test]
fn a_record_free_rail_commits_the_pinned_rows() {
    let asset = *zolana_ring_policy::Member::asset(&Address::new_from_array([9; 32]))
        .unwrap()
        .as_bytes();
    let rows = [VelocityRow {
        asset,
        cap: 100,
        cosign_above: 10,
    }];
    let table = RuleTable::builder()
        .windowed(NonZeroU64::new(600).unwrap())
        .velocity(&rows)
        .build();
    let pinned = PinnedPolicy {
        config: pinned(ring(), &table, ring().namespace_pda(), PoolTree::from_id(0)),
        table,
    };
    let velocity = committed(ring(), &pinned).unwrap();
    assert_eq!(velocity.window_slots, 600);
    assert_eq!(velocity.row_count, 1);
    assert_eq!(velocity.rows[0], rows[0]);
    assert_eq!(velocity.window_index, 0);
    assert!(!velocity.approval_required);
    assert_eq!(velocity.record, SpendRecordProofInput::default());
    assert_eq!(
        velocity.namespace_owner_hash,
        pinned.config.namespace_owner_hash
    );
}

fn prepared_transfer(amount: u64) -> (ShieldedKeypair, ConfidentialTransaction) {
    let sender = ShieldedKeypair::new_ed25519().unwrap();
    let recipient = ShieldedKeypair::new_ed25519().unwrap();
    let mut transfer = ConfidentialTransaction::new(
        vec![note(&sender, 10, 0, Some(program()))],
        solana_signer::Signer::pubkey(&sender),
    )
    .unwrap();
    transfer
        .transfer_sol(&recipient.shielded_address().unwrap(), amount)
        .unwrap();
    transfer
        .pad_utxos(Shape::IN2_OUT4, &sender.shielded_address().unwrap())
        .unwrap();
    (sender, transfer)
}

#[test]
fn membership_accepts_active_and_default_outputs() {
    let (_, prepared) = prepared_transfer(4);
    let inputs: Vec<SppProofInputUtxo> = prepared.inputs().iter().map(Into::into).collect();
    let mut outputs = prepared.outputs().to_vec();
    check_membership(program(), &inputs, &outputs).unwrap();
    outputs[1].ring_program_id = Some(program());
    check_membership(program(), &inputs, &outputs).unwrap();
    outputs[1].ring_program_id = Some(Address::new_from_array([9; 32]));
    assert!(matches!(
        check_membership(program(), &inputs, &outputs),
        Err(RingError::ForeignRing(foreign)) if foreign == Address::new_from_array([9; 32])
    ));
}

#[test]
fn membership_refuses_ring_data_outside_a_ring() {
    let (_, prepared) = prepared_transfer(4);
    let inputs: Vec<SppProofInputUtxo> = prepared.inputs().iter().map(Into::into).collect();
    let mut outputs = prepared.outputs().to_vec();
    outputs[1].ring_data_hash = Some([3; 32]);
    assert!(matches!(
        check_membership(program(), &inputs, &outputs),
        Err(RingError::RingDataOutsideRing)
    ));
    outputs[1].ring_program_id = Some(program());
    check_membership(program(), &inputs, &outputs).unwrap();
}

#[test]
fn keys_without_a_signing_secret_derive_the_transfer_key() {
    let (keypair, prepared) = prepared_transfer(4);
    let first_nullifier = *prepared.first_nullifier();
    let keys = LocalShieldedKeys::from_keypair(&keypair).unwrap();
    let derived = keys
        .transaction_keys(&[TransactionKeyRequest {
            viewing_pubkey: keypair.viewing_pubkey(),
            first_nullifier,
        }])
        .unwrap();
    let expected = keypair
        .get_transaction_viewing_key(&first_nullifier)
        .unwrap()
        .pubkey();
    assert_eq!(derived[0].pubkey(), expected);
    assert_eq!(
        transaction_key(&keys, first_nullifier).unwrap().pubkey(),
        expected
    );
    let _transfer = CustomRingTransfer::new(CustomRingTransferInput {
        ring: ring(),
        sender: &keys,
        nullifier_key: Some(&keypair.nullifier_key),
        transaction: prepared,
    });
}

struct NoRpc;

#[async_trait::async_trait]
impl AsyncRpc for NoRpc {}

no_witnesses!(NoRpc);

#[test]
fn the_prove_future_is_send() {
    fn assert_send<F: Send>(_: F) {}
    let (keypair, prepared) = prepared_transfer(4);
    let client = AsyncZolanaClient::new(NoRpc, NoRpc, zolana_client::AsyncProverClient::local());
    let transfer = CustomRingTransfer::new(CustomRingTransferInput {
        ring: ring(),
        sender: &keypair,
        nullifier_key: Some(&keypair.nullifier_key),
        transaction: prepared,
    });
    assert_send(transfer.prove(&client));
}

#[tokio::test]
async fn withdrawal_accounts_are_validated_before_proving() {
    let sender = ShieldedKeypair::new_ed25519().unwrap();
    let recipient = Address::new_from_array([7; 32]);
    let mut prepared = ConfidentialTransaction::new(
        vec![note(&sender, 10, 0, Some(program()))],
        solana_signer::Signer::pubkey(&sender),
    )
    .unwrap();
    prepared.withdraw_sol(4, recipient).unwrap();
    let transfer = |accounts| {
        CustomRingTransfer::new(CustomRingTransferInput {
            ring: ring(),
            sender: &sender,
            nullifier_key: Some(&sender.nullifier_key),
            transaction: prepared.clone(),
        })
        .with_interface_transfer_accounts(accounts)
    };
    let missing = transfer(Vec::new());
    assert!(matches!(
        missing
            .rail
            .stage(ring(), &Accounts::default(), &audit_only())
            .await,
        Err(RingError::Client(
            ClientError::SettlementTransferCountMismatch { .. }
        ))
    ));
    let settled = transfer(vec![TransactInterfaceTransferAccounts::Sol(
        TransactSolTransferAccounts { recipient },
    )]);
    let staged = settled
        .rail
        .stage(ring(), &Accounts::default(), &audit_only())
        .await
        .unwrap();
    assert_eq!(staged.interface_transfer_accounts.len(), 1);
}

#[tokio::test]
async fn an_audit_only_transfer_stages_the_auditor_message_under_the_ring_tag() {
    let (sender, prepared) = prepared_transfer(4);
    let config = audit_only();
    let transfer = CustomRingTransfer::new(CustomRingTransferInput {
        ring: ring(),
        sender: &sender,
        nullifier_key: Some(&sender.nullifier_key),
        transaction: prepared,
    });
    let rpc = Accounts::default();
    let staged = transfer.rail.stage(ring(), &rpc, &config).await.unwrap();
    // An audit-only ring reads no policy account.
    assert!(rpc.reads().is_empty());
    assert!(staged.pinned.is_none() && staged.velocity.is_none() && staged.record.is_none());
    assert!(staged.key_registry.is_none() && staged.delegate.is_none());
    let external = &staged.proof_inputs.external_data;
    assert_eq!(external.instruction_discriminator, RING_TRANSACT);
    assert_eq!(external.messages.len(), 1);
    // The fee payer owns the spent note and signs once.
    assert!(staged.owner_signers.is_empty());
    for encoded in &external.outputs {
        assert!(encoded.data.is_some());
    }
    assert!(staged.authority.owner.is_some() && staged.authority.spend_record.is_none());
}

#[tokio::test]
async fn a_policy_ring_without_its_policy_account_is_refused() {
    let (sender, prepared) = prepared_transfer(4);
    let transfer = CustomRingTransfer::new(CustomRingTransferInput {
        ring: ring(),
        sender: &sender,
        nullifier_key: Some(&sender.nullifier_key),
        transaction: prepared,
    });
    let config = CustomRingConfig {
        has_policy: true,
        ..audit_only()
    };
    assert!(matches!(
        transfer
            .rail
            .stage(ring(), &Accounts::default(), &config)
            .await,
        Err(RingError::MissingPolicyConfig)
    ));
}

/// Input tree ids once the record and one padding slot follow the spent inputs.
fn record_input_trees(spend_trees: &[u16], record_tree: u16) -> Result<Vec<u16>, RingError> {
    let sender = ShieldedKeypair::new_ed25519().unwrap();
    let inputs = spend_trees
        .iter()
        .map(|&tree_id| note(&sender, 1, tree_id, None))
        .collect();
    let mut transaction =
        ConfidentialTransaction::new(inputs, solana_signer::Signer::pubkey(&sender)).unwrap();
    transaction
        .transfer_sol(&sender.shielded_address().unwrap(), 1)
        .unwrap();
    check_record_tree_count(&transaction, record_tree)?;
    let mut proof_inputs = transaction.encrypt(&sender).unwrap();
    assert!(!proof_inputs.input_utxos[0].is_dummy());
    let n_inputs = proof_inputs.input_utxos.len() + 2;
    place_record_input(
        &mut proof_inputs.input_utxos,
        input(&sender, 0, record_tree, Some(program())),
        n_inputs,
    )?;
    Ok(proof_inputs
        .input_utxos
        .iter()
        .map(|input| input.tree_id)
        .collect())
}

#[test]
fn a_record_in_the_first_spend_tree_follows_the_spends_in_their_order() {
    // The padding sits under the last tree the inputs declare.
    assert_eq!(record_input_trees(&[4, 9], 4).unwrap(), vec![4, 9, 4, 9]);
}

#[test]
fn a_record_in_a_new_tree_follows_the_spends_and_hosts_the_padding() {
    assert_eq!(record_input_trees(&[4], 9).unwrap(), vec![4, 9, 9]);
}

#[test]
fn a_record_tree_past_the_input_tree_limit_is_refused() {
    let full: Vec<u16> = (1..=MAX_INPUT_TREES as u16).collect();
    assert!(record_input_trees(&full, 1).is_ok());
    assert!(matches!(
        record_input_trees(&full, 99),
        Err(RingError::Transaction(TransactionError::TooManyInputTrees { got, max }))
            if got == MAX_INPUT_TREES + 1 && max == MAX_INPUT_TREES
    ));
}

fn blinding_at(proof_inputs: &SppProofInputs, slot: u32) -> [u8; 32] {
    let first = proof_inputs.first_nullifier().unwrap();
    let seed = derive_output_blinding_seed(&first, &proof_inputs.blinding_seed).unwrap();
    derive_transact_output_blinding(&first, &seed, slot).unwrap()
}

/// A record plan whose output takes `record_slot` under `shape`.
fn plan(
    proof_inputs: &SppProofInputs,
    tx_viewing_key: &ViewingKey,
    shape: Shape,
    record_slot: usize,
) -> VelocityPlan {
    let record_owner = ShieldedAddress::for_pda(
        &ring().namespace_pda(),
        zero_nullifier_key().pubkey().unwrap(),
        tx_viewing_key.pubkey(),
    );
    let owner = ShieldedKeypair::new_ed25519().unwrap();
    VelocityPlan {
        input: input(&owner, 0, 9, None),
        output: SppProofOutputUtxo {
            blinding: blinding_at(proof_inputs, record_slot as u32),
            ..SppProofOutputUtxo::new(Mint::SOL, 0, record_owner).unwrap()
        },
        record_message: MessageData {
            view_tag: [0; 32],
            data: Vec::new(),
        },
        counters_message: MessageData {
            view_tag: [0; 32],
            data: Vec::new(),
        },
        proof_input: VelocityProofInput::off(RingIdentity {
            ring_id: [1; 32],
            namespace_owner_hash: [2; 32],
        }),
        shape,
        record_slot,
    }
}

struct RecordFixture {
    sender: ShieldedKeypair,
    recipient: ShieldedKeypair,
    sender_tag: ResolvedOwnerTag,
    tx_viewing_key: ViewingKey,
    proof_inputs: SppProofInputs,
}

impl RecordFixture {
    fn new(mint: Mint, amount: u64, sent: u64, sender_pays_fee: bool) -> Self {
        let sender = ShieldedKeypair::new_ed25519().unwrap();
        let recipient = ShieldedKeypair::new_ed25519().unwrap();
        let payer = match sender_pays_fee {
            true => solana_signer::Signer::pubkey(&sender),
            false => Address::new_from_array([7; 32]),
        };
        let input = crate::tests::support::wallet(
            zolana_transaction::Utxo {
                owner: sender.signing_pubkey(),
                asset: mint,
                amount,
                blinding: random_blinding(),
                ring_program_id: None,
                data: Data::default(),
            },
            &sender.nullifier_key,
            0,
            0,
            None,
            None,
        );
        let mut tx = ConfidentialTransaction::new(vec![input], payer).unwrap();
        tx.transfer_with_ring(&recipient.shielded_address().unwrap(), mint, sent, None)
            .unwrap();
        let sender_tag = tx.sender_owner_tag(&sender.signing_pubkey()).unwrap();
        let tx_viewing_key = sender
            .get_transaction_viewing_key(tx.first_nullifier())
            .unwrap();
        let proof_inputs = tx.encrypt(&sender).unwrap();
        Self {
            sender,
            recipient,
            sender_tag,
            tx_viewing_key,
            proof_inputs,
        }
    }

    fn published_tag(&self, slot: usize) -> ResolvedOwnerTag {
        let external = &self.proof_inputs.external_data;
        ResolvedOwnerTag {
            tag: external.outputs[slot].owner_tag,
            resolved: external.resolved_owner_tags[slot],
        }
    }

    /// Two spare slots precede the record, returns the real output count.
    fn append(&mut self) -> usize {
        let real = money_shape(&self.proof_inputs).n_outputs();
        let plan = plan(
            &self.proof_inputs,
            &self.tx_viewing_key,
            Shape::new(2, real + 3),
            real + 2,
        );
        append_record(
            &mut self.proof_inputs,
            &plan,
            &self.tx_viewing_key,
            &self.sender.shielded_address().unwrap(),
            self.sender_tag,
        )
        .unwrap();
        assert_eq!(self.proof_inputs.output_utxos[real + 2], plan.output);
        real
    }

    fn assert_padding(
        &self,
        real: usize,
        owner: &ShieldedKeypair,
        asset: Mint,
        owner_tag: ResolvedOwnerTag,
    ) {
        let external = &self.proof_inputs.external_data;
        for slot in real..real + 2 {
            let output = &self.proof_inputs.output_utxos[slot];
            let encoded = &external.outputs[slot];
            assert_eq!(
                output,
                &SppProofOutputUtxo {
                    blinding: blinding_at(&self.proof_inputs, slot as u32),
                    ..SppProofOutputUtxo::new(asset, 0, owner.shielded_address().unwrap()).unwrap()
                }
            );
            assert_eq!(
                (encoded.owner_tag, external.resolved_owner_tags[slot]),
                (owner_tag.tag, owner_tag.resolved)
            );
            assert_eq!(
                encoded.utxo_hash,
                output.hash(self.proof_inputs.output_tree_id).unwrap()
            );
            let body = encoded
                .data
                .as_deref()
                .and_then(confidential_encrypted_output_body)
                .unwrap();
            let plaintext = Confidential::decode(
                body,
                &DecodeCx {
                    viewing_key: &owner.viewing_key,
                    tx_viewing_pk: Some(self.tx_viewing_key.pubkey()),
                    salt: Some(external.salt),
                    slot_index: slot as u32,
                    first_nullifier: None,
                },
            )
            .unwrap();
            assert_eq!(
                (
                    plaintext.asset_id,
                    plaintext.amount,
                    plaintext.blinding,
                    plaintext.ring_program_id
                ),
                (asset.asset_id, 0, output.blinding, None)
            );
        }
    }
}

#[derive(serde::Deserialize)]
struct RecordPaddingCase {
    name: String,
    sender_pays_fee: bool,
    keeps_change: bool,
    copies: String,
    owner_tag: String,
}

fn record_padding_cases(copies: &str) -> Vec<RecordPaddingCase> {
    #[derive(serde::Deserialize)]
    struct Vectors {
        cases: Vec<RecordPaddingCase>,
    }
    let vectors: Vectors =
        serde_json::from_str(include_str!("../../../../test-vectors/record_padding.json")).unwrap();
    let cases: Vec<_> = vectors
        .cases
        .into_iter()
        .filter(|case| case.copies == copies)
        .collect();
    assert!(
        !cases.is_empty(),
        "no record padding vector copies {copies}"
    );
    cases
}

fn assert_record_padding_case(case: &RecordPaddingCase) {
    let (mint, amount) = match case.keeps_change {
        true => (Mint::new(Address::new_from_array([9; 32]), 9), 5),
        false => (Mint::SOL, 1),
    };
    let mut fixture = RecordFixture::new(mint, amount, 1, case.sender_pays_fee);
    let copies_sender = match case.copies.as_str() {
        "sender" => true,
        "recipient" => false,
        other => panic!("{}: unknown copied owner {other}", case.name),
    };
    let copied_owner = match copies_sender {
        true => fixture.sender.signing_pubkey(),
        false => fixture.recipient.signing_pubkey(),
    };
    let resolved = copied_owner.confidential_view_tag().unwrap();
    let expected = ResolvedOwnerTag {
        tag: match case.owner_tag.as_str() {
            "account_0" => OwnerTag::Account(0),
            "inline" => OwnerTag::Inline(resolved),
            other => panic!("{}: unknown owner tag {other}", case.name),
        },
        resolved,
    };
    let owned: Vec<usize> = fixture
        .proof_inputs
        .output_utxos
        .iter()
        .enumerate()
        .filter(|(_, output)| {
            output
                .owner_address
                .is_some_and(|address| address.signing_pubkey == copied_owner)
        })
        .map(|(slot, _)| slot)
        .collect();
    let copied = match copies_sender {
        true => owned.first(),
        false => owned.last(),
    }
    .copied()
    .unwrap();
    assert_eq!(fixture.published_tag(copied), expected, "{}", case.name);
    let real = fixture.append();
    let owner = match copies_sender {
        true => &fixture.sender,
        false => &fixture.recipient,
    };
    fixture.assert_padding(real, owner, mint, expected);
}

#[test]
fn record_padding_copies_the_sender_change() {
    for case in record_padding_cases("sender") {
        assert!(case.keeps_change, "{}", case.name);
        assert_record_padding_case(&case);
    }
}

#[test]
fn record_padding_copies_the_last_money_output_without_change() {
    for case in record_padding_cases("recipient") {
        assert!(!case.keeps_change, "{}", case.name);
        assert_record_padding_case(&case);
    }
}

#[test]
fn record_padding_without_money_outputs_is_the_senders_zero_sol() {
    let mut fixture = RecordFixture::new(Mint::SOL, 1, 1, true);
    fixture.proof_inputs.output_utxos.clear();
    fixture.proof_inputs.external_data.outputs.clear();
    fixture
        .proof_inputs
        .external_data
        .resolved_owner_tags
        .clear();
    let real = fixture.append();
    fixture.assert_padding(real, &fixture.sender, Mint::SOL, fixture.sender_tag);
}

#[test]
fn a_record_output_off_its_derived_blinding_is_refused() {
    let mut fixture = RecordFixture::new(Mint::SOL, 1, 1, true);
    let real = money_shape(&fixture.proof_inputs).n_outputs();
    let mut plan = plan(
        &fixture.proof_inputs,
        &fixture.tx_viewing_key,
        Shape::new(2, real + 1),
        real,
    );
    plan.output.blinding[0] ^= 1;
    assert!(matches!(
        append_record(
            &mut fixture.proof_inputs,
            &plan,
            &fixture.tx_viewing_key,
            &fixture.sender.shielded_address().unwrap(),
            fixture.sender_tag,
        ),
        Err(RingError::Client(ClientError::OutputBlindingMismatch { index })) if index == real
    ));
}

#[test]
fn a_record_shape_without_a_spare_slot_is_refused() {
    let mut fixture = RecordFixture::new(Mint::SOL, 1, 1, true);
    let real = money_shape(&fixture.proof_inputs).n_outputs();
    let plan = plan(
        &fixture.proof_inputs,
        &fixture.tx_viewing_key,
        Shape::new(2, real),
        real,
    );
    assert!(matches!(
        append_record(
            &mut fixture.proof_inputs,
            &plan,
            &fixture.tx_viewing_key,
            &fixture.sender.shielded_address().unwrap(),
            fixture.sender_tag,
        ),
        Err(RingError::PolicyShapeUnsupported)
    ));
}

fn record_slots_case(sent: u64) {
    let sender = ShieldedKeypair::new_ed25519().unwrap();
    let address = sender.shielded_address().unwrap();
    let recipient = ShieldedKeypair::new_ed25519().unwrap();
    let mut tx = ConfidentialTransaction::new(
        vec![note(&sender, 5, 4, Some(program()))],
        solana_signer::Signer::pubkey(&sender),
    )
    .unwrap();
    tx.transfer_sol(&recipient.shielded_address().unwrap(), sent)
        .unwrap();
    tx.pad_utxos(Shape::IN2_OUT2, &address).unwrap();
    let sender_tag = tx.sender_owner_tag(&sender.signing_pubkey()).unwrap();
    let tx_viewing_key = sender
        .get_transaction_viewing_key(tx.first_nullifier())
        .unwrap();
    let mut proof_inputs = tx.encrypt(&sender).unwrap();
    let money_input = proof_inputs.input_utxos[0].clone();
    assert!(proof_inputs
        .input_utxos
        .last()
        .is_some_and(SppProofInputUtxo::is_dummy));
    let money_outputs: Vec<_> = proof_inputs
        .output_utxos
        .iter()
        .filter(|output| !output.is_dummy())
        .cloned()
        .collect();
    assert_eq!(
        money_outputs.len() < proof_inputs.output_utxos.len(),
        sent == 5
    );
    let shape = Shape::IN4_OUT4;
    let plan = plan(&proof_inputs, &tx_viewing_key, shape, 2);
    append_record(
        &mut proof_inputs,
        &plan,
        &tx_viewing_key,
        &address,
        sender_tag,
    )
    .unwrap();

    assert_eq!(proof_inputs.check_shape().unwrap(), shape);
    assert_eq!(
        proof_inputs.first_nullifier().unwrap(),
        money_input.nullifier()
    );
    let inputs: Vec<(bool, u16)> = proof_inputs
        .input_utxos
        .iter()
        .map(|input| (input.is_dummy(), input.tree_id))
        .collect();
    assert_eq!(inputs, vec![(false, 4), (false, 9), (true, 9), (true, 9)]);
    assert_eq!(
        proof_inputs.input_utxos[1].nullifier(),
        plan.input.nullifier()
    );
    assert_eq!(record_input_position(&proof_inputs.input_utxos), Some(1));
    assert!(proof_inputs
        .output_utxos
        .iter()
        .take(3)
        .all(|output| !output.is_dummy()));
    assert_eq!(
        proof_inputs.output_utxos.get(..money_outputs.len()),
        Some(money_outputs.as_slice())
    );
    let copied = match sent {
        5 => recipient.shielded_address().unwrap(),
        _ => address,
    };
    for slot in money_outputs.len()..2 {
        assert_eq!(
            proof_inputs.output_utxos[slot],
            SppProofOutputUtxo {
                blinding: blinding_at(&proof_inputs, slot as u32),
                ..SppProofOutputUtxo::new(Mint::SOL, 0, copied).unwrap()
            }
        );
    }
    assert_eq!(proof_inputs.output_utxos[2], plan.output);
    assert!(proof_inputs.output_utxos[3].is_compact());
    assert_eq!(proof_inputs.external_data.outputs.len(), 3);
    assert_eq!(proof_inputs.external_data.resolved_owner_tags.len(), 3);
}

#[test]
fn record_slots_keep_every_dummy_after_the_real_slots() {
    for sent in [1, 5] {
        record_slots_case(sent);
    }
}

#[test]
fn the_record_shape_follows_the_real_outputs_not_the_padding() {
    let sender = ShieldedKeypair::new_ed25519().unwrap();
    let address = sender.shielded_address().unwrap();
    let mut tx = ConfidentialTransaction::new(
        vec![note(&sender, 5, 4, Some(program()))],
        solana_signer::Signer::pubkey(&sender),
    )
    .unwrap();
    for _ in 0..2 {
        let recipient = ShieldedKeypair::new_ed25519().unwrap();
        tx.transfer_sol(&recipient.shielded_address().unwrap(), 1)
            .unwrap();
    }
    tx.pad_utxos(Shape::IN1_OUT4, &address).unwrap();
    let sender_tag = tx.sender_owner_tag(&sender.signing_pubkey()).unwrap();
    let tx_viewing_key = sender
        .get_transaction_viewing_key(tx.first_nullifier())
        .unwrap();
    let mut proof_inputs = tx.encrypt(&sender).unwrap();
    assert_eq!(proof_inputs.check_shape().unwrap(), Shape::IN1_OUT4);
    let money = money_shape(&proof_inputs);
    assert_eq!(money, Shape::new(1, 3));
    let shape = record_shape(money).unwrap();
    assert_eq!(shape, Shape::IN2_OUT4);
    let money_outputs: Vec<_> = proof_inputs.output_utxos[..3].to_vec();
    let plan = plan(&proof_inputs, &tx_viewing_key, shape, money.n_outputs());
    append_record(
        &mut proof_inputs,
        &plan,
        &tx_viewing_key,
        &address,
        sender_tag,
    )
    .unwrap();
    assert_eq!(proof_inputs.check_shape().unwrap(), shape);
    assert_eq!(record_input_position(&proof_inputs.input_utxos), Some(1));
    assert_eq!(proof_inputs.output_utxos[..3], money_outputs[..]);
    assert_eq!(proof_inputs.output_utxos[3], plan.output);
    assert_eq!(proof_inputs.external_data.outputs.len(), 4);
}

fn framed_fixture(rings: &[Option<Address>]) -> SppProofInputs {
    let sender = ShieldedKeypair::new_ed25519().unwrap();
    let mut tx = ConfidentialTransaction::new(
        vec![note(&sender, rings.len() as u64, 0, None)],
        solana_signer::Signer::pubkey(&sender),
    )
    .unwrap();
    for ring in rings {
        tx.transfer_with_ring(&sender.shielded_address().unwrap(), Mint::SOL, 1, *ring)
            .unwrap();
    }
    tx.encrypt(&sender).unwrap()
}

#[test]
fn output_framing_selects_ring_membership() {
    for binding in [None, Some(program())] {
        let proof_inputs = framed_fixture(&[binding; 4]);
        for slot in &proof_inputs.external_data.outputs {
            let data = slot.data.as_deref().unwrap();
            assert_eq!(
                ring_confidential_encrypted_output_body(data).is_some(),
                binding.is_some()
            );
            assert_eq!(
                confidential_encrypted_output_body(data).is_some(),
                binding.is_none()
            );
        }
    }
}

#[test]
fn a_dummy_takes_the_length_of_a_real_slot_with_its_own_binding() {
    let mut proof_inputs = framed_fixture(&[None, Some(program()), None]);
    proof_inputs.output_utxos[2].owner_address = None;
    let real_len = |in_ring: bool| {
        proof_inputs
            .output_utxos
            .iter()
            .zip(&proof_inputs.external_data.outputs)
            .find(|(output, _)| !output.is_dummy() && output.ring_program_id.is_some() == in_ring)
            .and_then(|(_, output)| output.data.as_ref().map(Vec::len))
            .unwrap()
    };
    let (ring_len, default_len) = (real_len(true), real_len(false));
    assert_ne!(ring_len, default_len);
    frame_dummy_outputs(
        &proof_inputs.output_utxos,
        &mut proof_inputs.external_data.outputs,
    )
    .unwrap();
    assert!(proof_inputs
        .output_utxos
        .iter()
        .any(SppProofOutputUtxo::is_dummy));
    for (output, encoded) in proof_inputs
        .output_utxos
        .iter()
        .zip(&proof_inputs.external_data.outputs)
        .filter(|(output, _)| output.is_dummy())
    {
        let data = encoded.data.as_deref().unwrap();
        assert_eq!(data.len(), default_len);
        assert!(output.ring_program_id.is_none());
        assert!(ring_confidential_encrypted_output_body(data).is_none());
    }
}

#[test]
fn full_withdrawal_padding_uses_the_canonical_empty_payload_size() {
    let outputs: Vec<SppProofOutputUtxo> = (0..2)
        .map(|index| SppProofOutputUtxo {
            blinding: random_blinding(),
            ring_program_id: (index % 2 == 0).then_some(program()),
            ..Default::default()
        })
        .collect();
    let mut encoded: Vec<TransactOutput> = outputs
        .iter()
        .map(|output| TransactOutput {
            utxo_hash: output.hash(0).unwrap(),
            owner_tag: OwnerTag::Inline([0; 32]),
            data: None,
        })
        .collect();
    frame_dummy_outputs(&outputs, &mut encoded).unwrap();
    let key_len = ViewingKey::new().pubkey().as_bytes().len();
    for (output, encoded) in outputs.iter().zip(&encoded) {
        assert!(output.is_dummy());
        let data = encoded.data.as_deref().unwrap();
        let body = match output.ring_program_id {
            Some(_) => ring_confidential_encrypted_output_body(data),
            None => confidential_encrypted_output_body(data),
        }
        .unwrap();
        let plaintext = ConfidentialOutputPlaintext {
            asset_id: zolana_transaction::SOL_ASSET_ID,
            amount: 0,
            blinding: [0; 32],
            ring_program_id: output.ring_program_id,
            data: Data::default(),
        }
        .serialize()
        .unwrap();
        assert_eq!(body.len(), key_len + plaintext.len());
    }
}

#[test]
fn a_record_carrier_frames_a_full_withdrawals_dummy_outputs() {
    let mut proof = framed_fixture(&[Some(program()); 4]);
    let money_count = proof.output_utxos.len() - 1;
    for output in &mut proof.output_utxos[..money_count] {
        output.owner_address = None;
    }
    let record = proof.external_data.outputs.last().unwrap().clone();
    frame_dummy_outputs(&proof.output_utxos, &mut proof.external_data.outputs).unwrap();
    assert_eq!(proof.external_data.outputs.last(), Some(&record));
    for encoded in &proof.external_data.outputs[..money_count] {
        let data = encoded.data.as_deref().unwrap();
        assert!(ring_confidential_encrypted_output_body(data).is_some());
        assert_eq!(data.len(), record.data.as_ref().unwrap().len());
    }
}

#[test]
fn dummy_framing_matches_ring_slot_lengths() {
    let mut proof_inputs = framed_fixture(&[Some(program()); 4]);
    proof_inputs.output_utxos[1].owner_address = None;
    proof_inputs.output_utxos[2].owner_address = None;
    let real_len = proof_inputs
        .output_utxos
        .iter()
        .zip(&proof_inputs.external_data.outputs)
        .find(|(output, _)| !output.is_dummy())
        .and_then(|(_, output)| output.data.as_ref().map(Vec::len))
        .unwrap();
    frame_dummy_outputs(
        &proof_inputs.output_utxos,
        &mut proof_inputs.external_data.outputs,
    )
    .unwrap();
    for encoded in &proof_inputs.external_data.outputs {
        let data = encoded.data.as_deref().unwrap();
        assert!(ring_confidential_encrypted_output_body(data).is_some());
        assert_eq!(data.len(), real_len);
    }
    let dummy_keys: Vec<Vec<u8>> = proof_inputs
        .output_utxos
        .iter()
        .zip(&proof_inputs.external_data.outputs)
        .filter(|(output, _)| output.is_dummy())
        .map(|(_, encoded)| {
            ring_confidential_encrypted_output_body(encoded.data.as_deref().unwrap()).unwrap()[..33]
                .to_vec()
        })
        .collect();
    assert_ne!(dummy_keys[0], dummy_keys[1]);
}

#[test]
fn a_dummy_beside_a_slot_without_data_is_refused() {
    let mut proof_inputs = framed_fixture(&[Some(program()); 2]);
    proof_inputs.output_utxos[1].owner_address = None;
    proof_inputs.external_data.outputs[0].data = None;
    assert!(matches!(
        frame_dummy_outputs(
            &proof_inputs.output_utxos,
            &mut proof_inputs.external_data.outputs,
        ),
        Err(RingError::InvalidDummyOutput)
    ));
}

fn member_note(owner: &ShieldedKeypair, amount: u64, tree_id: u16) -> SppProofInputUtxo {
    input(owner, amount, tree_id, Some(program()))
}

fn recipient(owner: &ShieldedKeypair, amount: u64) -> SppProofOutputUtxo {
    SppProofOutputUtxo {
        ring_program_id: Some(program()),
        ..SppProofOutputUtxo::new(Mint::SOL, amount, owner.shielded_address().unwrap()).unwrap()
    }
}

#[test]
fn padding_fills_the_smallest_square_width_under_the_last_declared_tree() {
    let member = ShieldedKeypair::new_ed25519().unwrap();
    let other = ShieldedKeypair::new_ed25519().unwrap();
    let mut inputs = vec![member_note(&member, 5, 3), member_note(&member, 2, 6)];
    let mut outputs = vec![recipient(&other, 7)];
    let tag = outputs[0].owner_tag;
    pad(&mut inputs, &mut outputs, program()).unwrap();
    assert_eq!((inputs.len(), outputs.len()), (2, 2));
    assert!(outputs[1].is_dummy());
    assert_eq!(outputs[1].owner_tag, tag);
    assert_eq!(outputs[1].ring_program_id, Some(program()));

    let mut inputs = vec![
        member_note(&member, 1, 3),
        member_note(&member, 1, 6),
        member_note(&member, 1, 3),
    ];
    let mut outputs = vec![recipient(&other, 3)];
    pad(&mut inputs, &mut outputs, program()).unwrap();
    assert_eq!(inputs.len(), ring_authority_width(3).unwrap());
    assert!(inputs[3..]
        .iter()
        .all(|input| input.is_dummy() && input.tree_id == 6));
}

#[test]
fn padding_refuses_a_fifth_slot_a_dummy_output_and_a_dummy_first_input() {
    let member = ShieldedKeypair::new_ed25519().unwrap();
    let mut inputs: Vec<_> = (0..5).map(|_| member_note(&member, 1, 3)).collect();
    assert!(matches!(
        pad(&mut inputs, &mut vec![recipient(&member, 5)], program()),
        Err(RingError::Transaction(TransactionError::UnsupportedShape {
            n_in: 5,
            n_out: 1
        }))
    ));
    assert!(matches!(
        pad(
            &mut vec![member_note(&member, 5, 3)],
            &mut vec![SppProofOutputUtxo::default()],
            program()
        ),
        Err(RingError::Transaction(TransactionError::MissingOutput))
    ));
    assert!(matches!(
        pad(
            &mut vec![member_note(&member, 5, 3)],
            &mut Vec::new(),
            program()
        ),
        Err(RingError::Transaction(TransactionError::MissingOutput))
    ));
    assert!(matches!(
        pad(
            &mut vec![
                SppProofInputUtxo::dummy(3).unwrap(),
                member_note(&member, 5, 3)
            ],
            &mut vec![recipient(&member, 5)],
            program()
        ),
        Err(RingError::Transaction(TransactionError::NoInputs))
    ));
}

#[test]
fn a_supplied_dummy_outside_the_padding_tree_is_refused() {
    let member = ShieldedKeypair::new_ed25519().unwrap();
    let mut inputs = vec![
        member_note(&member, 5, 3),
        SppProofInputUtxo::dummy(8).unwrap(),
    ];
    assert!(matches!(
        pad(&mut inputs, &mut vec![recipient(&member, 5)], program()),
        Err(RingError::Transaction(
            TransactionError::PaddingInUndeclaredTree {
                index: 1,
                tree_id: 8
            }
        ))
    ));
}

#[test]
fn an_unbalanced_move_is_refused_before_proving() {
    let member = ShieldedKeypair::new_ed25519().unwrap();
    let outputs = [recipient(&member, 4)];
    assert!(matches!(
        check_balance(&[member_note(&member, 5, 0)], &outputs),
        Err(RingError::UnbalancedMove(asset)) if asset == Mint::SOL.asset
    ));
    check_balance(&[member_note(&member, 4, 0)], &outputs).unwrap();
    check_balance(
        &[
            member_note(&member, 4, 0),
            SppProofInputUtxo::dummy(0).unwrap(),
        ],
        &outputs,
    )
    .unwrap();
}

/// The delegate account, the pinned policy and a ring delegate.
fn delegate_accounts(delegate: Address) -> Accounts {
    let state = custom_ring_interface::Delegate {
        discriminator: custom_ring_interface::DELEGATE,
        delegate,
        bump: Address::find_program_address(&[custom_ring_interface::Delegate::SEED], &program()).1,
    };
    let table = RuleTable::builder().build();
    Accounts::default()
        .with(ring().delegate_pda(), account(program(), &state))
        .with(
            ring().policy_config_pda(),
            account(
                program(),
                &pinned(ring(), &table, ring().namespace_pda(), PoolTree::from_id(0)),
            ),
        )
}

fn delegate_transfer<'a>(
    member: &'a ShieldedKeypair,
    recipient: &ShieldedKeypair,
    delegate: Address,
) -> DelegateTransfer<'a> {
    DelegateTransfer::new(DelegateTransferInput {
        ring: ring(),
        delegate,
        payer: Address::new_from_array([9; 32]),
        source_nullifier_key: &member.nullifier_key,
        inputs: vec![member_note(member, 5, 3), member_note(member, 7, 3)],
        outputs: vec![DelegateOutput {
            recipient: recipient.shielded_address().unwrap(),
            asset: SOL_MINT,
            amount: 12,
        }],
    })
}

#[tokio::test]
async fn the_delegate_rail_stages_framed_padding_under_its_own_tag() {
    let member = ShieldedKeypair::new_ed25519().unwrap();
    let other = ShieldedKeypair::new_ed25519().unwrap();
    let delegate = Address::new_from_array([47; 32]);
    let assets = AssetRegistry::default();
    let transfer = delegate_transfer(&member, &other, delegate).with_assets(&assets);
    let staged = transfer
        .rail
        .stage(ring(), &delegate_accounts(delegate), &escrowed())
        .await
        .unwrap();
    let proof_inputs = &staged.proof_inputs;
    assert_eq!(proof_inputs.input_utxos.len(), 2);
    assert_eq!(proof_inputs.output_utxos.len(), 2);
    assert!(proof_inputs.output_utxos[1].is_dummy());
    let external = &proof_inputs.external_data;
    assert_eq!(external.instruction_discriminator, RING_AUTHORITY_TRANSACT);
    assert_eq!(external.messages.len(), 1);
    // A pad names the recipient, never the member whose notes move.
    let recipient_tag = other.signing_pubkey().confidential_view_tag().unwrap();
    assert_eq!(external.resolved_owner_tags, vec![recipient_tag; 2]);
    for output in &external.outputs {
        let data = output.data.as_deref().unwrap();
        assert!(ring_confidential_encrypted_output_body(data).is_some());
    }
    assert_eq!(staged.delegate, Some(delegate));
    assert!(staged.key_registry.is_some());
    assert!(staged.owner_signers.is_empty());
    assert!(staged.pinned.is_some() && staged.velocity.is_none());
}

#[tokio::test]
async fn the_delegate_rail_refuses_a_ring_it_cannot_serve() {
    let member = ShieldedKeypair::new_ed25519().unwrap();
    let other = ShieldedKeypair::new_ed25519().unwrap();
    let delegate = Address::new_from_array([47; 32]);
    let assets = AssetRegistry::default();
    let stage = |accounts: Accounts, config: CustomRingConfig, with_assets: bool| {
        let member = &member;
        let other = &other;
        let assets = &assets;
        async move {
            let mut transfer = delegate_transfer(member, other, delegate);
            if with_assets {
                transfer = transfer.with_assets(assets);
            }
            transfer
                .rail
                .stage(ring(), &accounts, &config)
                .await
                .map(|_| ())
        }
    };
    assert!(matches!(
        stage(Accounts::default(), escrowed(), true).await,
        Err(RingError::MissingDelegate)
    ));
    let stranger = Address::new_from_array([48; 32]);
    assert!(matches!(
        stage(delegate_accounts(stranger), escrowed(), true).await,
        Err(RingError::UnauthorizedDelegate(stored)) if stored == stranger
    ));
    let unescrowed = CustomRingConfig {
        key_escrow: KeyEscrow::Off,
        ..escrowed()
    };
    assert!(matches!(
        stage(delegate_accounts(delegate), unescrowed, true).await,
        Err(RingError::DelegateRequiresEscrow)
    ));
    assert!(matches!(
        stage(delegate_accounts(delegate), escrowed(), false).await,
        Err(RingError::MissingAssetRegistry)
    ));
}
