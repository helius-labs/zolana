//! A child of `pipeline`, both rails stage through private items.

use std::sync::Mutex;

use custom_ring_interface::{RingMode, ANONYMOUS_OUTPUT_BODY_LEN};
use solana_address::Address;
use zolana_client::Shape;
use zolana_interface::instruction::{
    instruction_data::transact::{
        confidential_encrypted_output_body, ring_anonymous_encrypted_output_body,
        ring_confidential_encrypted_output_body, OwnerTag, TransactOutput,
    },
    tag::{RING_AUTHORITY_TRANSACT, RING_TRANSACT},
};
use zolana_keypair::{
    random_blinding, RingAddress, ShieldedAddress, ShieldedKeypair, ViewingKey, X25519Keypair,
};
use zolana_program::instruction::TransactSolTransferAccounts;
use zolana_ring_policy::{OutflowLimit, RuleTable};
use zolana_ring_transaction::{AnonymousViewTags, RingAnonymousSlot};
use zolana_transaction::{
    instructions::transact::{ConfidentialTransaction, OutputEncryption},
    keys::{LocalShieldedKeys, TransactionKeyRequest},
    serialization::confidential::ConfidentialOutputPlaintext,
    AssetRegistry, Data, Mint, ShieldedKeys, TransactionError, SOL_MINT,
};

use super::{
    anonymous,
    delegate::{check_balance, pad},
    owner::{check_membership, transaction_key},
    *,
};
use crate::{
    tests::support::{account, input, no_witnesses, note, pinned, ring, Accounts, OccupiedTags},
    CustomRingConfig, PoolTree,
};

fn program() -> Address {
    ring().program_id()
}

fn audit_only() -> CustomRingConfig {
    CustomRingConfig {
        authority: Address::new_from_array([3; 32]),
        auditor_pubkey: X25519Keypair::new().pubkey(),
        has_policy: false,
        mode: RingMode::Off,
    }
}

fn escrowed() -> CustomRingConfig {
    CustomRingConfig {
        has_policy: true,
        mode: RingMode::Registry,
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
fn the_delegate_rail_commits_the_pinned_limits() {
    let asset = *zolana_ring_policy::Member::asset(&Address::new_from_array([9; 32]))
        .unwrap()
        .as_bytes();
    let limits = [OutflowLimit {
        asset,
        cap: 100,
        cosign_above: 10,
    }];
    let table = RuleTable::builder().limits(&limits).build();
    let pinned = PinnedPolicy {
        config: pinned(ring(), &table, PoolTree::from_id(0)),
        table,
    };
    let committed = committed(ring(), &pinned).unwrap();
    assert_eq!(committed.limit_count, 1);
    assert_eq!(committed.limits[0], limits[0]);
    assert!(!committed.approval_required);
    assert_eq!(
        committed.namespace_owner_hash,
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
    assert!(staged.pinned.is_none() && staged.limits.is_none());
    assert!(!staged.key_escrow && staged.delegate.is_none());
    let external = &staged.proof_inputs.external_data;
    assert_eq!(external.instruction_discriminator, RING_TRANSACT);
    assert_eq!(external.messages.len(), 1);
    // The note owner is explicit even when it also pays the transaction fee.
    assert_eq!(
        staged.owner_signers,
        vec![solana_signer::Signer::pubkey(&sender)]
    );
    for encoded in &external.outputs {
        assert!(encoded.data.is_some());
    }
    assert!(staged.authority.owner.is_some());
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
            account(program(), &pinned(ring(), &table, PoolTree::from_id(0))),
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
    assert!(staged.key_escrow);
    assert!(staged.owner_signers.is_empty());
    assert!(staged.pinned.is_some() && staged.limits.is_none());
}

#[tokio::test]
async fn compact_delegate_padding_keeps_only_published_slots_in_the_payload_and_disclosure() {
    let member = ShieldedKeypair::new_ed25519().unwrap();
    let recipient = ShieldedKeypair::new_ed25519().unwrap();
    let delegate = Address::new_from_array([47; 32]);
    let assets = AssetRegistry::default();
    let transfer = DelegateTransfer::new(DelegateTransferInput {
        ring: ring(),
        delegate,
        payer: Address::new_from_array([9; 32]),
        source_nullifier_key: &member.nullifier_key,
        inputs: vec![member_note(&member, 5, 3), member_note(&member, 7, 3)],
        outputs: vec![
            DelegateOutput {
                recipient: recipient.shielded_address().unwrap(),
                asset: SOL_MINT,
                amount: 4,
            };
            3
        ],
    })
    .with_assets(&assets)
    .with_compact_padding();
    let staged = transfer
        .rail
        .stage(ring(), &delegate_accounts(delegate), &escrowed())
        .await
        .unwrap();
    let inputs = &staged.proof_inputs;
    assert_eq!(inputs.check_shape().unwrap(), Shape::IN4_OUT4);
    assert!(inputs.input_utxos[..2]
        .iter()
        .all(|input| !input.is_dummy()));
    assert!(inputs.input_utxos[2..]
        .iter()
        .all(SppProofInputUtxo::is_compact));
    assert!(inputs.output_utxos[3].is_compact());
    assert_eq!(inputs.external_data.outputs.len(), 3);
    assert_eq!(inputs.external_data.resolved_owner_tags.len(), 3);
    let mut misplaced = inputs.clone();
    misplaced.output_utxos.swap(2, 3);
    assert!(matches!(
        misplaced.check_shape(),
        Err(TransactionError::RealOutputAfterDummy { index: 3 })
    ));
    let mut misplaced = inputs.clone();
    misplaced.input_utxos.swap(1, 2);
    assert!(matches!(
        misplaced.check_shape(),
        Err(TransactionError::RealInputAfterDummy { index: 2 })
    ));
    let audit = staged.pending.finish_base([0; 32]).unwrap();
    assert_eq!(audit.n_out, 3);
    assert_eq!(audit.outputs.len(), 3);
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
        mode: RingMode::Off,
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

fn anonymous() -> CustomRingConfig {
    CustomRingConfig {
        mode: RingMode::Anonymous,
        ..audit_only()
    }
}

#[test]
fn anonymous_signer_slots_exclude_the_fee_payer_for_every_shape() {
    for shape in zolana_client::SPP_SUPPORTED_SHAPES {
        if ANONYMOUS_RING_SHAPES.contains(&shape) {
            assert_eq!(
                anonymous::anonymous_signers(shape.signer_width()),
                vec![[0; 32]; shape.signer_width()],
                "{shape:?}"
            );
        }
    }
}

/// One unpadded ring note of `amount` lamports, the anonymous rail adds its payments.
fn ring_transaction(sender: &ShieldedKeypair, amount: u64) -> ConfidentialTransaction {
    ConfidentialTransaction::new_with_ring(
        vec![note(sender, amount, 0, Some(program()))],
        Address::new_from_array([7; 32]),
        program(),
    )
    .unwrap()
}

fn sol_payment(to: AnonymousRecipient, amount: u64) -> AnonymousPayment {
    AnonymousPayment {
        to,
        asset: Mint::SOL,
        amount,
    }
}

fn owner_transfer(
    sender: &ShieldedKeypair,
    transaction: ConfidentialTransaction,
) -> CustomRingTransfer<'_> {
    CustomRingTransfer::new(CustomRingTransferInput {
        ring: ring(),
        sender,
        nullifier_key: Some(&sender.nullifier_key),
        transaction,
    })
}

#[tokio::test]
async fn an_anonymous_ring_refuses_a_public_owner() {
    let (sender, prepared) = prepared_transfer(4);
    let transfer = owner_transfer(&sender, prepared);
    assert!(matches!(
        transfer
            .rail
            .stage(ring(), &Accounts::default(), &anonymous())
            .await,
        Err(RingError::MissingAnonymousSigner)
    ));
}

#[tokio::test]
async fn the_hidden_owner_is_the_sender_on_an_anonymous_ring() {
    let (sender, prepared) = prepared_transfer(4);
    let other = ShieldedKeypair::new_ed25519().unwrap();
    let transfer = owner_transfer(&sender, prepared)
        .with_anonymous_signer(&other.signing_key, &sender.viewing_key);
    assert!(matches!(
        transfer
            .rail
            .stage(ring(), &Accounts::default(), &anonymous(), None)
            .await,
        Err(RingError::AnonymousSignerMismatch)
    ));
    let (sender, prepared) = prepared_transfer(4);
    let transfer = owner_transfer(&sender, prepared)
        .with_anonymous_signer(&sender.signing_key, &sender.viewing_key);
    assert!(matches!(
        transfer
            .rail
            .stage(ring(), &Accounts::default(), &audit_only(), None)
            .await,
        Err(RingError::NotAnonymousRing)
    ));
}

/// A public signature by the hidden owner, as payer or co-signer, would name it.
#[tokio::test]
async fn the_hidden_owner_never_signs_in_public() {
    for as_cosigner in [false, true] {
        let (sender, prepared) = prepared_transfer(4);
        let owner = solana_signer::Signer::pubkey(&sender);
        let prepared = match as_cosigner {
            true => {
                let mut transaction = ConfidentialTransaction::new(
                    prepared.inputs().to_vec(),
                    Address::new_from_array([7; 32]),
                )
                .unwrap();
                transaction
                    .transfer_sol(&sender.shielded_address().unwrap(), 4)
                    .unwrap();
                transaction
            }
            false => prepared,
        };
        let mut transfer = owner_transfer(&sender, prepared)
            .with_anonymous_signer(&sender.signing_key, &sender.viewing_key);
        if as_cosigner {
            transfer = transfer.with_cosigner(owner);
        }
        assert!(matches!(
            transfer
                .rail
                .stage(
                    ring(),
                    &Accounts::default(),
                    &anonymous(),
                    transfer.cosigner
                )
                .await,
            Err(RingError::AnonymousPublicSignerLinksOwner)
        ));
    }
}

#[tokio::test]
async fn anonymous_staging_derives_every_tag_from_the_sender_key() {
    let sender = ShieldedKeypair::new_ed25519().unwrap();
    let recipient = ShieldedKeypair::new_ed25519().unwrap();
    let receiver = recipient.shielded_address().unwrap();
    let address = RingAddress {
        recipient: receiver,
        ring_program_id: program(),
        inbox_secret: recipient.viewing_key.inbox_secret(0).unwrap(),
    };
    let inbox_tag = address.inbox_secret.view_tag(0).unwrap();
    let pair_tag = sender
        .viewing_key
        .pair_send_view_tag(&receiver.viewing_pubkey, 0)
        .unwrap();
    for (recipient, tag) in [
        (AnonymousRecipient::Address(address.clone()), inbox_tag),
        (AnonymousRecipient::Paired(address.clone()), pair_tag),
    ] {
        let transaction = ring_transaction(&sender, 10);
        let first_nullifier = *transaction.first_nullifier();
        let transfer = owner_transfer(&sender, transaction)
            .with_anonymous_signer(&sender.signing_key, &sender.viewing_key)
            .with_payment(sol_payment(recipient, 4))
            .unwrap()
            .with_shape(Shape::IN2_OUT2)
            .unwrap();
        let staged = transfer
            .rail
            .stage(ring(), &Accounts::default(), &anonymous(), None)
            .await
            .unwrap();
        let external = &staged.proof_inputs.external_data;
        assert_eq!(external.resolved_owner_tags[0], tag);
        assert_eq!(
            external.resolved_owner_tags[1],
            sender
                .viewing_key
                .ring_change_view_tag(&first_nullifier, 1)
                .unwrap()
        );
        assert_eq!(
            staged.proof_inputs.blinding_seed,
            sender
                .viewing_key
                .ring_blinding_seed(&first_nullifier)
                .unwrap()
        );
    }
    let foreign = Address::new_from_array([9; 32]);
    let transfer = owner_transfer(&sender, ring_transaction(&sender, 10))
        .with_anonymous_signer(&sender.signing_key, &sender.viewing_key)
        .with_payment(sol_payment(
            AnonymousRecipient::Address(RingAddress {
                ring_program_id: foreign,
                ..address
            }),
            4,
        ))
        .unwrap();
    assert!(matches!(
        transfer
            .rail
            .stage(ring(), &Accounts::default(), &anonymous(), None)
            .await,
        Err(RingError::ForeignRing(ring)) if ring == foreign
    ));
}

#[tokio::test]
async fn an_anonymous_exit_publishes_the_default_ring_owner() {
    let sender = ShieldedKeypair::new_ed25519().unwrap();
    let recipient = ShieldedKeypair::new_ed25519().unwrap();
    let receiver = recipient.shielded_address().unwrap();
    let mut transaction = ConfidentialTransaction::new_with_ring(
        vec![note(&sender, 10, 0, Some(program()))],
        Address::new_from_array([7; 32]),
        program(),
    )
    .unwrap();
    transaction
        .transfer_with_ring(&receiver, Mint::SOL, 4, None)
        .unwrap();
    transaction
        .pad_utxos(Shape::IN2_OUT2, &sender.shielded_address().unwrap())
        .unwrap();
    let first_nullifier = *transaction.first_nullifier();
    let transfer = owner_transfer(&sender, transaction)
        .with_anonymous_signer(&sender.signing_key, &sender.viewing_key);
    let staged = transfer
        .rail
        .stage(ring(), &Accounts::default(), &anonymous(), None)
        .await
        .unwrap();
    let external = &staged.proof_inputs.external_data;
    let owner_key = receiver.signing_pubkey.confidential_view_tag().unwrap();
    assert_eq!(external.outputs[0].owner_tag, OwnerTag::Inline(owner_key));
    assert_eq!(external.resolved_owner_tags[0], owner_key);
    let exit = external.outputs[0].data.as_deref().unwrap();
    assert!(confidential_encrypted_output_body(exit).is_some_and(|body| !body.is_empty()));
    let change = external.outputs[1].data.as_deref().unwrap();
    assert!(ring_anonymous_encrypted_output_body(change).is_some());
    assert_eq!(
        external.resolved_owner_tags[1],
        sender
            .viewing_key
            .ring_change_view_tag(&first_nullifier, 1)
            .unwrap()
    );
    assert_eq!(staged.proof_inputs.output_utxos[0].ring_program_id, None);
    assert_eq!(
        staged.proof_inputs.output_utxos[1].ring_program_id,
        Some(program())
    );
}

/// AnonymousRingEddsa keeps every note in the ring and refuses a slot it cannot prove.
#[test]
fn anonymous_slots_carry_ed25519_owners_in_the_ring_or_the_default_ring() {
    let sender = ShieldedKeypair::new_ed25519().unwrap();
    let mut transaction = ConfidentialTransaction::new_with_ring(
        vec![note(&sender, 10, 0, Some(program()))],
        Address::new_from_array([7; 32]),
        program(),
    )
    .unwrap();
    transaction
        .transfer_sol(&sender.shielded_address().unwrap(), 4)
        .unwrap();
    transaction
        .pad_utxos(Shape::IN2_OUT2, &sender.shielded_address().unwrap())
        .unwrap();
    let key = transaction_key(&sender, *transaction.first_nullifier()).unwrap();
    let address = sender.shielded_address().unwrap();
    let inputs = OutputEncryption {
        sender: &address,
        tx_viewing_key: &key,
        encoder: &AnonymousViewTags::new(&sender.viewing_key),
    }
    .encrypt(transaction)
    .unwrap();
    let shape = inputs.check_shape().unwrap();
    anonymous::check_anonymous_slots(shape, &inputs).unwrap();
    for attach in [
        |output: &mut SppProofOutputUtxo| output.data_hash = Some([2; 32]),
        |output: &mut SppProofOutputUtxo| output.ring_data_hash = Some([2; 32]),
    ] {
        let mut attached = inputs.clone();
        attach(&mut attached.output_utxos[0]);
        assert!(matches!(
            anonymous::check_anonymous_slots(shape, &attached),
            Err(RingError::AnonymousOutputData)
        ));
    }
    let mut compact = inputs.clone();
    compact.output_utxos[1] = SppProofOutputUtxo {
        compact: true,
        ..Default::default()
    };
    compact.check_shape().unwrap();
    assert!(matches!(
        anonymous::check_anonymous_slots(shape, &compact),
        Err(RingError::InvalidAnonymousSlot)
    ));
    let mut compact_input = inputs.clone();
    compact_input.input_utxos[1] = SppProofInputUtxo::compact(0).unwrap();
    assert!(matches!(
        anonymous::check_anonymous_slots(shape, &compact_input),
        Err(RingError::InvalidAnonymousSlot)
    ));
    for output_cache in [false, true] {
        let mut cached = inputs.clone();
        if output_cache {
            cached.output_utxos[0].cache_slot = Some(0);
        } else {
            cached.input_utxos[0].cache_slot = Some(0);
        }
        assert!(matches!(
            anonymous::check_anonymous_slots(shape, &cached),
            Err(RingError::InvalidAnonymousSlot)
        ));
    }
    assert!(matches!(
        anonymous::check_anonymous_slots(Shape::IN2_OUT8, &inputs),
        Err(RingError::AnonymousShapeUnsupported)
    ));
    let mut exit = inputs.clone();
    exit.output_utxos[0].ring_program_id = None;
    anonymous::check_anonymous_slots(shape, &exit).unwrap();
    let mut pda = inputs;
    pda.output_utxos[0]
        .owner_address
        .as_mut()
        .unwrap()
        .signing_pubkey = zolana_keypair::PublicKey::from_pda(&Address::new_from_array([9; 32]));
    assert!(matches!(
        anonymous::check_anonymous_slots(shape, &pda),
        Err(RingError::InvalidAnonymousSlot)
    ));
}

/// One read per stream and window, two addresses on one viewing key share the pair stream.
#[tokio::test]
async fn anonymous_slots_reserve_distinct_indices_per_stream() {
    let sender = ShieldedKeypair::new_ed25519().unwrap();
    let recipient = ShieldedKeypair::new_ed25519().unwrap();
    let other = ShieldedKeypair::new_ed25519().unwrap();
    let receiver = recipient.shielded_address().unwrap();
    let sibling = zolana_keypair::ShieldedAddress {
        viewing_pubkey: receiver.viewing_pubkey,
        ..other.shielded_address().unwrap()
    };
    let address = RingAddress {
        recipient: receiver,
        ring_program_id: program(),
        inbox_secret: recipient.viewing_key.inbox_secret(0).unwrap(),
    };
    let inbox = |j| address.inbox_secret.view_tag(j).unwrap();
    let pair = |k| {
        sender
            .viewing_key
            .pair_send_view_tag(&receiver.viewing_pubkey, k)
            .unwrap()
    };
    let indexer = OccupiedTags {
        occupied: vec![inbox(0), inbox(2), pair(0)],
        queries: Mutex::default(),
    };
    let sibling_address = RingAddress {
        recipient: sibling,
        ..address.clone()
    };
    let transfer = owner_transfer(&sender, ring_transaction(&sender, 20))
        .with_anonymous_signer(&sender.signing_key, &sender.viewing_key)
        .with_payment(sol_payment(AnonymousRecipient::Address(address.clone()), 2))
        .unwrap()
        .with_payment(sol_payment(AnonymousRecipient::Address(address.clone()), 3))
        .unwrap()
        .with_payment(sol_payment(
            AnonymousRecipient::Paired(sibling_address.clone()),
            4,
        ))
        .unwrap();
    let staged = transfer
        .rail
        .stage(ring(), &indexer, &anonymous(), None)
        .await
        .unwrap();
    let tags = &staged.proof_inputs.external_data.resolved_owner_tags;
    // Slots 0 and 1 pay the address, slot 2 the sibling on the pair stream, slot 3 is change.
    assert_eq!(&tags[..3], &[inbox(1), inbox(3), pair(1)]);
    assert_eq!(indexer.queries.lock().unwrap().len(), 2);

    // A paired recipient on the same viewing key competes for the same pair indices.
    let indexer = OccupiedTags::default();
    let transfer = owner_transfer(&sender, ring_transaction(&sender, 20))
        .with_anonymous_signer(&sender.signing_key, &sender.viewing_key)
        .with_payment(sol_payment(AnonymousRecipient::Paired(address), 2))
        .unwrap()
        .with_payment(sol_payment(AnonymousRecipient::Paired(sibling_address), 3))
        .unwrap();
    let staged = transfer
        .rail
        .stage(ring(), &indexer, &anonymous(), None)
        .await
        .unwrap();
    let tags = &staged.proof_inputs.external_data.resolved_owner_tags;
    assert_eq!(&tags[..2], &[pair(0), pair(1)]);
    assert_eq!(indexer.queries.lock().unwrap().len(), 1);
}

/// Two requests of one wallet carry different inbox secrets, each slot keeps the address it pays.
#[tokio::test]
async fn anonymous_tags_follow_the_address_each_output_pays() {
    let sender = ShieldedKeypair::new_ed25519().unwrap();
    let recipient = ShieldedKeypair::new_ed25519().unwrap();
    let request = |index| RingAddress {
        recipient: recipient.shielded_address().unwrap(),
        ring_program_id: program(),
        inbox_secret: recipient.viewing_key.inbox_secret(index).unwrap(),
    };
    let (first, second) = (request(0), request(1));
    for payments in [[(&first, 2), (&second, 3)], [(&second, 3), (&first, 2)]] {
        let mut transfer = owner_transfer(&sender, ring_transaction(&sender, 10))
            .with_anonymous_signer(&sender.signing_key, &sender.viewing_key);
        for (address, amount) in payments {
            transfer = transfer
                .with_payment(sol_payment(
                    AnonymousRecipient::Address(address.clone()),
                    amount,
                ))
                .unwrap();
        }
        let staged = transfer
            .with_shape(Shape::IN2_OUT4)
            .unwrap()
            .rail
            .stage(ring(), &Accounts::default(), &anonymous(), None)
            .await
            .unwrap();
        let inputs = &staged.proof_inputs;
        for (slot, (address, amount)) in payments.into_iter().enumerate() {
            assert_eq!(inputs.output_utxos[slot].amount, amount);
            assert_eq!(
                inputs.external_data.resolved_owner_tags[slot],
                address.inbox_secret.view_tag(0).unwrap()
            );
        }
    }
}

#[tokio::test]
async fn an_anonymous_self_payment_takes_its_inbox_tag_beside_the_change_tag() {
    let sender = ShieldedKeypair::new_ed25519().unwrap();
    let own = RingAddress {
        recipient: sender.shielded_address().unwrap(),
        ring_program_id: program(),
        inbox_secret: sender.viewing_key.inbox_secret(7).unwrap(),
    };
    let inbox = |j| own.inbox_secret.view_tag(j).unwrap();
    let indexer = OccupiedTags {
        occupied: vec![inbox(0), inbox(1)],
        queries: Mutex::default(),
    };
    let transaction = ring_transaction(&sender, 10);
    let first_nullifier = *transaction.first_nullifier();
    let staged = owner_transfer(&sender, transaction)
        .with_anonymous_signer(&sender.signing_key, &sender.viewing_key)
        .with_payment(sol_payment(AnonymousRecipient::Address(own.clone()), 4))
        .unwrap()
        .rail
        .stage(ring(), &indexer, &anonymous(), None)
        .await
        .unwrap();
    let change = sender
        .viewing_key
        .ring_change_view_tag(&first_nullifier, 1)
        .unwrap();
    assert_eq!(
        &staged.proof_inputs.external_data.resolved_owner_tags[..2],
        &[inbox(2), change]
    );
    assert_eq!(indexer.queries.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn an_anonymous_payment_to_another_viewing_key_of_the_sender_is_sealed_to_it() {
    let sender = ShieldedKeypair::new_ed25519().unwrap();
    let other = ShieldedKeypair::new_ed25519().unwrap();
    let sibling = RingAddress {
        recipient: ShieldedAddress {
            viewing_pubkey: other.viewing_pubkey(),
            ..sender.shielded_address().unwrap()
        },
        ring_program_id: program(),
        inbox_secret: other.viewing_key.inbox_secret(0).unwrap(),
    };
    let staged = owner_transfer(&sender, ring_transaction(&sender, 10))
        .with_anonymous_signer(&sender.signing_key, &sender.viewing_key)
        .with_payment(sol_payment(AnonymousRecipient::Address(sibling.clone()), 4))
        .unwrap()
        .rail
        .stage(ring(), &Accounts::default(), &anonymous(), None)
        .await
        .unwrap();
    let external = &staged.proof_inputs.external_data;
    assert_eq!(
        external.resolved_owner_tags[0],
        sibling.inbox_secret.view_tag(0).unwrap()
    );
    let body =
        ring_anonymous_encrypted_output_body(external.outputs[0].data.as_deref().unwrap()).unwrap();
    let open = |reader: &ShieldedKeypair| {
        RingAnonymousSlot {
            tx_viewing_pk: staged.tx_viewing_key.pubkey(),
            recipient_pk: reader.viewing_pubkey(),
            salt: external.salt,
            slot: 0,
        }
        .open(&reader.viewing_key, body)
    };
    let opened = open(&other).unwrap();
    assert_eq!(opened.amount, 4);
    assert_eq!(
        opened.pair_u,
        sender
            .viewing_key
            .pair_key(&other.viewing_pubkey())
            .unwrap()
            .pubkey()
            .u()
    );
    assert_ne!(open(&sender).ok(), Some(opened));
}

#[tokio::test]
async fn anonymous_staging_refuses_an_output_without_a_payment() {
    let sender = ShieldedKeypair::new_ed25519().unwrap();
    let address = sender.shielded_address().unwrap();
    let stranger = ShieldedKeypair::new_ed25519()
        .unwrap()
        .shielded_address()
        .unwrap();
    for owner in [
        stranger,
        ShieldedAddress {
            viewing_pubkey: stranger.viewing_pubkey,
            ..address
        },
        ShieldedAddress {
            nullifier_pubkey: stranger.nullifier_pubkey,
            ..address
        },
    ] {
        let mut transaction = ring_transaction(&sender, 10);
        transaction.transfer_sol(&owner, 4).unwrap();
        let staged = owner_transfer(&sender, transaction)
            .with_anonymous_signer(&sender.signing_key, &sender.viewing_key)
            .rail
            .stage(ring(), &Accounts::default(), &anonymous(), None)
            .await;
        assert!(matches!(
            staged,
            Err(RingError::Transaction(
                TransactionError::UnknownAnonymousRecipient { slot_index: 0 }
            ))
        ));
    }
}

#[tokio::test]
async fn anonymous_padding_is_framed_like_a_real_slot() {
    let sender = ShieldedKeypair::new_ed25519().unwrap();
    let mut transaction = ConfidentialTransaction::new_with_ring(
        vec![note(&sender, 10, 0, Some(program()))],
        Address::new_from_array([7; 32]),
        program(),
    )
    .unwrap();
    transaction
        .transfer_sol(&sender.shielded_address().unwrap(), 4)
        .unwrap();
    transaction
        .pad_utxos(Shape::IN2_OUT4, &sender.shielded_address().unwrap())
        .unwrap();
    let transfer = owner_transfer(&sender, transaction)
        .with_anonymous_signer(&sender.signing_key, &sender.viewing_key);
    let staged = transfer
        .rail
        .stage(ring(), &Accounts::default(), &anonymous(), None)
        .await
        .unwrap();
    let outputs = &staged.proof_inputs.external_data.outputs;
    assert_eq!(outputs.len(), 4);
    let mut tags = Vec::new();
    for output in outputs {
        let data = output.data.as_deref().unwrap();
        assert_eq!(data.len(), 1 + 4 + ANONYMOUS_OUTPUT_BODY_LEN);
        assert_eq!(
            ring_anonymous_encrypted_output_body(data).map(<[u8]>::len),
            Some(ANONYMOUS_OUTPUT_BODY_LEN - 1)
        );
        let OwnerTag::Inline(tag) = output.owner_tag else {
            panic!("inline tag");
        };
        assert_eq!(tag[0], 0);
        assert_ne!(tag, [0; 32]);
        assert_ne!(output.utxo_hash, [0; 32]);
        tags.push(tag);
    }
    tags.sort_unstable();
    tags.dedup();
    assert_eq!(tags.len(), 4);
}

/// A memo has no room in the fixed body, compact padding would leave a slot unpublished.
#[tokio::test]
async fn anonymous_staging_refuses_memos_and_compact_padding() {
    let sender = ShieldedKeypair::new_ed25519().unwrap();
    let receiver = sender.shielded_address().unwrap();
    let mut with_memo = ConfidentialTransaction::new_with_ring(
        vec![note(&sender, 10, 0, Some(program()))],
        Address::new_from_array([7; 32]),
        program(),
    )
    .unwrap();
    with_memo
        .add_output_utxo(
            SppProofOutputUtxo::new(Mint::SOL, 4, receiver)
                .unwrap()
                .with_ring_program_id(program())
                .with_memo(vec![1, 2, 3]),
        )
        .unwrap();
    let transfer = owner_transfer(&sender, with_memo)
        .with_anonymous_signer(&sender.signing_key, &sender.viewing_key);
    assert!(matches!(
        transfer
            .rail
            .stage(ring(), &Accounts::default(), &anonymous(), None)
            .await,
        Err(RingError::Transaction(
            TransactionError::AnonymousOutputData { slot_index: 0 }
        ))
    ));

    let mut compact = ConfidentialTransaction::new_compact_with_ring(
        vec![note(&sender, 10, 0, Some(program()))],
        Address::new_from_array([7; 32]),
        program(),
    )
    .unwrap();
    compact.transfer_sol(&receiver, 4).unwrap();
    compact.pad_utxos(Shape::IN2_OUT4, &receiver).unwrap();
    let transfer = owner_transfer(&sender, compact)
        .with_anonymous_signer(&sender.signing_key, &sender.viewing_key);
    assert!(matches!(
        transfer
            .rail
            .stage(ring(), &Accounts::default(), &anonymous(), None)
            .await,
        Err(RingError::Transaction(
            TransactionError::AnonymousCompactPadding { slot_index: 2 }
        ))
    ));
}
