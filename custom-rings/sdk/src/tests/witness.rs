//! A child of `witness`, the slot plan and the rule check are private to it.

use std::{collections::HashMap, sync::Mutex};

use async_trait::async_trait;
use custom_ring_interface::{
    EscrowKey, MemberRegistryRoot, MEMBER_REGISTRY_ROOT, MEMBER_REGISTRY_ROOT_HISTORY,
};
use solana_account::Account;
use solana_address::Address;
use zolana_client::{ClientError, GetRingMemberRecordRequest, GetRingMemberRecordResponse};
use zolana_keypair::{ShieldedAddress, ShieldedKeypair, X25519Keypair};
use zolana_ring_client::{NullifierKeyEnvelope, SealedNullifierKey};
use zolana_ring_member_registry::MemberRegistryTree;
use zolana_ring_policy::{ListSet, RuleTable};
use zolana_transaction::Mint;

use super::*;
use crate::{
    member_registry::tests::response,
    tests::support::{input, pinned, pinned_with_curator, ring, tree, tree_account, Accounts},
    OutflowLimitProofInput, RingIdentity,
};

/// The configured address tree, its account id is zero.
fn address_tree() -> PoolTree {
    PoolTree {
        address: tree(),
        id: 0,
    }
}

fn curator() -> CustomRing {
    CustomRing::new(Address::new_from_array([77; 32]))
}

fn policy(table: &RuleTable) -> PinnedPolicy {
    PinnedPolicy {
        config: pinned(ring(), table, address_tree()),
        table: *table,
    }
}

fn curated(table: &RuleTable, lists: ListSet) -> PinnedPolicy {
    PinnedPolicy {
        config: pinned_with_curator(
            ring(),
            table,
            address_tree(),
            curator().member_registry_root_pda(),
            lists,
        ),
        table: *table,
    }
}

fn limits_none() -> OutflowLimitProofInput {
    OutflowLimitProofInput::none(RingIdentity {
        ring_id: [0; 32],
        namespace_owner_hash: [0; 32],
    })
}

fn witness<'a>(
    pinned: &'a PinnedPolicy,
    inputs: &'a [SppProofInputUtxo],
    outputs: &'a [SppProofOutputUtxo],
) -> WitnessInput<'a> {
    WitnessInput {
        ring: ring(),
        pinned,
        inputs,
        outputs,
        output_tree_id: 0,
        private_tx_blinding: [0; 32],
        limits: limits_none(),
        key_escrow: false,
    }
}

fn recipient() -> (Member, ShieldedKeypair) {
    let keypair = ShieldedKeypair::new_ed25519().unwrap();
    let address = keypair.shielded_address().unwrap();
    let member =
        Member::from_bytes(address.signing_pubkey.owner_proof_input_hash().unwrap()).unwrap();
    (member, keypair)
}

/// The mint whose asset field `ASSETS` lists.
const MINT: [u8; 32] = [0xd4; 32];

fn output(address: ShieldedAddress, amount: u64) -> SppProofOutputUtxo {
    output_asset(Address::new_from_array(MINT), address, amount)
}

fn output_asset(asset: Address, address: ShieldedAddress, amount: u64) -> SppProofOutputUtxo {
    SppProofOutputUtxo::new(Mint::new(asset, 2), amount, address).unwrap()
}

const EMPTY: RuleTable = RuleTable::builder().build();

/// `hash_bytes` of `MINT`, the asset field an output carries.
const ASSETS: &[[u8; 32]] = &[[
    0x14, 0xa6, 0xb5, 0x09, 0x2f, 0x94, 0x1b, 0xd4, 0x33, 0x6f, 0xe2, 0xa2, 0x5f, 0xc6, 0x17, 0xa9,
    0x51, 0x5b, 0x45, 0x7e, 0x02, 0x7e, 0x0c, 0xf5, 0xe4, 0x86, 0x7c, 0x08, 0x58, 0x85, 0x5e, 0xc1,
]];

#[test]
fn the_inline_pool_lists_the_mint_asset_field() {
    assert_eq!(&hash_bytes(&MINT).unwrap(), &ASSETS[0]);
}

/// An owner guard needs a single unguarded inline asset beside it.
const GUARDED: RuleTable = RuleTable::builder()
    .rule(Rule::require(Subject::OutputOwner, ListId::Allow).above(5))
    .build();

const BLOCK: RuleTable = RuleTable::builder()
    .rule(Rule::forbid(Subject::OutputOwner, ListId::Block))
    .build();

const SENDER_ALLOW: RuleTable = RuleTable::builder()
    .rule(Rule::require(Subject::Sender, ListId::Allow))
    .build();

/// An approval overrides a block.
const MIXED: RuleTable = RuleTable::builder()
    .rule(Rule::any_of(
        Subject::OutputOwner,
        ListSet::single(ListId::Approval),
        ListSet::single(ListId::Block),
    ))
    .build();

#[test]
fn dummy_output_opening_preserves_its_tree_and_blinding() {
    let output = SppProofOutputUtxo {
        blinding: [0x5a; 32],
        ..Default::default()
    };
    let opening = output_opening(&output, 7).unwrap();
    assert_eq!(opening.domain, right_align(&DUMMY_DOMAIN.to_be_bytes()));
    assert_eq!(opening.tree_id, tree_id_field(7));
    assert_eq!(opening.blinding, [0x5a; 32]);
    assert_eq!(opening.owner_pk_hash, [0; 32]);
}

#[test]
fn a_dummy_input_opens_only_its_domain() {
    let dummy = SppProofInputUtxo::dummy(3).unwrap();
    let opening = input_opening(&dummy).unwrap();
    assert_eq!(opening.domain, right_align(&DUMMY_DOMAIN.to_be_bytes()));
    assert_eq!(opening.tree_id, [0; 32]);
    assert_eq!(opening.nullifier_pk, [0; 32]);
}

#[test]
fn a_rule_holds_on_its_primary_list_or_off_every_alternative() {
    let rule = Rule::any_of(
        Subject::OutputOwner,
        ListSet::single(ListId::Approval),
        ListSet::single(ListId::Block),
    );
    let RuleSource::Lists { present, absent } = rule.source;
    assert!(satisfied(&rule, present, absent, ListSet::EMPTY));
    assert!(satisfied(
        &rule,
        present,
        absent,
        ListSet::single(ListId::Approval)
    ));
    assert!(satisfied(
        &rule,
        present,
        absent,
        ListSet::of(&[ListId::Approval, ListId::Block])
    ));
    assert!(!satisfied(
        &rule,
        present,
        absent,
        ListSet::single(ListId::Block)
    ));
    let forbid = Rule::forbid(Subject::Sender, ListId::Frozen);
    let RuleSource::Lists { present, absent } = forbid.source;
    assert!(satisfied(
        &forbid,
        present,
        absent,
        ListSet::single(ListId::Allow)
    ));
    assert!(!satisfied(
        &forbid,
        present,
        absent,
        ListSet::single(ListId::Frozen)
    ));
}

fn registry_account(ring: CustomRing, tree: &MemberRegistryTree) -> Account {
    let mut history = [[0; 32]; MEMBER_REGISTRY_ROOT_HISTORY];
    history[0] = tree.root();
    let root = MemberRegistryRoot {
        discriminator: MEMBER_REGISTRY_ROOT,
        next_index: tree.next_index().to_le_bytes(),
        bump: Address::find_program_address(&[MemberRegistryRoot::SEED], &ring.program_id()).1,
        history_cursor: 0,
        history,
    };
    Account {
        lamports: 1,
        data: bytemuck::bytes_of(&root).to_vec(),
        owner: ring.program_id(),
        executable: false,
        rent_epoch: 0,
    }
}

/// Serves the tree account and both registries, with the indexer's view of each.
struct RegistryRpc {
    accounts: Accounts,
    own: MemberRegistryTree,
    foreign: Option<MemberRegistryTree>,
    seals: HashMap<[u8; 32], SealedNullifierKey>,
    record_calls: Mutex<Vec<Address>>,
}

impl RegistryRpc {
    fn new(own: MemberRegistryTree, foreign: Option<MemberRegistryTree>) -> Self {
        let mut accounts = Accounts::default()
            .with(tree(), tree_account(address_tree()))
            .with(
                ring().member_registry_root_pda(),
                registry_account(ring(), &own),
            );
        if let Some(foreign) = &foreign {
            accounts = accounts.with(
                curator().member_registry_root_pda(),
                registry_account(curator(), foreign),
            );
        }
        Self {
            accounts,
            own,
            foreign,
            seals: HashMap::new(),
            record_calls: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl AsyncRpc for RegistryRpc {
    async fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
        self.accounts.get_account(address).await
    }

    async fn get_ring_member_record(
        &self,
        request: GetRingMemberRecordRequest,
    ) -> Result<GetRingMemberRecordResponse, ClientError> {
        let program = Address::new_from_array(request.ring_program_id.0.to_bytes());
        self.record_calls.lock().unwrap().push(program);
        let tree = if program == ring().program_id() {
            &self.own
        } else {
            self.foreign.as_ref().expect("a curator registry")
        };
        let member = Member::from_bytes(request.member.0).unwrap();
        Ok(response(
            tree,
            &member,
            0,
            self.seals.get(&request.member.0),
        ))
    }
}

fn listed(tree: &mut MemberRegistryTree, member: Member, lists: ListSet) {
    let items = tree
        .list_items(&[(*member.as_bytes(), lists.record_bits())])
        .unwrap();
    tree.apply(&items).unwrap();
}

#[tokio::test]
async fn live_slots_open_their_records_in_circuit_order() {
    let sender = ShieldedKeypair::new_ed25519().unwrap();
    let (recipient_member, recipient) = recipient();
    let inputs = [
        input(&sender, 5, 0, None),
        SppProofInputUtxo::dummy(0).unwrap(),
    ];
    let outputs = [output(recipient.shielded_address().unwrap(), 5)];
    let policy = policy(&EMPTY);
    let rpc = RegistryRpc::new(MemberRegistryTree::new().unwrap(), None);
    let built = witness(&policy, &inputs, &outputs)
        .build(&rpc, false)
        .await
        .unwrap();
    assert_eq!(built.n_in, 2);
    assert_eq!(built.n_out, 1);
    assert_eq!(built.member_registry_root, rpc.own.root());
    assert_eq!(built.foreign_root, [0; 32]);
    assert!(built.foreign.is_none());
    assert_eq!(built.registry.root, rpc.own.root());
    let opened: Vec<usize> = built
        .subjects
        .iter()
        .enumerate()
        .filter_map(|(slot, subject)| subject.as_ref().map(|_| slot))
        .collect();
    assert_eq!(opened, [0, POLICY_INPUT_SLOTS]);
    let subject = built.subjects[POLICY_INPUT_SLOTS].as_ref().unwrap();
    assert!(!subject.present);
    assert_eq!(subject.low_member, [0; 32]);
    assert!(built.foreign_subjects.iter().all(Option::is_none));
    assert_eq!(built.outputs[0].ct_hash, [0; 32]);
    assert_eq!(built.trees.len(), 1);
    assert_eq!(rpc.record_calls.lock().unwrap().len(), 2);
    let _ = recipient_member;
}

#[tokio::test]
async fn compact_padding_does_not_change_the_exact_policy_shape() {
    let sender = ShieldedKeypair::new_ed25519().unwrap();
    let (_, recipient) = recipient();
    let inputs = [
        input(&sender, 5, 0, None),
        input(&sender, 7, 0, None),
        SppProofInputUtxo::compact(0).unwrap(),
        SppProofInputUtxo::compact(0).unwrap(),
    ];
    let mut outputs = vec![output(recipient.shielded_address().unwrap(), 4); 3];
    outputs.push(SppProofOutputUtxo {
        compact: true,
        ..Default::default()
    });
    let policy = policy(&EMPTY);
    let rpc = RegistryRpc::new(MemberRegistryTree::new().unwrap(), None);
    let built = witness(&policy, &inputs, &outputs)
        .build(&rpc, false)
        .await
        .unwrap();
    assert_eq!((built.n_in, built.n_out), (2, 3));
    assert!(built.supports_two_by_three());
    assert!(built.subjects[2..POLICY_INPUT_SLOTS]
        .iter()
        .all(Option::is_none));
}

#[tokio::test]
async fn a_blocked_recipient_is_refused_before_proving() {
    let sender = ShieldedKeypair::new_ed25519().unwrap();
    let (member, recipient) = recipient();
    let inputs = [input(&sender, 5, 0, None)];
    let outputs = [output(recipient.shielded_address().unwrap(), 5)];
    let policy = policy(&BLOCK);
    let mut registry = MemberRegistryTree::new().unwrap();
    listed(&mut registry, member, ListSet::single(ListId::Block));
    let rpc = RegistryRpc::new(registry, None);
    assert!(matches!(
        witness(&policy, &inputs, &outputs).build(&rpc, false).await,
        Err(RingError::PolicyRuleUnsatisfied)
    ));
    let rpc = RegistryRpc::new(MemberRegistryTree::new().unwrap(), None);
    let built = witness(&policy, &inputs, &outputs)
        .build(&rpc, false)
        .await
        .unwrap();
    assert!(!built.subjects[POLICY_INPUT_SLOTS].as_ref().unwrap().present);
}

#[tokio::test]
async fn an_approval_overrides_a_block_and_a_sender_rule_reads_the_inputs() {
    let sender = ShieldedKeypair::new_ed25519().unwrap();
    let sender_member =
        Member::from_bytes(sender.signing_pubkey().owner_proof_input_hash().unwrap()).unwrap();
    let (member, recipient) = recipient();
    let inputs = [input(&sender, 5, 0, None)];
    let outputs = [output(recipient.shielded_address().unwrap(), 5)];
    let mixed = policy(&MIXED);
    let mut blocked = MemberRegistryTree::new().unwrap();
    listed(&mut blocked, member, ListSet::single(ListId::Block));
    let rpc = RegistryRpc::new(blocked.clone(), None);
    assert!(matches!(
        witness(&mixed, &inputs, &outputs).build(&rpc, false).await,
        Err(RingError::PolicyRuleUnsatisfied)
    ));
    listed(
        &mut blocked,
        member,
        ListSet::of(&[ListId::Block, ListId::Approval]),
    );
    let rpc = RegistryRpc::new(blocked, None);
    let built = witness(&mixed, &inputs, &outputs)
        .build(&rpc, false)
        .await
        .unwrap();
    let subject = built.subjects[POLICY_INPUT_SLOTS].as_ref().unwrap();
    assert!(subject.present);
    assert_eq!(
        subject.record.lists,
        ListSet::of(&[ListId::Block, ListId::Approval]).record_bits()
    );

    let senders = policy(&SENDER_ALLOW);
    let rpc = RegistryRpc::new(MemberRegistryTree::new().unwrap(), None);
    assert!(matches!(
        witness(&senders, &inputs, &outputs)
            .build(&rpc, false)
            .await,
        Err(RingError::PolicyRuleUnsatisfied)
    ));
    let mut allowed = MemberRegistryTree::new().unwrap();
    listed(&mut allowed, sender_member, ListSet::single(ListId::Allow));
    let rpc = RegistryRpc::new(allowed, None);
    assert!(witness(&senders, &inputs, &outputs)
        .build(&rpc, false)
        .await
        .is_ok());
}

#[tokio::test]
async fn a_guarded_rule_exempts_a_recipient_only_below_the_aggregated_threshold() {
    let sender = ShieldedKeypair::new_ed25519().unwrap();
    let (_, recipient) = recipient();
    let inputs = [input(&sender, 10, 0, None)];
    let policy = policy(&GUARDED);
    let address = recipient.shielded_address().unwrap();
    let rpc = RegistryRpc::new(MemberRegistryTree::new().unwrap(), None);
    let exempt = [output(address, 3), output(address, 2)];
    assert!(witness(&policy, &inputs, &exempt)
        .build(&rpc, false)
        .await
        .is_ok());
    let above = [output(address, 3), output(address, 3)];
    assert!(matches!(
        witness(&policy, &inputs, &above).build(&rpc, false).await,
        Err(RingError::PolicyRuleUnsatisfied)
    ));
    let foreign_asset = [
        output(address, 1),
        output_asset(Address::new_from_array([8; 32]), address, 1),
    ];
    assert!(matches!(
        witness(&policy, &inputs, &foreign_asset)
            .build(&rpc, false)
            .await,
        Err(RingError::PolicyRuleUnsatisfied)
    ));
}

#[tokio::test]
async fn a_curator_registry_serves_the_lists_the_sources_name() {
    let sender = ShieldedKeypair::new_ed25519().unwrap();
    let (member, recipient) = recipient();
    let inputs = [input(&sender, 5, 0, None)];
    let outputs = [output(recipient.shielded_address().unwrap(), 5)];
    let policy = curated(&BLOCK, ListSet::single(ListId::Block));
    let mut blocked = MemberRegistryTree::new().unwrap();
    listed(&mut blocked, member, ListSet::single(ListId::Block));
    // A block in the ring's own registry does not count, the curator's does.
    let rpc = RegistryRpc::new(blocked.clone(), Some(MemberRegistryTree::new().unwrap()));
    let built = witness(&policy, &inputs, &outputs)
        .build(&rpc, false)
        .await
        .unwrap();
    assert_eq!(built.foreign_root, rpc.foreign.as_ref().unwrap().root());
    assert!(built.foreign_subjects[POLICY_INPUT_SLOTS].is_some());
    assert_eq!(
        built.foreign.unwrap().registry,
        curator().member_registry_root_pda()
    );
    assert_eq!(
        built.reads().foreign.unwrap().curator.program_id(),
        curator().program_id()
    );
    assert_eq!(
        built.sources[ListId::Block.slot()].registry,
        zolana_ring_policy::registry_field(curator().member_registry_root_pda().as_array())
            .unwrap()
    );
    let rpc = RegistryRpc::new(MemberRegistryTree::new().unwrap(), Some(blocked));
    assert!(matches!(
        witness(&policy, &inputs, &outputs).build(&rpc, false).await,
        Err(RingError::PolicyRuleUnsatisfied)
    ));
}

#[tokio::test]
async fn escrow_requires_the_output_owner_to_register_the_key_it_uses() {
    let sender = ShieldedKeypair::new_ed25519().unwrap();
    let (member, recipient) = recipient();
    let inputs = [input(&sender, 5, 0, None)];
    let outputs = [output(recipient.shielded_address().unwrap(), 5)];
    let policy = policy(&EMPTY);
    fn escrowed<'a>(
        pinned: &'a PinnedPolicy,
        inputs: &'a [SppProofInputUtxo],
        outputs: &'a [SppProofOutputUtxo],
    ) -> WitnessInput<'a> {
        WitnessInput {
            key_escrow: true,
            ..witness(pinned, inputs, outputs)
        }
    }
    let rpc = RegistryRpc::new(MemberRegistryTree::new().unwrap(), None);
    assert!(matches!(
        escrowed(&policy, &inputs, &outputs).build(&rpc, false).await,
        Err(RingError::UnregisteredOutputKey { owner }) if owner == member
    ));
    let auditor = X25519Keypair::new();
    let envelope = NullifierKeyEnvelope::new(&recipient.nullifier_key, &auditor.pubkey()).unwrap();
    let escrow_key = EscrowKey {
        nullifier_pk: &envelope.nullifier_pk,
        ciphertext: &envelope.sealed.ciphertext,
    }
    .hash()
    .unwrap();
    let mut registry = MemberRegistryTree::new().unwrap();
    let item = registry
        .register_item(member.as_bytes(), escrow_key)
        .unwrap();
    registry.apply(&[item]).unwrap();
    let mut rpc = RegistryRpc::new(registry, None);
    rpc.seals.insert(*member.as_bytes(), envelope.sealed);
    let built = escrowed(&policy, &inputs, &outputs)
        .build(&rpc, false)
        .await
        .unwrap();
    assert!(built.key_escrow);
    assert_eq!(
        built.outputs[0].ct_hash,
        ciphertext_hash(&envelope.sealed.ciphertext).unwrap()
    );
    // Another member's key under the owner's record is not the owner's.
    let stranger = ShieldedKeypair::new_ed25519().unwrap();
    let other = NullifierKeyEnvelope::new(&stranger.nullifier_key, &auditor.pubkey()).unwrap();
    rpc.seals.insert(*member.as_bytes(), other.sealed);
    assert!(matches!(
        escrowed(&policy, &inputs, &outputs).build(&rpc, false).await,
        Err(RingError::UnregisteredOutputKey { owner }) if owner == member
    ));
}

#[tokio::test]
async fn an_indexed_build_leaves_the_records_to_the_prover() {
    let sender = ShieldedKeypair::new_ed25519().unwrap();
    let (_, recipient) = recipient();
    let inputs = [input(&sender, 5, 0, None)];
    let outputs = [output(recipient.shielded_address().unwrap(), 5)];
    let policy = curated(&BLOCK, ListSet::single(ListId::Block));
    let rpc = RegistryRpc::new(
        MemberRegistryTree::new().unwrap(),
        Some(MemberRegistryTree::new().unwrap()),
    );
    let built = witness(&policy, &inputs, &outputs)
        .build(&rpc, true)
        .await
        .unwrap();
    assert!(built.subjects.iter().all(Option::is_none));
    assert!(built.foreign_subjects.iter().all(Option::is_none));
    assert!(rpc.record_calls.lock().unwrap().is_empty());
    let indexed = built.indexed.as_ref().unwrap();
    assert_eq!(indexed.registry.ring_program_id, ring().program_id());
    assert_eq!(indexed.registry.next_index, 1);
    assert_eq!(
        indexed.foreign.as_ref().unwrap().ring_program_id,
        curator().program_id()
    );
    assert_eq!(built.outputs[0].ct_hash, [0; 32]);
}

#[tokio::test]
async fn a_missing_registry_or_a_tree_under_another_id_is_refused() {
    let sender = ShieldedKeypair::new_ed25519().unwrap();
    let (_, recipient) = recipient();
    let inputs = [input(&sender, 5, 0, None)];
    let outputs = [output(recipient.shielded_address().unwrap(), 5)];
    let policy = policy(&EMPTY);
    let rpc = Accounts::default().with(tree(), tree_account(address_tree()));
    assert!(matches!(
        witness(&policy, &inputs, &outputs).build(&rpc, false).await,
        Err(RingError::MissingMemberRegistry)
    ));
    let other = PoolTree {
        address: tree(),
        id: 9,
    };
    let rpc = RegistryRpc {
        accounts: Accounts::default().with(tree(), tree_account(other)),
        ..RegistryRpc::new(MemberRegistryTree::new().unwrap(), None)
    };
    assert!(matches!(
        witness(&policy, &inputs, &outputs).build(&rpc, false).await,
        Err(RingError::TreeIdMismatch {
            expected: 9,
            found: 0,
            ..
        })
    ));
}

#[test]
fn a_transfer_past_the_policy_slots_is_refused() {
    let sender = ShieldedKeypair::new_ed25519().unwrap();
    let inputs: Vec<_> = (0..=POLICY_INPUT_SLOTS)
        .map(|_| input(&sender, 1, 0, None))
        .collect();
    let policy = policy(&EMPTY);
    let input = witness(&policy, &inputs, &[]);
    assert!(input.slots().is_ok());
    assert!(inputs.len() > POLICY_INPUT_SLOTS);
}

#[tokio::test]
async fn asset_rules_open_mint_records_after_output_owners() {
    let sender = ShieldedKeypair::new_ed25519().unwrap();
    let (owner, recipient) = recipient();
    let inputs = [input(&sender, 10, 0, None)];
    let outputs = [output(recipient.shielded_address().unwrap(), 5)];
    let mint = Member::asset(&Address::new_from_array(MINT)).unwrap();
    let table = RuleTable::builder()
        .rule(Rule::require(Subject::Asset, ListId::Allow))
        .build();
    let pinned = policy(&table);
    let mut registry = MemberRegistryTree::new().unwrap();
    listed(&mut registry, owner, ListSet::single(ListId::Allow));
    let rpc = RegistryRpc::new(registry.clone(), None);
    assert!(matches!(
        witness(&pinned, &inputs, &outputs).build(&rpc, false).await,
        Err(RingError::PolicyRuleUnsatisfied)
    ));
    listed(&mut registry, mint, ListSet::single(ListId::Allow));
    let rpc = RegistryRpc::new(registry, None);
    let built = witness(&pinned, &inputs, &outputs)
        .build(&rpc, false)
        .await
        .unwrap();
    assert!(
        built.subjects[POLICY_INPUT_SLOTS + POLICY_OUTPUT_SLOTS]
            .as_ref()
            .unwrap()
            .present
    );
    assert_eq!(built.subjects.len(), 13);
    let mut foreign = MemberRegistryTree::new().unwrap();
    listed(&mut foreign, mint, ListSet::single(ListId::Allow));
    let pinned = curated(&table, ListSet::single(ListId::Allow));
    let rpc = RegistryRpc::new(MemberRegistryTree::new().unwrap(), Some(foreign));
    let built = witness(&pinned, &inputs, &outputs)
        .build(&rpc, false)
        .await
        .unwrap();
    assert!(
        built.foreign_subjects[POLICY_INPUT_SLOTS + POLICY_OUTPUT_SLOTS]
            .as_ref()
            .unwrap()
            .present
    );
}
