//! A child of `witness`, the plan and the fact resolution are private to it.

use std::sync::Mutex;

use async_trait::async_trait;
use solana_account::Account;
use solana_address::Address;
use zolana_client::{
    rpc::GetShieldedTransactionsByNullifiersResponse, ClientError, Context,
    GetMerkleProofsResponse, GetNonInclusionProofsResponse, MerkleContext, ShieldedTransaction,
    NULLIFIER_TREE_HEIGHT, STATE_TREE_HEIGHT,
};
use zolana_keypair::{ShieldedAddress, ShieldedKeypair};
use zolana_ring_policy::{ListSet, RuleTable, ZERO_NULLIFIER_PK};
use zolana_transaction::Mint;

use super::*;
use crate::{
    tests::support::{
        input, lookup, member, namespace, pinned, ring, tree, tree_account, Accounts, Lineage,
        NullifierRpc,
    },
    RingIdentity,
};

const SECOND_TREE_ID: u16 = 9;

/// The configured address tree, its account id is zero.
fn address_tree() -> PoolTree {
    PoolTree {
        address: tree(),
        id: 0,
    }
}

fn policy(table: &RuleTable) -> PinnedPolicy {
    PinnedPolicy {
        config: pinned(ring(), table, namespace(), address_tree()),
        table: *table,
    }
}

fn velocity_off() -> VelocityProofInput {
    VelocityProofInput::off(RingIdentity {
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
        pinned,
        inputs,
        outputs,
        output_tree_id: 0,
        private_tx_blinding: [0; 32],
        velocity: velocity_off(),
        record: false,
        key_registry: None,
        indexer_config: None,
    }
}

fn recipient() -> (Member, ShieldedAddress) {
    let keypair = ShieldedKeypair::new_ed25519().unwrap();
    let address = keypair.shielded_address().unwrap();
    let member =
        Member::from_bytes(address.signing_pubkey.owner_proof_input_hash().unwrap()).unwrap();
    (member, address)
}

fn output(address: ShieldedAddress, amount: u64) -> SppProofOutputUtxo {
    output_asset(Address::new_from_array([9; 32]), address, amount)
}

fn output_asset(asset: Address, address: ShieldedAddress, amount: u64) -> SppProofOutputUtxo {
    SppProofOutputUtxo::new(Mint::new(asset, 2), amount, address).unwrap()
}

const EMPTY: RuleTable = RuleTable::builder().build();

const TWO_ALLOW: RuleTable = RuleTable::builder()
    .rule(Rule::require(Subject::OutputOwner, ListId::Allow))
    .rule(Rule::require_any(
        Subject::OutputOwner,
        ListSet::of(&[ListId::Allow, ListId::Block]),
    ))
    .build();

const ASSETS: &[[u8; 32]] = &[[9; 32]];

/// An owner guard needs a single unguarded inline asset beside it.
const GUARDED: RuleTable = RuleTable::builder()
    .rule(Rule::require(Subject::OutputOwner, ListId::Allow).above(5))
    .rule(Rule::allow_only_assets())
    .inline_assets(ASSETS)
    .build();

const BLOCK: RuleTable = RuleTable::builder()
    .rule(Rule::forbid(Subject::OutputOwner, ListId::Block))
    .build();

/// An approval overrides a block.
const MIXED: RuleTable = RuleTable::builder()
    .rule(Rule::any_of(
        Subject::OutputOwner,
        ListSet::single(ListId::Approval),
        ListSet::single(ListId::Block),
    ))
    .rule(Rule::allow_only_assets())
    .inline_assets(ASSETS)
    .build();

#[test]
fn dummy_output_opening_preserves_its_tree_and_blinding() {
    let output = SppProofOutputUtxo {
        blinding: [0x5a; 32],
        ..SppProofOutputUtxo::default()
    };
    let opening = output_opening(&output, 27).unwrap();
    assert_eq!(opening.domain, right_align(&DUMMY_DOMAIN.to_be_bytes()));
    assert_eq!(opening.tree_id, tree_id_field(27));
    assert_eq!(opening.blinding, output.blinding);
    for field in [
        opening.owner_pk_hash,
        opening.nullifier_pk,
        opening.asset,
        opening.amount,
        opening.data_hash,
        opening.ring_data_hash,
        opening.ring_program_id,
    ] {
        assert_eq!(field, [0; 32]);
    }
}

#[test]
fn a_dummy_input_opens_only_its_domain() {
    let opening = input_opening(&SppProofInputUtxo::dummy(4).unwrap()).unwrap();
    assert_eq!(opening.domain, right_align(&DUMMY_DOMAIN.to_be_bytes()));
    assert_eq!(opening.tree_id, [0; 32]);
    let owner = ShieldedKeypair::new_ed25519().unwrap();
    let real = input(&owner, 3, 4, None);
    let opening = input_opening(&real).unwrap();
    assert_eq!(opening.domain, right_align(&UTXO_DOMAIN.to_be_bytes()));
    assert_eq!(opening.tree_id, tree_id_field(4));
    assert_eq!(opening.amount, right_align(&3u64.to_be_bytes()));
    // An absent ring is the zero field element.
    assert_eq!(opening.ring_program_id, [0; 32]);
}

#[test]
fn only_the_namespace_owned_record_skips_its_key_opening() {
    let pinned = policy(&EMPTY);
    let (_, member) = recipient();
    let record = ShieldedAddress::for_pda(
        &ring().namespace_pda(),
        ZERO_NULLIFIER_PK,
        member.viewing_pubkey,
    );
    let zero_key = ShieldedAddress {
        nullifier_pubkey: ZERO_NULLIFIER_PK,
        ..member
    };
    let outputs = [
        output(record, 0),
        output(zero_key, 1),
        SppProofOutputUtxo::default(),
    ];
    let refused = OutputKey {
        owner_pk_hash: member.signing_pubkey.owner_proof_input_hash().unwrap(),
        nullifier_pk: ZERO_NULLIFIER_PK,
    };
    assert_eq!(
        witness(&pinned, &[], &outputs).output_keys().unwrap(),
        vec![None, Some(refused), None]
    );
}

#[test]
fn list_backed_asset_rules_name_each_live_output_asset() {
    let (_, address) = recipient();
    let asset = Address::new_from_array([9; 32]);
    let outputs = [
        output_asset(asset, address, 1),
        SppProofOutputUtxo::default(),
    ];
    let pinned = policy(&EMPTY);
    assert_eq!(
        witness(&pinned, &[], &outputs)
            .subjects(&Rule::require(Subject::Asset, ListId::Allow))
            .unwrap(),
        vec![Member::asset(&asset).unwrap()]
    );
}

#[test]
fn a_guarded_rule_exempts_a_recipient_only_below_the_aggregated_threshold() {
    let (member, address) = recipient();
    let pinned = policy(&EMPTY);
    // Two outputs to the same recipient sum to 2500, over the 2000 threshold.
    let outputs = [output(address, 1000), output(address, 1500)];
    let guarded = Rule::require(Subject::OutputOwner, ListId::Allow).above(2000);
    let over = witness(&pinned, &[], &outputs);
    assert!(!over.guard_exempts(&guarded, &member).unwrap());
    let unguarded = Rule::require(Subject::OutputOwner, ListId::Allow);
    assert!(!over.guard_exempts(&unguarded, &member).unwrap());
    let one = [output(address, 1000)];
    assert!(witness(&pinned, &[], &one)
        .guard_exempts(&guarded, &member)
        .unwrap());
}

#[test]
fn the_guard_sums_exactly_past_the_u64_range() {
    let (member, address) = recipient();
    let (other_member, other_address) = recipient();
    let pinned = policy(&EMPTY);
    let guarded = Rule::require(Subject::OutputOwner, ListId::Allow).above(u64::MAX);
    let one_recipient = [output(address, u64::MAX), output(address, 1)];
    assert!(!witness(&pinned, &[], &one_recipient)
        .guard_exempts(&guarded, &member)
        .unwrap());
    let two_recipients = [output(address, u64::MAX), output(other_address, 1)];
    let split = witness(&pinned, &[], &two_recipients);
    assert!(split.guard_exempts(&guarded, &member).unwrap());
    assert!(split.guard_exempts(&guarded, &other_member).unwrap());
}

#[test]
fn per_asset_guard_uses_each_mint_limit_and_rejects_an_unknown_mint() {
    let (owner, address) = recipient();
    let first = Address::new_from_array([8; 32]);
    let second = Address::new_from_array([9; 32]);
    let members = [
        *Member::asset(&first).unwrap().as_bytes(),
        *Member::asset(&second).unwrap().as_bytes(),
    ];
    let table = RuleTable::builder()
        .rule(Rule::require(Subject::OutputOwner, ListId::Allow).above_by_asset())
        .inline_assets(&members)
        .inline_limits(&[10, 20])
        .build();
    let pinned = policy(&table);
    let rule = &table.rules()[0];
    let below = [
        output_asset(first, address, 4),
        output_asset(first, address, 6),
        output_asset(second, address, 20),
    ];
    assert!(witness(&pinned, &[], &below)
        .guard_exempts(rule, &owner)
        .unwrap());
    let above = [output_asset(first, address, 11)];
    assert!(!witness(&pinned, &[], &above)
        .guard_exempts(rule, &owner)
        .unwrap());
    let unknown = [output_asset(Address::new_from_array([7; 32]), address, 1)];
    assert!(matches!(
        witness(&pinned, &[], &unknown).guard_exempts(rule, &owner),
        Err(RingError::PolicyAssetUnsupported)
    ));
}

#[test]
fn a_sender_guard_never_exempts() {
    let (member, _) = recipient();
    let pinned = policy(&EMPTY);
    let guarded = Rule::require(Subject::Sender, ListId::Allow).above(u64::MAX);
    assert!(!witness(&pinned, &[], &[])
        .guard_exempts(&guarded, &member)
        .unwrap());
}

#[test]
fn a_record_ends_the_active_inputs_and_leaves_the_rules() {
    let owner = ShieldedKeypair::new_ed25519().unwrap();
    let inputs = [
        input(&owner, 1, 0, None),
        input(&owner, 1, 9, None),
        SppProofInputUtxo::dummy(9).unwrap(),
        SppProofInputUtxo::dummy(9).unwrap(),
    ];
    let nullifiers = |inputs: &[SppProofInputUtxo]| {
        inputs
            .iter()
            .map(SppProofInputUtxo::nullifier)
            .collect::<Vec<_>>()
    };
    let pinned = policy(&EMPTY);
    let windowed = WitnessInput {
        record: true,
        ..witness(&pinned, &inputs, &[])
    };
    assert_eq!(windowed.active_input_count(), 2);
    assert_eq!(nullifiers(windowed.rule_inputs()), nullifiers(&inputs[..1]));
    let unwindowed = witness(&pinned, &inputs, &[]);
    assert_eq!(unwindowed.active_input_count(), inputs.len());
    assert_eq!(nullifiers(unwindowed.rule_inputs()), nullifiers(&inputs));
}

#[test]
fn a_record_leaves_the_rule_outputs_before_the_compact_padding() {
    let (_, address) = recipient();
    let outputs = [
        output(address, 1),
        output(address, 0),
        SppProofOutputUtxo {
            compact: true,
            ..SppProofOutputUtxo::default()
        },
    ];
    let pinned = policy(&EMPTY);
    let windowed = WitnessInput {
        record: true,
        ..witness(&pinned, &[], &outputs)
    };
    assert_eq!(windowed.active_output_count(), 2);
    assert_eq!(windowed.rule_outputs().len(), 1);
    assert_eq!(witness(&pinned, &[], &outputs).rule_outputs().len(), 2);
}

#[test]
fn a_transfer_past_the_policy_slots_is_refused() {
    let owner = ShieldedKeypair::new_ed25519().unwrap();
    let inputs: Vec<_> = (0..=POLICY_INPUT_SLOTS)
        .map(|_| input(&owner, 1, 0, None))
        .collect();
    let pinned = policy(&EMPTY);
    assert!(matches!(
        witness(&pinned, &inputs, &[]).plan(),
        Err(RingError::PolicyShapeUnsupported)
    ));
}

type ProofTamper = fn(&mut MerkleProof);
type AbsenceTamper = fn(&mut NonInclusionProof);

#[derive(Default)]
struct Calls {
    merkle: Vec<Vec<[u8; 32]>>,
    non_inclusion: Vec<Vec<[u8; 32]>>,
    /// The tree of every merkle then non-inclusion request, in call order.
    trees: Vec<Address>,
    accounts: usize,
}

/// Serves tree accounts, lineages and proofs at the given roots.
struct ProofRpc {
    lineages: NullifierRpc,
    accounts: Accounts,
    state_roots: Vec<([u8; 32], u16)>,
    nullifier_roots: Vec<([u8; 32], u16)>,
    state_tamper: Option<ProofTamper>,
    absence_tamper: Option<AbsenceTamper>,
    calls: Mutex<Calls>,
}

impl ProofRpc {
    async fn new(spenders: Vec<ShieldedTransaction>) -> Self {
        let roots = current(address_tree()).await;
        Self {
            lineages: NullifierRpc::new(spenders),
            accounts: Accounts::default().with(tree(), tree_account(address_tree())),
            state_roots: vec![(roots.state, roots.state_index)],
            nullifier_roots: vec![(roots.nullifier, roots.nullifier_index)],
            state_tamper: None,
            absence_tamper: None,
            calls: Mutex::new(Calls::default()),
        }
    }

    fn with_tree(mut self, id: u16) -> Self {
        let tree = PoolTree::from_id(id);
        self.accounts = self.accounts.with(tree.address, tree_account(tree));
        self
    }

    fn root(roots: &[([u8; 32], u16)], position: usize) -> ([u8; 32], u16) {
        roots[position.min(roots.len() - 1)]
    }

    fn calls(&self) -> std::sync::MutexGuard<'_, Calls> {
        self.calls.lock().unwrap()
    }
}

async fn current(tree: PoolTree) -> TransactRoots {
    let rpc = Accounts::default().with(tree.address, tree_account(tree));
    read_tree(&rpc, tree.address).await.unwrap().roots
}

#[async_trait]
impl AsyncRpc for ProofRpc {
    async fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
        self.calls().accounts += 1;
        self.accounts.get_account(address).await
    }

    async fn get_shielded_transactions_by_nullifiers(
        &self,
        nullifiers: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        _limit: Option<u32>,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByNullifiersResponse, ClientError> {
        Ok(self.lineages.page(nullifiers, cursor))
    }

    async fn get_merkle_proofs(
        &self,
        tree_account: Address,
        leaves: Vec<[u8; 32]>,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetMerkleProofsResponse, ClientError> {
        let mut calls = self.calls();
        calls.merkle.push(leaves.clone());
        calls.trees.push(tree_account);
        drop(calls);
        let proofs = leaves
            .iter()
            .enumerate()
            .map(|(position, leaf)| {
                let (root, root_index) = Self::root(&self.state_roots, position);
                let mut proof = MerkleProof {
                    leaf: *leaf,
                    merkle_context: MerkleContext {
                        tree_type: 0,
                        tree: tree_account,
                    },
                    path: vec![[position as u8; 32]; STATE_TREE_HEIGHT],
                    leaf_index: position as u64,
                    root,
                    root_seq: 0,
                    root_index,
                };
                if let Some(tamper) = self.state_tamper {
                    tamper(&mut proof);
                }
                proof
            })
            .collect();
        Ok(GetMerkleProofsResponse {
            context: Context {
                block_time: 0,
                slot: 0,
            },
            proofs,
        })
    }

    async fn get_non_inclusion_proofs(
        &self,
        tree_account: Address,
        leaves: Vec<[u8; 32]>,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetNonInclusionProofsResponse, ClientError> {
        let mut calls = self.calls();
        calls.non_inclusion.push(leaves.clone());
        calls.trees.push(tree_account);
        drop(calls);
        let proofs = leaves
            .iter()
            .enumerate()
            .map(|(position, leaf)| {
                let (root, root_index) = Self::root(&self.nullifier_roots, position);
                let mut proof = NonInclusionProof {
                    leaf: *leaf,
                    merkle_context: MerkleContext {
                        tree_type: 1,
                        tree: tree_account,
                    },
                    path: vec![[0; 32]; NULLIFIER_TREE_HEIGHT],
                    low_element: [position as u8; 32],
                    low_element_index: position as u64,
                    high_element: [0xff; 32],
                    high_element_index: position as u64 + 1,
                    root,
                    root_seq: 0,
                    root_index,
                };
                if let Some(tamper) = self.absence_tamper {
                    tamper(&mut proof);
                }
                proof
            })
            .collect();
        Ok(GetNonInclusionProofsResponse {
            context: Context {
                block_time: 0,
                slot: 0,
            },
            proofs,
        })
    }
}

fn enabled(witness: &CustomRingWitness) -> Vec<&RuleAnswer> {
    witness
        .answers
        .iter()
        .filter(|answer| answer.enabled)
        .collect()
}

#[tokio::test]
async fn two_outputs_to_one_recipient_under_two_rules_consult_the_pair_once() {
    let (member, address) = recipient();
    let lineage = Lineage::new(lookup(ListId::Allow, member), &[EntryState::Active]);
    let rpc = ProofRpc::new(lineage.spenders()).await;
    let outputs = [output(address, 10), output(address, 20)];
    let pinned = policy(&TWO_ALLOW);
    let built = witness(&pinned, &[], &outputs)
        .build(&rpc, false)
        .await
        .unwrap();

    let live = lineage.live().unwrap();
    {
        let calls = rpc.calls();
        assert_eq!(calls.merkle, vec![vec![live.utxo_hash]]);
        assert_eq!(calls.non_inclusion, vec![vec![live.nullifier]]);
        assert_eq!(calls.accounts, 1);
    }
    let requests = rpc.lineages.requests();
    // The claim round asks for both group addresses, the Allow lineage one more round.
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].len(), 2);
    assert_eq!(requests[1], vec![live.nullifier]);
    let answers = enabled(&built);
    assert_eq!(answers.len(), 1);
    assert_eq!(answers[0].member, *member.as_bytes());
    assert_eq!(answers[0].absent_branch, 2);
    assert_eq!(answers[0].state_path.len(), STATE_TREE_HEIGHT);
    assert_eq!(built.answers.len(), ANSWER_SLOTS);
    assert_eq!(built.trees[0].roots, current(address_tree()).await);
    assert_eq!(built.revocation_targets[0], live.nullifier);
}

#[tokio::test]
async fn a_guard_exempt_subject_triggers_no_request() {
    let (_, address) = recipient();
    let rpc = ProofRpc::new(Vec::new()).await;
    let outputs = [output(address, 1)];
    let pinned = policy(&GUARDED);
    let built = witness(&pinned, &[], &outputs)
        .build(&rpc, false)
        .await
        .unwrap();
    assert!(rpc.lineages.requests().is_empty());
    let calls = rpc.calls();
    assert!(calls.merkle.is_empty() && calls.non_inclusion.is_empty());
    assert!(built.answers.iter().all(|answer| !answer.enabled));
}

#[tokio::test]
async fn a_missing_entry_refuses_the_transfer_before_any_proof_call() {
    let (_, address) = recipient();
    let rpc = ProofRpc::new(Vec::new()).await;
    let outputs = [output(address, 1)];
    let pinned = policy(&TWO_ALLOW);
    assert!(matches!(
        witness(&pinned, &[], &outputs).build(&rpc, false).await,
        Err(RingError::PolicyRuleUnsatisfied)
    ));
    let calls = rpc.calls();
    assert!(calls.merkle.is_empty() && calls.non_inclusion.is_empty());
    assert_eq!(calls.accounts, 0);
}

#[tokio::test]
async fn responses_with_two_roots_are_refused() {
    let (member, address) = recipient();
    let (other_member, other_address) = recipient();
    let first = Lineage::new(lookup(ListId::Allow, member), &[EntryState::Active]);
    let second = Lineage::new(lookup(ListId::Allow, other_member), &[EntryState::Active]);
    let mut spenders = first.spenders();
    spenders.extend(second.spenders());
    let mut rpc = ProofRpc::new(spenders).await;
    rpc.state_roots.push(([5; 32], 5));
    let outputs = [output(address, 1), output(other_address, 1)];
    let pinned = policy(&TWO_ALLOW);
    assert!(matches!(
        witness(&pinned, &[], &outputs).build(&rpc, false).await,
        Err(RingError::PolicyRootMismatch)
    ));
}

#[tokio::test]
async fn absence_proofs_at_an_older_live_root_keep_their_own_root_and_index() {
    let (_, address) = recipient();
    let mut rpc = ProofRpc::new(Vec::new()).await;
    rpc.nullifier_roots = vec![([0x33; 32], 2)];
    let outputs = [output(address, 1)];
    let pinned = policy(&BLOCK);
    let built = witness(&pinned, &[], &outputs)
        .build(&rpc, false)
        .await
        .unwrap();
    assert_eq!(built.trees[0].roots.nullifier, [0x33; 32]);
    assert_eq!(built.trees[0].roots.nullifier_index, 2);
    assert_eq!(built.reads().trees[0].context.nullifier_tree_root_index, 2);
}

#[tokio::test]
async fn unclaimed_answers_take_the_state_root_from_the_tree_account() {
    let (member, address) = recipient();
    let rpc = ProofRpc::new(Vec::new()).await;
    let outputs = [output(address, 1)];
    let pinned = policy(&BLOCK);
    let built = witness(&pinned, &[], &outputs)
        .build(&rpc, false)
        .await
        .unwrap();
    assert_eq!(built.trees[0].roots, current(address_tree()).await);
    let calls = rpc.calls();
    assert!(calls.merkle.is_empty());
    assert_eq!(
        calls.non_inclusion,
        vec![vec![lookup(ListId::Block, member).address().unwrap()]]
    );
    assert_eq!(calls.accounts, 1);
    assert_eq!(built.answers[0].absent_branch, 1);
    assert_eq!(built.answers[0].mode, Mode::Absent as u8);
}

#[tokio::test]
async fn a_table_without_answers_reads_both_roots_from_the_tree_account() {
    let rpc = ProofRpc::new(Vec::new()).await;
    let pinned = policy(&EMPTY);
    let built = witness(&pinned, &[], &[]).build(&rpc, false).await.unwrap();
    assert_eq!(built.trees.len(), 1);
    assert_eq!(built.trees[0].roots, current(address_tree()).await);
    let calls = rpc.calls();
    assert!(calls.merkle.is_empty() && calls.non_inclusion.is_empty());
    assert_eq!(calls.accounts, 1);
}

#[tokio::test]
async fn a_blocked_member_passes_through_its_approval() {
    let (member, address) = recipient();
    let approved = Lineage::new(lookup(ListId::Approval, member), &[EntryState::Active]);
    let blocked = Lineage::new(lookup(ListId::Block, member), &[EntryState::Active]);
    let mut spenders = approved.spenders();
    spenders.extend(blocked.spenders());
    let rpc = ProofRpc::new(spenders).await;
    let outputs = [output(address, 1)];
    let pinned = policy(&MIXED);
    let built = witness(&pinned, &[], &outputs)
        .build(&rpc, false)
        .await
        .unwrap();
    let answers = enabled(&built);
    assert_eq!(answers.len(), 1);
    assert_eq!(answers[0].list_id, ListId::Approval as u8);
    assert_eq!(answers[0].mode, Mode::Present as u8);
    assert_eq!(answers[0].absent_branch, 2);
    assert_eq!(answers[0].state, EntryState::Active as u8);
    let live = approved.live().unwrap();
    let calls = rpc.calls();
    assert_eq!(calls.merkle, vec![vec![live.utxo_hash]]);
    assert_eq!(calls.non_inclusion, vec![vec![live.nullifier]]);
    // Both alternatives are claimed in one round.
    assert_eq!(rpc.lineages.requests()[0].len(), 2);
}

#[tokio::test]
async fn an_unlisted_member_passes_through_the_absent_alternative() {
    let (member, address) = recipient();
    let rpc = ProofRpc::new(Vec::new()).await;
    let outputs = [output(address, 1)];
    let pinned = policy(&MIXED);
    let built = witness(&pinned, &[], &outputs)
        .build(&rpc, false)
        .await
        .unwrap();
    let answers = enabled(&built);
    assert_eq!(answers.len(), 1);
    assert_eq!(answers[0].list_id, ListId::Block as u8);
    assert_eq!(answers[0].mode, Mode::Absent as u8);
    assert_eq!(answers[0].absent_branch, 1);
    let calls = rpc.calls();
    assert!(calls.merkle.is_empty());
    assert_eq!(
        calls.non_inclusion,
        vec![vec![lookup(ListId::Block, member).address().unwrap()]]
    );
}

#[tokio::test]
async fn a_blocked_member_without_approval_is_refused() {
    let (member, address) = recipient();
    let blocked = Lineage::new(lookup(ListId::Block, member), &[EntryState::Active]);
    let rpc = ProofRpc::new(blocked.spenders()).await;
    let outputs = [output(address, 1)];
    let pinned = policy(&MIXED);
    assert!(matches!(
        witness(&pinned, &[], &outputs).build(&rpc, false).await,
        Err(RingError::PolicyRuleUnsatisfied)
    ));
    let calls = rpc.calls();
    assert!(calls.merkle.is_empty() && calls.non_inclusion.is_empty());
}

#[tokio::test]
async fn the_request_carries_the_account_rows_verbatim() {
    let (_, address) = recipient();
    let rpc = ProofRpc::new(Vec::new()).await;
    let outputs = [output(address, 1)];
    let pinned = policy(&MIXED);
    let built = witness(&pinned, &[], &outputs)
        .build(&rpc, false)
        .await
        .unwrap();
    let rules = &pinned.config.rules;
    assert_eq!(built.rules, rules.rules);
    assert_eq!(built.policy_len, rules.rule_count);
    assert_eq!(built.inline_assets, rules.inline_assets);
    assert_eq!(
        built.inline_limits,
        rules.inline_limits.map(u64::from_be_bytes)
    );
    assert_eq!(built.inline_count, rules.inline_count);
    assert_eq!(built.rules[0][19], ListSet::single(ListId::Block).bits());
    assert_eq!(built.inline_assets[0], ASSETS[0]);
    let mapped: Vec<u8> = built
        .sources
        .iter()
        .map(|slot| slot.list_id)
        .filter(|list_id| *list_id != 0)
        .collect();
    assert_eq!(mapped, vec![ListId::Block as u8, ListId::Approval as u8]);
    assert_eq!(built.address_tree_id, 0);
    assert_eq!(built.n_out, 1);
}

#[tokio::test]
async fn an_indexed_build_leaves_every_proof_to_the_prover() {
    let (member, address) = recipient();
    let lineage = Lineage::new(lookup(ListId::Allow, member), &[EntryState::Active]);
    let rpc = ProofRpc::new(lineage.spenders()).await;
    let outputs = [output(address, 1)];
    let pinned = policy(&TWO_ALLOW);
    let built = witness(&pinned, &[], &outputs)
        .build(&rpc, true)
        .await
        .unwrap();
    {
        let calls = rpc.calls();
        assert!(calls.merkle.is_empty() && calls.non_inclusion.is_empty());
        assert_eq!(calls.accounts, 1);
    }
    let live = lineage.live().unwrap();
    let indexed = built.indexed.as_ref().unwrap();
    assert_eq!(indexed.len(), ANSWER_SLOTS);
    assert_eq!(indexed[0].commitment, Some(live.utxo_hash));
    assert_eq!(indexed[0].nullifier, Some(live.nullifier));
    assert_eq!(indexed[1].nullifier, None);
    let answer = &built.answers[0];
    assert!(answer.enabled);
    assert_eq!(answer.low, [0; 32]);
    assert_eq!(answer.state_path, vec![[0; 32]; STATE_TREE_HEIGHT]);
}

fn live_in(tree_id: u16, byte: u8) -> EntryFact {
    let lineage = Lineage::across(
        lookup(ListId::Block, member(byte)),
        &[EntryState::Cleared],
        &[tree_id],
    );
    EntryFact::Live(lineage.live().unwrap())
}

/// One absent demand per fact, every fact under its own member.
fn trees_of(facts: &[EntryFact]) -> Result<(Vec<u8>, Vec<PoolTree>), RingError> {
    let lookups: Vec<EntryLookup> = (0..facts.len())
        .map(|index| lookup(ListId::Block, member(index as u8 + 1)))
        .collect();
    let demands: Vec<Demand> = lookups
        .iter()
        .enumerate()
        .map(|(index, lookup)| Demand {
            member: lookup.member,
            alternatives: vec![(index, Mode::Absent)],
        })
        .collect();
    let (answers, trees) = resolve(&lookups, &demands, facts, address_tree())?;
    Ok((answers.iter().map(|answer| answer.slot).collect(), trees))
}

#[test]
fn fact_trees_dedupe_and_bind_the_address_tree_first() {
    let unclaimed = EntryFact::Unclaimed { address: [1; 32] };
    let facts = [live_in(9, 1), unclaimed, live_in(9, 2), live_in(0, 3)];
    let (slots, trees) = trees_of(&facts).unwrap();
    assert_eq!(
        trees,
        vec![address_tree(), PoolTree::from_id(SECOND_TREE_ID)]
    );
    assert_eq!(slots, vec![1, 0, 1, 0]);
    let (_, live_only) = trees_of(&[live_in(9, 1)]).unwrap();
    assert_eq!(live_only, vec![PoolTree::from_id(SECOND_TREE_ID)]);
    let (_, no_facts) = trees_of(&[]).unwrap();
    assert_eq!(no_facts, vec![address_tree()]);
}

#[test]
fn facts_in_more_than_five_trees_are_refused() {
    let facts: Vec<EntryFact> = (1..=6).map(|id| live_in(id, id as u8)).collect();
    assert!(matches!(
        trees_of(&facts),
        Err(RingError::TooManyPolicyTrees { count: 6 })
    ));
}

#[test]
fn a_demand_no_fact_satisfies_is_refused() {
    let active = Lineage::new(lookup(ListId::Block, member(1)), &[EntryState::Active]);
    assert!(matches!(
        trees_of(&[EntryFact::Live(active.live().unwrap())]),
        Err(RingError::PolicyRuleUnsatisfied)
    ));
}

/// A cleared entry that moved to a second tree answers there, an unclaimed address in the address tree.
#[tokio::test]
async fn facts_in_two_trees_select_their_own_slots() {
    let (moved, moved_address) = recipient();
    let (_, unclaimed_address) = recipient();
    let lineage = Lineage::across(
        lookup(ListId::Block, moved),
        &[EntryState::Active, EntryState::Cleared],
        &[0, SECOND_TREE_ID],
    );
    let rpc = ProofRpc::new(lineage.spenders())
        .await
        .with_tree(SECOND_TREE_ID);
    let outputs = [output(moved_address, 1), output(unclaimed_address, 1)];
    let pinned = policy(&BLOCK);
    let built = witness(&pinned, &[], &outputs)
        .build(&rpc, false)
        .await
        .unwrap();

    let second = PoolTree::from_id(SECOND_TREE_ID);
    assert_eq!(
        built.trees.iter().map(|tree| tree.tree).collect::<Vec<_>>(),
        vec![address_tree(), second]
    );
    let answers = enabled(&built);
    assert_eq!(answers[0].tree_slot, 1);
    assert_eq!(answers[0].absent_branch, 2);
    assert_eq!(answers[1].tree_slot, 0);
    assert_eq!(answers[1].absent_branch, 1);
    assert_eq!(built.revocation_tree_indexes[..2], [1, 0]);
    let live = lineage.live().unwrap();
    assert_eq!(built.revocation_targets[0], live.nullifier);
    let calls = rpc.calls();
    assert_eq!(calls.merkle, vec![vec![live.utxo_hash]]);
    // The trees fetch concurrently, each asks for its own proofs.
    let mut asked = calls.trees.clone();
    asked.sort();
    let mut expected = vec![tree(), second.address, second.address];
    expected.sort();
    assert_eq!(asked, expected);
    assert_eq!(calls.accounts, 2);
    assert_eq!(built.reads().trees[1].tree, second.address);
}

#[tokio::test]
async fn a_tree_account_under_another_id_is_refused() {
    let (_, address) = recipient();
    let mut rpc = ProofRpc::new(Vec::new()).await;
    rpc.accounts = Accounts::default().with(
        tree(),
        tree_account(PoolTree {
            address: tree(),
            id: 3,
        }),
    );
    let outputs = [output(address, 1)];
    let pinned = policy(&BLOCK);
    assert!(matches!(
        witness(&pinned, &[], &outputs).build(&rpc, false).await,
        Err(RingError::TreeIdMismatch {
            expected: 3,
            found: 0,
            ..
        })
    ));
}

#[tokio::test]
async fn fact_proofs_for_another_leaf_tree_or_height_are_refused() {
    let (member, address) = recipient();
    let lineage = Lineage::new(lookup(ListId::Allow, member), &[EntryState::Active]);
    let outputs = [output(address, 1)];
    let pinned = policy(&TWO_ALLOW);
    let build = |state_tamper: Option<ProofTamper>, absence_tamper: Option<AbsenceTamper>| {
        let spenders = lineage.spenders();
        let pinned = &pinned;
        let outputs = &outputs;
        async move {
            let mut rpc = ProofRpc::new(spenders).await;
            rpc.state_tamper = state_tamper;
            rpc.absence_tamper = absence_tamper;
            witness(pinned, &[], outputs).build(&rpc, false).await
        }
    };
    build(None, None).await.unwrap();
    let state_cases: [(ProofTamper, ClientError); 3] = [
        (
            |proof| proof.leaf[0] ^= 1,
            ClientError::StateProofLeafMismatch { index: 0 },
        ),
        (
            |proof| proof.merkle_context.tree = pda_tree(8),
            ClientError::StateProofTreeMismatch { index: 0 },
        ),
        (
            |proof| {
                proof.path.pop();
            },
            ClientError::ProofPathLength {
                got: STATE_TREE_HEIGHT - 1,
                expected: STATE_TREE_HEIGHT,
            },
        ),
    ];
    for (tamper, expected) in state_cases {
        let error = build(Some(tamper), None).await.err().unwrap();
        assert!(
            matches!(&error, RingError::Client(found) if found.to_string() == expected.to_string()),
            "{error:?}"
        );
    }
    let absence_cases: [(AbsenceTamper, ClientError); 3] = [
        (
            |proof| proof.leaf[0] ^= 1,
            ClientError::NullifierProofLeafMismatch { index: 0 },
        ),
        (
            |proof| proof.merkle_context.tree = pda_tree(8),
            ClientError::NullifierProofTreeMismatch { index: 0 },
        ),
        (
            |proof| {
                proof.path.pop();
            },
            ClientError::ProofPathLength {
                got: NULLIFIER_TREE_HEIGHT - 1,
                expected: NULLIFIER_TREE_HEIGHT,
            },
        ),
    ];
    for (tamper, expected) in absence_cases {
        let error = build(None, Some(tamper)).await.err().unwrap();
        assert!(
            matches!(&error, RingError::Client(found) if found.to_string() == expected.to_string()),
            "{error:?}"
        );
    }
}

fn pda_tree(id: u16) -> Address {
    zolana_interface::pda::tree(id)
}
