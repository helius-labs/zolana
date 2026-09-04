//! Shared mollusk fixtures, each test binary uses a subset.
#![allow(dead_code)]

use bytemuck::Zeroable;
use custom_ring_interface::{
    tag, CreateConfigIxData, CreateEntryIxData, PolicyConfig, PolicyTableIxData, ReadAccessRecord,
    ReaderKeyBytes, RingProgramConfig, SetPausedIxData, SourceSlot, SourceSpec, UpdateEntryIxData,
    CONFIG_PDA_SEED, N_SOURCE_SLOTS, POLICY_CONFIG, POLICY_CONFIG_PDA_SEED, READER_KEY_ED25519,
    READER_KEY_P256, READ_ACCESS_RECORD, READ_ACCESS_RECORD_PDA_SEED, RING_PROGRAM_CONFIG,
};
use mollusk_svm::{
    result::{InstructionResult, ProgramResult},
    Mollusk,
};
use pinocchio::Address;
use solana_account::Account;
use solana_instruction::{error::InstructionError, AccountMeta, Instruction};
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;
use zolana_interface::{
    instruction::instruction_data::transact::TransactProof,
    state::{default_tree_fees, discriminator::RING_CONFIG, nullifier_tree_params, RingConfig},
    BPF_LOADER_UPGRADEABLE_PUBKEY, RING_AUTH_PDA_SEED, SHIELDED_POOL_PROGRAM_ID,
};
use zolana_ring_policy::{
    ListId, ListNamespace, Rule, RuleTable, SourceMap, SourceOwner, Subject, MAX_INLINE_ASSETS,
    MAX_SOURCES, NAMESPACE_PDA_SEED,
};
use zolana_tree::TreeAccount;

/// A workspace deploy dir, filled by `just build-programs`.
fn sbf_dir(relative: &str) -> String {
    let mut dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        let candidate = dir.join(relative);
        if candidate.is_dir() {
            return candidate.to_string_lossy().into_owned();
        }
        assert!(
            dir.pop(),
            "no {relative} above {}",
            env!("CARGO_MANIFEST_DIR")
        );
    }
}

pub struct Slot {
    pub label: &'static str,
    pub meta: AccountMeta,
    pub account: Account,
}

pub struct Fixture {
    instruction: Instruction,
    accounts: Vec<(Pubkey, Account)>,
    labels: Vec<&'static str>,
}

impl Fixture {
    pub fn new(data: Vec<u8>, slots: Vec<Slot>) -> Self {
        let mut fixture = Self {
            instruction: Instruction {
                program_id: program_id(),
                accounts: Vec::with_capacity(slots.len()),
                data,
            },
            accounts: Vec::with_capacity(slots.len()),
            labels: Vec::with_capacity(slots.len()),
        };
        for slot in slots {
            fixture.push(slot);
        }
        fixture
    }

    pub fn push(&mut self, slot: Slot) {
        self.accounts.push((slot.meta.pubkey, slot.account));
        self.instruction.accounts.push(slot.meta);
        self.labels.push(slot.label);
    }

    /// Appends to the instruction data, negatives use it for trailing bytes.
    pub fn push_data(&mut self, byte: u8) {
        self.instruction.data.push(byte);
    }

    pub fn truncate(&mut self, len: usize) {
        self.instruction.accounts.truncate(len);
        self.labels.truncate(len);
    }

    pub fn substitute(&mut self, label: &str, replacement: Pubkey) {
        // Point the selected meta at a registered substitute account.
        self.meta_mut(label).pubkey = replacement;
        if !self.accounts.iter().any(|(key, _)| key == &replacement) {
            self.accounts.push((replacement, account(1_000_000_000)));
        }
    }

    pub fn unsign(&mut self, label: &str) {
        self.meta_mut(label).is_signer = false;
    }

    pub fn set_writable(&mut self, label: &str, writable: bool) {
        self.meta_mut(label).is_writable = writable;
    }

    pub fn set_account(&mut self, label: &str, account: Account) {
        let key = self.meta_mut(label).pubkey;
        let entry = self
            .accounts
            .iter_mut()
            .find(|(candidate, _)| candidate == &key)
            .unwrap_or_else(|| panic!("no account registered for slot {label}"));
        entry.1 = account;
    }

    pub fn data_mut(&mut self) -> &mut Vec<u8> {
        &mut self.instruction.data
    }

    pub fn instruction(&self) -> &Instruction {
        &self.instruction
    }

    pub fn accounts(&self) -> &[(Pubkey, Account)] {
        &self.accounts
    }

    #[track_caller]
    pub fn expect_err(&self, mollusk: &Mollusk, error: ProgramError) {
        zolana_test_utils::mollusk::expect_err_exact(
            mollusk,
            &self.instruction,
            &self.accounts,
            error,
        );
    }

    /// SPP is absent from mollusk, a run that clears every ring check dies in
    /// the CPI.
    #[track_caller]
    pub fn expect_spp_cpi(&self, mollusk: &Mollusk) -> u64 {
        let result = mollusk.process_instruction(&self.instruction, &self.accounts);
        assert_eq!(
            result.program_result,
            ProgramResult::UnknownError(InstructionError::UnsupportedProgramId),
            "expected the SPP CPI"
        );
        result.compute_units_consumed
    }

    fn meta_mut(&mut self, label: &str) -> &mut AccountMeta {
        let index = self
            .labels
            .iter()
            .position(|candidate| *candidate == label)
            .unwrap_or_else(|| panic!("unknown slot {label}"));
        self.instruction
            .accounts
            .get_mut(index)
            .unwrap_or_else(|| panic!("slot {label} has no meta"))
    }
}

pub fn setup_mollusk() -> (Mollusk, Pubkey) {
    let (mut mollusk, program_id) = zolana_test_utils::mollusk::mollusk_with_program(
        &sbf_dir("target/deploy"),
        *program_id().as_array(),
        "custom_ring_program",
    );
    mollusk.compute_budget.compute_unit_limit = 1_400_000;
    (mollusk, program_id)
}

#[track_caller]
fn green(mollusk: &Mollusk, fixture: &Fixture) -> InstructionResult {
    let result = mollusk.process_instruction(fixture.instruction(), fixture.accounts());
    assert_eq!(result.program_result, ProgramResult::Success);
    result
}

#[track_caller]
pub fn consumed(mollusk: &Mollusk, fixture: &Fixture) -> u64 {
    green(mollusk, fixture).compute_units_consumed
}

/// The policy config a green run wrote.
#[track_caller]
pub fn stored_policy_config(mollusk: &Mollusk, fixture: &Fixture) -> PolicyConfig {
    let written = green(mollusk, fixture)
        .resulting_accounts
        .into_iter()
        .find(|(key, _)| key == &policy_config_pda().0)
        .map(|(_, account)| account)
        .expect("policy config account");
    assert_eq!(written.owner, program_id());
    *bytemuck::from_bytes(&written.data)
}

/// Arbitrary, the shared binary serves any deployment address.
pub fn program_id() -> Pubkey {
    Pubkey::new_from_array([77u8; 32])
}

pub fn payer() -> Pubkey {
    Pubkey::new_from_array([21; 32])
}

pub fn authority() -> Pubkey {
    Pubkey::new_from_array([22; 32])
}

pub fn rent_recipient() -> Pubkey {
    Pubkey::new_from_array([24; 32])
}

pub fn account(lamports: u64) -> Account {
    Account {
        lamports,
        data: Vec::new(),
        owner: Pubkey::new_from_array([0; 32]),
        executable: false,
        rent_epoch: 0,
    }
}

fn system_program_slot() -> Slot {
    let (key, account) = mollusk_svm::program::keyed_account_for_system_program();
    Slot {
        label: "system_program",
        meta: AccountMeta::new_readonly(key, false),
        account,
    }
}

fn spp_program_slot() -> Slot {
    let (key, account) = spp_program_account();
    Slot {
        label: "spp_program",
        meta: AccountMeta::new_readonly(key, false),
        account,
    }
}

pub fn config_pda() -> (Pubkey, u8) {
    Pubkey::find_program_address(&[CONFIG_PDA_SEED], &program_id())
}

pub fn ring_auth_pda() -> (Pubkey, u8) {
    Pubkey::find_program_address(&[RING_AUTH_PDA_SEED], &program_id())
}

pub fn program_data_pda() -> Pubkey {
    Pubkey::find_program_address(&[program_id().as_ref()], &BPF_LOADER_UPGRADEABLE_PUBKEY).0
}

pub fn program_data_account(upgrade_authority: Option<&Pubkey>) -> Account {
    let mut data = Vec::with_capacity(48);
    data.extend_from_slice(&3u32.to_le_bytes());
    data.extend_from_slice(&0u64.to_le_bytes());
    match upgrade_authority {
        Some(authority) => {
            data.push(1);
            data.extend_from_slice(authority.as_ref());
        }
        None => data.push(0),
    }
    Account {
        lamports: 1_000_000_000,
        data,
        owner: BPF_LOADER_UPGRADEABLE_PUBKEY,
        executable: false,
        rent_epoch: 0,
    }
}

/// The shielded-pool program account as the runtime presents it: executable and
/// loader-v3 owned. The program itself is not loaded into mollusk, so any CPI
/// into it fails; only the ring's own pre-CPI validation is assertable here.
pub fn spp_program_account() -> (Pubkey, Account) {
    let spp_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    (
        spp_id,
        mollusk_svm::program::create_program_account_loader_v3(&spp_id),
    )
}

/// A well-formed SEC1-compressed auditor key, or a deliberately malformed one
/// when `prefix` is not 2 or 3.
pub fn auditor_pubkey(prefix: u8) -> [u8; 33] {
    let mut key: [u8; 33] =
        hex::decode("039dc51b59006b13f143944d4e432db7c032241ceb3698a6cc0cdabadf29b71dec")
            .expect("valid hex")
            .try_into()
            .expect("compressed key");
    if let Some(first) = key.first_mut() {
        *first = prefix;
    }
    key
}

pub fn policy_config_pda() -> (Pubkey, u8) {
    policy_config_pda_of(program_id())
}

pub fn namespace_pda() -> (Pubkey, u8) {
    namespace_pda_of(program_id())
}

fn policy_config_pda_of(ring: Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[POLICY_CONFIG_PDA_SEED], &ring)
}

fn namespace_pda_of(ring: Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[NAMESPACE_PDA_SEED], &ring)
}

pub const RELEASED_RULES: RuleTable = RuleTable::builder()
    .rule(Rule::require(Subject::OutputOwner, ListId::Allow))
    .rule(Rule::require(Subject::Sender, ListId::Allow))
    .rule(Rule::forbid(Subject::OutputOwner, ListId::Block))
    .rule(Rule::forbid(Subject::Sender, ListId::Frozen))
    .build();

pub const PINNED_RULES: RuleTable = RuleTable::builder()
    .rule(Rule::require(Subject::OutputOwner, ListId::Allow))
    .rule(Rule::forbid(Subject::Sender, ListId::Frozen))
    .rule(Rule::allow_only_assets())
    .inline_assets(&[[3u8; 32], [4u8; 32]])
    .build();

pub const INLINE_POOL: [[u8; 32]; MAX_INLINE_ASSETS] = [
    [1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32], [5u8; 32], [6u8; 32], [7u8; 32], [8u8; 32],
];

/// The largest table `try_build` admits.
pub fn largest_table() -> RuleTable {
    ListId::ALL
        .into_iter()
        .map(|list_id| Rule::require(Subject::Sender, list_id))
        .chain([
            Rule::forbid(Subject::Sender, ListId::Allow),
            Rule::forbid(Subject::Sender, ListId::Block),
        ])
        .fold(
            RuleTable::builder()
                .rule(Rule::allow_only_assets())
                .inline_assets(&INLINE_POOL),
            |builder, rule| builder.rule(rule),
        )
        .build()
}

pub const WARPED_SLOT: u64 = 7_777;

/// One slot per list `rules` references, all serving the ring's own entries.
pub fn own_source_slots(rules: &RuleTable) -> [SourceSlot; N_SOURCE_SLOTS] {
    source_slots_serving(rules, namespace_pda().0)
}

/// The curator's own-mode map, one slot per list `rules` references.
pub fn curator_source_slots(rules: &RuleTable) -> [SourceSlot; N_SOURCE_SLOTS] {
    source_slots_serving(rules, curator_namespace_pda().0)
}

fn source_slots_serving(rules: &RuleTable, namespace: Pubkey) -> [SourceSlot; N_SOURCE_SLOTS] {
    let namespace = Address::new_from_array(namespace.to_bytes());
    let mut sources = [SourceSlot::zeroed(); N_SOURCE_SLOTS];
    for list_id in rules.referenced().iter() {
        sources[list_id.slot()] = SourceSlot {
            list_id: list_id as u8,
            namespace,
        };
    }
    sources
}

pub fn mixed_sources() -> [SourceSlot; N_SOURCE_SLOTS] {
    let mut sources = own_source_slots(&RELEASED_RULES);
    sources[ListId::Block.slot()].namespace =
        Address::new_from_array(curator_namespace_pda().0.to_bytes());
    sources
}

pub fn own_specs(rules: &RuleTable) -> Vec<SourceSpec> {
    rules
        .referenced()
        .iter()
        .map(|list_id| SourceSpec {
            list_id: list_id as u8,
            source: 0,
        })
        .collect()
}

pub fn specs_with_block_source(source: u8) -> Vec<SourceSpec> {
    let mut specs = own_specs(&RELEASED_RULES);
    for spec in &mut specs {
        if spec.list_id == ListId::Block as u8 {
            spec.source = source;
        }
    }
    specs
}

/// The hash `rules` pins over `sources`.
pub fn policy_hash_for(rules: &RuleTable, sources: &[SourceSlot; N_SOURCE_SLOTS]) -> [u8; 32] {
    let mut slots = [SourceOwner::default(); MAX_SOURCES];
    for (slot, stored) in slots.iter_mut().zip(sources) {
        if stored.list_id == 0 {
            continue;
        }
        *slot = SourceOwner {
            list_id: stored.list_id,
            owner_hash: ListNamespace::new(stored.namespace.as_array())
                .expect("namespace owner")
                .owner_hash,
        };
    }
    rules
        .hash(&SourceMap::from_slots(slots).expect("positional map"))
        .expect("policy hash")
}

/// As the ring's `create_policy` wrote it.
pub struct PolicyConfigFixture<'a> {
    pub ring: Pubkey,
    pub entries_tree: Pubkey,
    pub rules: &'a RuleTable,
    pub sources: [SourceSlot; N_SOURCE_SLOTS],
}

impl PolicyConfigFixture<'_> {
    pub fn account(&self) -> Account {
        let state = PolicyConfig {
            discriminator: POLICY_CONFIG,
            policy_hash: policy_hash_for(self.rules, &self.sources),
            entries_tree: Address::new_from_array(self.entries_tree.to_bytes()),
            namespace_bump: namespace_pda_of(self.ring).1,
            bump: policy_config_pda_of(self.ring).1,
            sources: self.sources,
            rules: self.rules.encode(),
            generation: 1u32.to_le_bytes(),
            generation_slot: 0u64.to_le_bytes(),
        };
        Account {
            lamports: 1_000_000_000,
            data: bytemuck::bytes_of(&state).to_vec(),
            owner: self.ring,
            executable: false,
            rent_epoch: 0,
        }
    }
}

/// An empty table, the fixture reaches the proof.
pub fn initialized_policy_config_account() -> Account {
    let empty = RuleTable::empty();
    policy_config_account_with(&empty, own_source_slots(&empty))
}

pub fn policy_config_account_with(
    rules: &RuleTable,
    sources: [SourceSlot; N_SOURCE_SLOTS],
) -> Account {
    PolicyConfigFixture {
        ring: program_id(),
        entries_tree: entries_tree(),
        rules,
        sources,
    }
    .account()
}

/// A foreign curator ring, its policy and namespace PDAs derive from this id.
pub fn curator_program_id() -> Pubkey {
    Pubkey::new_from_array([88u8; 32])
}

pub fn curator_policy_config_pda() -> (Pubkey, u8) {
    policy_config_pda_of(curator_program_id())
}

pub fn curator_namespace_pda() -> (Pubkey, u8) {
    namespace_pda_of(curator_program_id())
}

pub fn initialized_curator_policy_config_account() -> Account {
    curator_policy_config_account_with(entries_tree(), curator_source_slots(&RELEASED_RULES))
}

/// The loader never rechecks the curator's stored hash.
pub fn curator_policy_config_account_with(
    entries_tree: Pubkey,
    sources: [SourceSlot; N_SOURCE_SLOTS],
) -> Account {
    PolicyConfigFixture {
        ring: curator_program_id(),
        entries_tree,
        rules: &RELEASED_RULES,
        sources,
    }
    .account()
}

pub fn curator_slot(account: Account) -> Slot {
    Slot {
        label: "curator",
        meta: AccountMeta::new_readonly(curator_policy_config_pda().0, false),
        account,
    }
}

/// The tree entries live in. Its bytes need only satisfy the owner and
/// discriminator checks, no fixture here reads a root.
pub fn entries_tree() -> Pubkey {
    Pubkey::new_from_array([41; 32])
}

pub fn entries_tree_account() -> Account {
    Account {
        lamports: 1_000_000_000,
        data: vec![zolana_interface::state::discriminator::TREE_ACCOUNT_DISCRIMINATOR; 1],
        owner: Pubkey::new_from_array(zolana_interface::SHIELDED_POOL_PROGRAM_ID),
        executable: false,
        rent_epoch: 0,
    }
}

/// A real SPP tree at the entries address, so the transact path reaches proof
/// verification.
pub fn initialized_entries_tree_account() -> Account {
    let mut data = vec![0u8; TreeAccount::account_size()];
    let params = nullifier_tree_params();
    TreeAccount::init(
        &mut data,
        zolana_interface::state::discriminator::TREE_ACCOUNT_DISCRIMINATOR,
        zolana_tree::UTXO_TREE_HEIGHT as u8,
        entries_tree().to_bytes(),
        0,
        params,
        default_tree_fees(params.input_queue_zkp_batch_size).expect("default tree fees"),
    )
    .expect("initialize entries tree");
    Account {
        lamports: 1_000_000_000,
        data,
        owner: Pubkey::new_from_array(zolana_interface::SHIELDED_POOL_PROGRAM_ID),
        executable: false,
        rent_epoch: 0,
    }
}

fn entries_tree_view(account: &mut Account) -> TreeAccount<'_> {
    TreeAccount::from_bytes(&mut account.data, entries_tree().to_bytes()).expect("entries tree")
}

/// The initialized tree after `rotations` nonzero nullifier roots.
pub fn initialized_entries_tree_account_with_roots(rotations: u16) -> Account {
    let mut account = initialized_entries_tree_account();
    {
        let mut tree = entries_tree_view(&mut account);
        let nullifier = tree.nullifier_tree();
        for rotation in 1..=rotations {
            let mut root = [0u8; 32];
            root[..2].copy_from_slice(&rotation.to_le_bytes());
            let cursor = nullifier.root_history.current_index as usize;
            nullifier.root_history.roots[cursor] = root;
            nullifier.root_history.current_index =
                ((cursor + 1) % nullifier.root_history.roots.len()) as u64;
        }
    }
    account
}

pub fn paused_entries_tree_account() -> Account {
    let mut account = initialized_entries_tree_account();
    entries_tree_view(&mut account).set_paused(true);
    account
}

pub fn nullifier_root_cursor(account: &Account) -> u16 {
    let mut account = account.clone();
    let cursor = entries_tree_view(&mut account)
        .nullifier_tree()
        .get_root_index();
    u16::try_from(cursor).expect("root cursor")
}

pub fn table_ix_data(rules: &RuleTable, specs: &[SourceSpec]) -> PolicyTableIxData {
    PolicyTableIxData {
        sources: specs.to_vec(),
        rules: rules.rules().iter().map(Rule::encoded).collect(),
        inline_assets: rules.inline_assets().to_vec(),
    }
}

pub fn policy_table_data(instruction_tag: u8, table: &PolicyTableIxData) -> Vec<u8> {
    let mut data = vec![instruction_tag];
    data.extend_from_slice(&wincode::serialize(table).expect("policy table data"));
    data
}

pub fn create_policy_fixture() -> Fixture {
    create_policy_fixture_with(&table_ix_data(&RuleTable::empty(), &[]))
}

/// Green `create_policy` fixture, `[payer(w,s), authority(s), policy_config(w),
/// entries_tree, system_program, program, program_data]`, curators trail.
pub fn create_policy_fixture_with(table: &PolicyTableIxData) -> Fixture {
    Fixture::new(
        policy_table_data(tag::CREATE_POLICY, table),
        vec![
            Slot {
                label: "payer",
                meta: AccountMeta::new(payer(), true),
                account: account(1_000_000_000),
            },
            Slot {
                label: "authority",
                meta: AccountMeta::new_readonly(authority(), true),
                account: account(1_000_000_000),
            },
            Slot {
                label: "policy_config",
                meta: AccountMeta::new(policy_config_pda().0, false),
                account: account(0),
            },
            Slot {
                label: "entries_tree",
                meta: AccountMeta::new_readonly(entries_tree(), false),
                account: entries_tree_account(),
            },
            system_program_slot(),
            Slot {
                label: "program",
                meta: AccountMeta::new_readonly(program_id(), false),
                account: mollusk_svm::program::create_program_account_loader_v3(&program_id()),
            },
            Slot {
                label: "program_data",
                meta: AccountMeta::new_readonly(program_data_pda(), false),
                account: program_data_account(Some(&authority())),
            },
        ],
    )
}

/// Green `set_policy_rules` fixture, `[authority(s), policy_config(w), program,
/// program_data]`, curators trail.
pub fn set_policy_rules_fixture(policy_config: Account, table: &PolicyTableIxData) -> Fixture {
    Fixture::new(
        policy_table_data(tag::SET_POLICY_RULES, table),
        vec![
            Slot {
                label: "authority",
                meta: AccountMeta::new_readonly(authority(), true),
                account: account(1_000_000_000),
            },
            Slot {
                label: "policy_config",
                meta: AccountMeta::new(policy_config_pda().0, false),
                account: policy_config,
            },
            Slot {
                label: "program",
                meta: AccountMeta::new_readonly(program_id(), false),
                account: mollusk_svm::program::create_program_account_loader_v3(&program_id()),
            },
            Slot {
                label: "program_data",
                meta: AccountMeta::new_readonly(program_data_pda(), false),
                account: program_data_account(Some(&authority())),
            },
        ],
    )
}

pub fn set_policy_source_data(list_id: u8, source: u8) -> Vec<u8> {
    let mut data = vec![tag::SET_POLICY_SOURCE];
    data.extend_from_slice(
        &wincode::serialize(&custom_ring_interface::SetPolicySourceIxData { list_id, source })
            .expect("set_policy_source data"),
    );
    data
}

/// Green `set_policy_source` fixture, `[authority(s), config, policy_config(w)]`,
/// shared mode pushes one trailing curator.
pub fn set_policy_source_fixture(policy_config: Account, list_id: u8, source: u8) -> Fixture {
    Fixture::new(
        set_policy_source_data(list_id, source),
        vec![
            Slot {
                label: "authority",
                meta: AccountMeta::new_readonly(authority(), true),
                account: account(1_000_000_000),
            },
            Slot {
                label: "config",
                meta: AccountMeta::new_readonly(config_pda().0, false),
                account: initialized_config_account(authority(), auditor_pubkey(2)),
            },
            Slot {
                label: "policy_config",
                meta: AccountMeta::new(policy_config_pda().0, false),
                account: policy_config,
            },
        ],
    )
}

/// The account layout `MutationAccounts` expects, `[config, policy_config,
/// payer(w,s), input_tree(w), output_tree(w), spp_program, system_program,
/// nullifier_pda(w), entries]`. SPP is not loaded, only the ring's pre-CPI
/// validation is assertable.
fn entry_mutation_slots(policy_config: Account, payer: Pubkey) -> Vec<Slot> {
    vec![
        Slot {
            label: "config",
            meta: AccountMeta::new_readonly(config_pda().0, false),
            account: initialized_config_account(authority(), auditor_pubkey(2)),
        },
        Slot {
            label: "policy_config",
            meta: AccountMeta::new_readonly(policy_config_pda().0, false),
            account: policy_config,
        },
        Slot {
            label: "payer",
            meta: AccountMeta::new(payer, true),
            account: account(1_000_000_000),
        },
        Slot {
            label: "input_tree",
            meta: AccountMeta::new(entries_tree(), false),
            account: entries_tree_account(),
        },
        Slot {
            label: "output_tree",
            meta: AccountMeta::new(entries_tree(), false),
            account: entries_tree_account(),
        },
        spp_program_slot(),
        system_program_slot(),
        Slot {
            label: "nullifier_pda",
            meta: AccountMeta::new(Pubkey::new_from_array([99; 32]), false),
            account: account(0),
        },
        Slot {
            label: "entries",
            meta: AccountMeta::new_readonly(namespace_pda().0, false),
            account: account(1_000_000_000),
        },
    ]
}

/// The member the entry fixtures derive, `owner_tag([61; 32])`.
pub fn default_entry_member() -> [u8; 32] {
    *zolana_ring_policy::Member::owner_tag(&[61u8; 32])
        .expect("member")
        .as_bytes()
}

/// The entry a mutation writes, `writer` signs as the payer.
pub struct EntryFixture {
    pub list_id: ListId,
    pub writer: Pubkey,
    pub member: [u8; 32],
    pub state: u8,
    pub content_hash: [u8; 32],
}

impl EntryFixture {
    /// Active with unit content.
    pub fn new(list_id: ListId, writer: Pubkey) -> Self {
        Self {
            list_id,
            writer,
            member: default_entry_member(),
            state: 1,
            content_hash: [0u8; 32],
        }
    }

    pub fn create(self, policy_config: Account) -> Fixture {
        let mut data = vec![tag::CREATE_ENTRY];
        data.extend_from_slice(
            &wincode::serialize(&CreateEntryIxData {
                list_id: self.list_id as u8,
                member: self.member,
                state: self.state,
                content_hash: self.content_hash,
                nullifier_tree_root_index: 0,
                utxo_tree_root_index: 0,
                proof: TransactProof::zeroed(),
            })
            .expect("create_entry data"),
        );
        Fixture::new(data, entry_mutation_slots(policy_config, self.writer))
    }

    /// Spends the Active unit-content version `spent_version` into the entry.
    pub fn update(self, policy_config: Account, spent_version: u64) -> Fixture {
        let mut data = vec![tag::UPDATE_ENTRY];
        data.extend_from_slice(
            &wincode::serialize(&UpdateEntryIxData {
                list_id: self.list_id as u8,
                member: self.member,
                spent_state: 1,
                spent_content_hash: [0u8; 32],
                spent_version,
                state: self.state,
                content_hash: self.content_hash,
                nullifier_tree_root_index: 0,
                utxo_tree_root_index: 0,
                proof: TransactProof::zeroed(),
            })
            .expect("update_entry data"),
        );
        Fixture::new(data, entry_mutation_slots(policy_config, self.writer))
    }
}

/// An initialized policy-ring config as this program would have written it.
pub fn initialized_config_account(authority: Pubkey, auditor_pubkey: [u8; 33]) -> Account {
    config_account_with(authority, auditor_pubkey, 1)
}

/// An audit-only ring config, transact takes the lighter proof path.
pub fn audit_only_config_account(authority: Pubkey, auditor_pubkey: [u8; 33]) -> Account {
    config_account_with(authority, auditor_pubkey, 0)
}

fn config_account_with(authority: Pubkey, auditor_pubkey: [u8; 33], has_policy: u8) -> Account {
    let state = RingProgramConfig {
        discriminator: RING_PROGRAM_CONFIG,
        authority: Address::new_from_array(authority.to_bytes()),
        auditor_pubkey,
        bump: config_pda().1,
        has_policy,
    };
    Account {
        lamports: 1_000_000_000,
        data: bytemuck::bytes_of(&state).to_vec(),
        owner: program_id(),
        executable: false,
        rent_epoch: 0,
    }
}

pub fn create_config_data(auditor_pubkey: [u8; 33]) -> Vec<u8> {
    let mut data = vec![tag::CREATE_CONFIG];
    data.extend_from_slice(
        &wincode::serialize(&CreateConfigIxData {
            auditor_pubkey,
            has_policy: 1,
        })
        .expect("serialize create_config data"),
    );
    data
}

pub fn create_config_fixture(auditor_pubkey: [u8; 33]) -> Fixture {
    create_config_fixture_deployed_by(auditor_pubkey, Some(&authority()))
}

/// Green `create_config` fixture: `[payer(w,s), authority(s), config(w),
/// system_program]`.
pub fn create_config_fixture_deployed_by(
    auditor_pubkey: [u8; 33],
    upgrade_authority: Option<&Pubkey>,
) -> Fixture {
    Fixture::new(
        create_config_data(auditor_pubkey),
        vec![
            Slot {
                label: "payer",
                meta: AccountMeta::new(payer(), true),
                account: account(1_000_000_000),
            },
            Slot {
                label: "authority",
                meta: AccountMeta::new_readonly(authority(), true),
                account: account(1_000_000_000),
            },
            Slot {
                label: "config",
                meta: AccountMeta::new(config_pda().0, false),
                account: account(0),
            },
            system_program_slot(),
            Slot {
                label: "program",
                meta: AccountMeta::new_readonly(program_id(), false),
                account: mollusk_svm::program::create_program_account_loader_v3(&program_id()),
            },
            Slot {
                label: "program_data",
                meta: AccountMeta::new_readonly(program_data_pda(), false),
                account: program_data_account(upgrade_authority),
            },
        ],
    )
}

/// `init_spp_ring_config` fixture: `[payer(w,s), authority(s), config,
/// protocol_config, ring_auth(w), system_program, spp_program, policy_config]`.
/// `config` is supplied by the caller so negatives can pass an uninitialized or
/// foreign-authority config, an audit-only ring truncates to seven accounts.
pub fn init_spp_ring_config_fixture(config: Account) -> Fixture {
    Fixture::new(
        vec![tag::INIT_SPP_RING_CONFIG],
        vec![
            Slot {
                label: "payer",
                meta: AccountMeta::new(payer(), true),
                account: account(1_000_000_000),
            },
            Slot {
                label: "authority",
                meta: AccountMeta::new_readonly(authority(), true),
                account: account(1_000_000_000),
            },
            Slot {
                label: "config",
                meta: AccountMeta::new_readonly(config_pda().0, false),
                account: config,
            },
            Slot {
                label: "protocol_config",
                meta: AccountMeta::new_readonly(zolana_interface::pda::protocol_config(), false),
                account: account(1_000_000_000),
            },
            Slot {
                label: "ring_auth",
                meta: AccountMeta::new(ring_auth_pda().0, false),
                account: account(0),
            },
            system_program_slot(),
            spp_program_slot(),
            Slot {
                label: "policy_config",
                meta: AccountMeta::new_readonly(policy_config_pda().0, false),
                account: initialized_policy_config_account(),
            },
        ],
    )
}

/// SPP's `RingConfig` at the `ring_auth` PDA, the PDA is its own authority.
pub fn spp_ring_config_account() -> Account {
    let (ring_auth, bump) = ring_auth_pda();
    let state = RingConfig {
        discriminator: RING_CONFIG,
        authority: Address::new_from_array(ring_auth.to_bytes()),
        program_id: Address::new_from_array(program_id().to_bytes()),
        ring_authority_transact_is_enabled: 0,
        paused: 0,
        bump,
    };
    Account {
        lamports: 1_000_000_000,
        data: bytemuck::bytes_of(&state).to_vec(),
        owner: Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
        executable: false,
        rent_epoch: 0,
    }
}

/// Green `set_paused` fixture, `[authority(s), config, ring_auth(w), spp_program]`.
pub fn set_paused_fixture(paused: u8) -> Fixture {
    let mut data = vec![tag::SET_PAUSED];
    data.extend_from_slice(
        &wincode::serialize(&SetPausedIxData { paused }).expect("set_paused data"),
    );
    Fixture::new(
        data,
        vec![
            Slot {
                label: "authority",
                meta: AccountMeta::new_readonly(authority(), true),
                account: account(1_000_000_000),
            },
            Slot {
                label: "config",
                meta: AccountMeta::new_readonly(config_pda().0, false),
                account: initialized_config_account(authority(), auditor_pubkey(2)),
            },
            Slot {
                label: "ring_auth",
                meta: AccountMeta::new(ring_auth_pda().0, false),
                account: spp_ring_config_account(),
            },
            spp_program_slot(),
        ],
    )
}

/// SOL-only ring-deposit fixture, laid out exactly as SPP's deposit loader wants
/// it: `[tree(w), depositor(w,s), ring_config, spp_program, system_program,
/// sol_interface]`. The instruction data starts with SPP's own `RING_DEPOSIT`
/// tag, which the ring forwards verbatim.
pub fn deposit_fixture() -> Fixture {
    Fixture::new(
        vec![tag::DEPOSIT],
        vec![
            Slot {
                label: "tree",
                meta: AccountMeta::new(Pubkey::new_from_array([51; 32]), false),
                account: account(1_000_000_000),
            },
            Slot {
                label: "depositor",
                meta: AccountMeta::new(Pubkey::new_from_array([52; 32]), true),
                account: account(1_000_000_000),
            },
            Slot {
                label: "ring_config",
                meta: AccountMeta::new_readonly(ring_auth_pda().0, false),
                account: account(1_000_000_000),
            },
            spp_program_slot(),
            system_program_slot(),
            Slot {
                label: "sol_interface",
                meta: AccountMeta::new(Pubkey::new_from_array([53; 32]), false),
                account: account(1_000_000_000),
            },
        ],
    )
}

pub fn transact_fixture(config: Account, data: Vec<u8>) -> Fixture {
    Fixture::new(
        data,
        vec![
            Slot {
                label: "payer",
                meta: AccountMeta::new(payer(), true),
                account: account(1_000_000_000),
            },
            Slot {
                label: "config",
                meta: AccountMeta::new_readonly(config_pda().0, false),
                account: config,
            },
            Slot {
                label: "policy_config",
                meta: AccountMeta::new_readonly(policy_config_pda().0, false),
                account: initialized_policy_config_account(),
            },
            Slot {
                label: "entries_tree",
                meta: AccountMeta::new_readonly(entries_tree(), false),
                account: initialized_entries_tree_account(),
            },
            Slot {
                label: "spp_payer",
                meta: AccountMeta::new(payer(), true),
                account: account(1_000_000_000),
            },
            // A stub distinct from entries_tree, unread because the CPI is
            // unreached.
            Slot {
                label: "input_tree",
                meta: AccountMeta::new(Pubkey::new_from_array([40; 32]), false),
                account: account(1_000_000_000),
            },
            Slot {
                label: "output_tree",
                meta: AccountMeta::new(Pubkey::new_from_array([42; 32]), false),
                account: account(1_000_000_000),
            },
            spp_program_slot(),
            system_program_slot(),
            Slot {
                label: "ring_config",
                meta: AccountMeta::new_readonly(ring_auth_pda().0, false),
                account: account(1_000_000_000),
            },
        ],
    )
}

/// An audit-only transact fixture, the policy_config and entries_tree accounts
/// the policy path reads are absent.
pub fn audit_transact_fixture(config: Account, data: Vec<u8>) -> Fixture {
    Fixture::new(
        data,
        vec![
            Slot {
                label: "payer",
                meta: AccountMeta::new(payer(), true),
                account: account(1_000_000_000),
            },
            Slot {
                label: "config",
                meta: AccountMeta::new_readonly(config_pda().0, false),
                account: config,
            },
            Slot {
                label: "spp_payer",
                meta: AccountMeta::new(payer(), true),
                account: account(1_000_000_000),
            },
            Slot {
                label: "input_tree",
                meta: AccountMeta::new(Pubkey::new_from_array([40; 32]), false),
                account: account(1_000_000_000),
            },
            Slot {
                label: "output_tree",
                meta: AccountMeta::new(Pubkey::new_from_array([42; 32]), false),
                account: account(1_000_000_000),
            },
            spp_program_slot(),
            system_program_slot(),
            Slot {
                label: "ring_config",
                meta: AccountMeta::new_readonly(ring_auth_pda().0, false),
                account: account(1_000_000_000),
            },
        ],
    )
}

pub fn reader() -> ReaderKeyBytes {
    ed25519_reader(23)
}

pub fn ed25519_reader(byte: u8) -> ReaderKeyBytes {
    let public = ed25519_dalek::SigningKey::from_bytes(&[byte; 32])
        .verifying_key()
        .to_bytes();
    let mut key = [0u8; 34];
    key[0] = READER_KEY_ED25519;
    key[1..33].copy_from_slice(&public);
    key
}

pub fn p256_reader() -> ReaderKeyBytes {
    let mut key = [0u8; 34];
    key[0] = READER_KEY_P256;
    key[1..].copy_from_slice(&auditor_pubkey(3));
    key
}

pub fn read_access_record_pda(reader: &ReaderKeyBytes) -> (Pubkey, u8) {
    let seed_hash = ReadAccessRecord::seed_hash(reader).expect("sha256");
    Pubkey::find_program_address(&[READ_ACCESS_RECORD_PDA_SEED, &seed_hash], &program_id())
}

pub fn reader_ix_data(instruction_tag: u8, reader: &ReaderKeyBytes) -> Vec<u8> {
    let mut data = vec![instruction_tag];
    data.extend_from_slice(reader);
    data
}

pub fn initialized_reader_account(reader: &ReaderKeyBytes) -> Account {
    let state = ReadAccessRecord {
        discriminator: READ_ACCESS_RECORD,
        reader: *reader,
        bump: read_access_record_pda(reader).1,
    };
    Account {
        lamports: 1_128_000,
        data: bytemuck::bytes_of(&state).to_vec(),
        owner: program_id(),
        executable: false,
        rent_epoch: 0,
    }
}

pub fn new_authority() -> Pubkey {
    Pubkey::new_from_array([31u8; 32])
}

pub fn set_authority_fixture() -> Fixture {
    Fixture::new(
        vec![tag::SET_AUTHORITY],
        vec![
            Slot {
                label: "authority",
                meta: AccountMeta::new_readonly(authority(), true),
                account: account(1_000_000_000),
            },
            Slot {
                label: "new_authority",
                meta: AccountMeta::new_readonly(new_authority(), true),
                account: account(1_000_000_000),
            },
            Slot {
                label: "config",
                meta: AccountMeta::new(config_pda().0, false),
                account: initialized_config_account(authority(), auditor_pubkey(2)),
            },
        ],
    )
}

pub fn grant_read_access_fixture(reader: &ReaderKeyBytes) -> Fixture {
    Fixture::new(
        reader_ix_data(tag::GRANT_READ_ACCESS, reader),
        vec![
            Slot {
                label: "payer",
                meta: AccountMeta::new(payer(), true),
                account: account(1_000_000_000),
            },
            Slot {
                label: "authority",
                meta: AccountMeta::new_readonly(authority(), true),
                account: account(1_000_000_000),
            },
            Slot {
                label: "config",
                meta: AccountMeta::new_readonly(config_pda().0, false),
                account: initialized_config_account(authority(), auditor_pubkey(2)),
            },
            Slot {
                label: "read_access_record",
                meta: AccountMeta::new(read_access_record_pda(reader).0, false),
                account: account(0),
            },
            system_program_slot(),
        ],
    )
}

pub fn revoke_read_access_fixture(reader: &ReaderKeyBytes) -> Fixture {
    Fixture::new(
        reader_ix_data(tag::REVOKE_READ_ACCESS, reader),
        vec![
            Slot {
                label: "authority",
                meta: AccountMeta::new_readonly(authority(), true),
                account: account(1_000_000_000),
            },
            Slot {
                label: "config",
                meta: AccountMeta::new_readonly(config_pda().0, false),
                account: initialized_config_account(authority(), auditor_pubkey(2)),
            },
            Slot {
                label: "read_access_record",
                meta: AccountMeta::new(read_access_record_pda(reader).0, false),
                account: initialized_reader_account(reader),
            },
            Slot {
                label: "rent_recipient",
                meta: AccountMeta::new(rent_recipient(), false),
                account: account(0),
            },
        ],
    )
}
