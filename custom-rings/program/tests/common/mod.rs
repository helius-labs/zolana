//! Shared mollusk fixtures, each test binary uses a subset.
#![allow(dead_code)]

use custom_ring_interface::{
    tag, CreateConfigIxData, ReadAccessRecord, ReaderKeyBytes, RingProgramConfig, CONFIG_PDA_SEED,
    READER_KEY_ED25519, READER_KEY_P256, READ_ACCESS_RECORD, READ_ACCESS_RECORD_PDA_SEED,
    RING_PROGRAM_CONFIG,
};
use mollusk_svm::Mollusk;
use pinocchio::Address;
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;
use zolana_interface::{
    BPF_LOADER_UPGRADEABLE_PUBKEY, RING_AUTH_PDA_SEED, SHIELDED_POOL_PROGRAM_ID,
};

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
    setup_mollusk_in("target/deploy")
}

/// The rule-featured image, one process must never mix the two deploy dirs.
pub fn setup_mollusk_rules() -> (Mollusk, Pubkey) {
    setup_mollusk_in("target/deploy-ring-rules")
}

fn setup_mollusk_in(deploy_dir: &str) -> (Mollusk, Pubkey) {
    let (mut mollusk, program_id) = zolana_test_utils::mollusk::mollusk_with_program(
        &sbf_dir(deploy_dir),
        *program_id().as_array(),
        "custom_ring_program",
    );
    mollusk.compute_budget.compute_unit_limit = 1_400_000;
    (mollusk, program_id)
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
    Pubkey::find_program_address(
        &[custom_ring_interface::POLICY_CONFIG_PDA_SEED],
        &program_id(),
    )
}

pub fn namespace_pda() -> (Pubkey, u8) {
    Pubkey::find_program_address(&[zolana_ring_policy::NAMESPACE_PDA_SEED], &program_id())
}

/// One slot per list_id the deployed table references, all serving the ring's
/// own entries.
pub fn own_source_slots(
) -> [custom_ring_interface::SourceSlot; custom_ring_interface::N_SOURCE_SLOTS] {
    let own = Address::new_from_array(namespace_pda().0.to_bytes());
    let mut sources = [custom_ring_interface::SourceSlot {
        list_id: 0,
        namespace: Address::new_from_array([0; 32]),
    }; custom_ring_interface::N_SOURCE_SLOTS];
    for rule in custom_ring_interface::RULES.rules() {
        if let zolana_ring_policy::RuleSource::List(list_id) = rule.source {
            sources[list_id as usize - 1] = custom_ring_interface::SourceSlot {
                list_id: list_id as u8,
                namespace: own,
            };
        }
    }
    sources
}

/// The hash the deployed table pins over `sources`.
pub fn policy_hash_for(
    sources: &[custom_ring_interface::SourceSlot; custom_ring_interface::N_SOURCE_SLOTS],
) -> [u8; 32] {
    let mut slots = [zolana_ring_policy::SourceOwner::default(); zolana_ring_policy::MAX_SOURCES];
    for (slot, stored) in slots.iter_mut().zip(sources) {
        if stored.list_id == 0 {
            continue;
        }
        *slot = zolana_ring_policy::SourceOwner {
            list_id: stored.list_id,
            owner_hash: zolana_ring_policy::ListNamespace::new(stored.namespace.as_array())
                .expect("namespace owner")
                .owner_hash,
        };
    }
    custom_ring_interface::RULES
        .hash(&zolana_ring_policy::SourceMap::from_slots(slots).expect("positional map"))
        .expect("policy hash")
}

/// Carries the deployed table's hash, so a fixture reaches the proof.
pub fn initialized_policy_config_account() -> Account {
    policy_config_account_with(own_source_slots())
}

pub fn policy_config_account_with(
    sources: [custom_ring_interface::SourceSlot; custom_ring_interface::N_SOURCE_SLOTS],
) -> Account {
    let state = custom_ring_interface::PolicyConfig {
        discriminator: custom_ring_interface::POLICY_CONFIG,
        policy_hash: policy_hash_for(&sources),
        entries_tree: Address::new_from_array([41; 32]),
        namespace_bump: namespace_pda().1,
        bump: policy_config_pda().1,
        sources,
    };
    Account {
        lamports: 1_000_000_000,
        data: bytemuck::bytes_of(&state).to_vec(),
        owner: program_id(),
        executable: false,
        rent_epoch: 0,
    }
}

/// A foreign curator ring, its policy and entries PDAs derive from this id.
pub fn curator_program_id() -> Pubkey {
    Pubkey::new_from_array([88u8; 32])
}

pub fn curator_policy_config_pda() -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[custom_ring_interface::POLICY_CONFIG_PDA_SEED],
        &curator_program_id(),
    )
}

pub fn curator_namespace_pda() -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[zolana_ring_policy::NAMESPACE_PDA_SEED],
        &curator_program_id(),
    )
}

/// The curator's own-mode map, one slot per referenced list_id.
pub fn curator_source_slots(
) -> [custom_ring_interface::SourceSlot; custom_ring_interface::N_SOURCE_SLOTS] {
    let entries = Address::new_from_array(curator_namespace_pda().0.to_bytes());
    let mut sources = own_source_slots();
    for slot in &mut sources {
        if slot.list_id != 0 {
            slot.namespace = entries;
        }
    }
    sources
}

pub fn initialized_curator_policy_config_account() -> Account {
    curator_policy_config_account_with(entries_tree(), curator_source_slots())
}

/// The loader never rechecks the curator's stored hash.
pub fn curator_policy_config_account_with(
    entries_tree: Pubkey,
    sources: [custom_ring_interface::SourceSlot; custom_ring_interface::N_SOURCE_SLOTS],
) -> Account {
    let state = custom_ring_interface::PolicyConfig {
        discriminator: custom_ring_interface::POLICY_CONFIG,
        policy_hash: policy_hash_for(&sources),
        entries_tree: Address::new_from_array(entries_tree.to_bytes()),
        namespace_bump: curator_namespace_pda().1,
        bump: curator_policy_config_pda().1,
        sources,
    };
    Account {
        lamports: 1_000_000_000,
        data: bytemuck::bytes_of(&state).to_vec(),
        owner: curator_program_id(),
        executable: false,
        rent_epoch: 0,
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
    let mut data = vec![0u8; zolana_tree::TreeAccount::account_size()];
    zolana_tree::TreeAccount::init(
        &mut data,
        zolana_interface::state::discriminator::TREE_ACCOUNT_DISCRIMINATOR,
        zolana_tree::UTXO_TREE_HEIGHT as u8,
        entries_tree().to_bytes(),
        zolana_batched_merkle_tree::initialize_address_tree::InitAddressTreeAccountsInstructionData::default(),
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

pub fn create_policy_data(specs: &[custom_ring_interface::SourceSpec]) -> Vec<u8> {
    let mut data = vec![custom_ring_interface::tag::CREATE_POLICY];
    data.extend_from_slice(
        &wincode::serialize(&custom_ring_interface::CreatePolicyIxData {
            sources: specs.to_vec(),
        })
        .expect("create_policy data"),
    );
    data
}

pub fn create_policy_fixture() -> Fixture {
    create_policy_fixture_with(&[])
}

/// Green `create_policy` fixture, `[payer(w,s), authority(s), policy_config(w),
/// entries_tree, system_program, program, program_data]`, curators trail.
pub fn create_policy_fixture_with(specs: &[custom_ring_interface::SourceSpec]) -> Fixture {
    Fixture::new(
        create_policy_data(specs),
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

/// `create_entry` fixture, `[config, policy_config, payer(w,s), input_tree(w),
/// output_tree(w), spp_program, system_program, entries]`. SPP is not loaded,
/// only the ring's pre-CPI validation is assertable.
pub fn create_entry_fixture(policy_config: Account, list_id: u8, payer: Pubkey) -> Fixture {
    let member = zolana_ring_policy::Member::owner_tag(&[61u8; 32]).expect("member");
    let mut data = vec![tag::CREATE_ENTRY];
    data.extend_from_slice(
        &wincode::serialize(&custom_ring_interface::CreateEntryIxData {
            list_id,
            member: *member.as_bytes(),
            state: 1,
            content_hash: [7u8; 32],
            nullifier_tree_root_index: 0,
            utxo_tree_root_index: 0,
            proof: zolana_interface::instruction::instruction_data::transact::TransactProof::zeroed(
            ),
        })
        .expect("create_entry data"),
    );
    Fixture::new(
        data,
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
                label: "entries",
                meta: AccountMeta::new_readonly(namespace_pda().0, false),
                account: account(1_000_000_000),
            },
        ],
    )
}

/// An initialized config account as this program would have written it.
pub fn initialized_config_account(authority: Pubkey, auditor_pubkey: [u8; 33]) -> Account {
    let state = RingProgramConfig {
        discriminator: RING_PROGRAM_CONFIG,
        authority: Address::new_from_array(authority.to_bytes()),
        auditor_pubkey,
        bump: config_pda().1,
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
        &wincode::serialize(&CreateConfigIxData { auditor_pubkey })
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
/// protocol_config, ring_auth(w), system_program, spp_program]`. `config` is
/// supplied by the caller so negatives can pass an uninitialized or
/// foreign-authority config.
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
                label: "spp_payer",
                meta: AccountMeta::new(payer(), true),
                account: account(1_000_000_000),
            },
            Slot {
                label: "input_tree",
                meta: AccountMeta::new(entries_tree(), false),
                account: initialized_entries_tree_account(),
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
