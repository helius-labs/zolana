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

/// Nearest ancestor `target/deploy`, the program crate sits one level deeper in
/// zolana than in a generated ring.
fn sbf_dir() -> String {
    let mut dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        let candidate = dir.join("target/deploy");
        if candidate.is_dir() {
            return candidate.to_string_lossy().into_owned();
        }
        assert!(
            dir.pop(),
            "no target/deploy above {}",
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
    #[cfg(feature = "policy")]
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
    let (mut mollusk, program_id) = zolana_test_utils::mollusk::mollusk_with_program(
        &sbf_dir(),
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

#[cfg(feature = "policy")]
pub fn policy_config_pda() -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[custom_ring_interface::POLICY_CONFIG_PDA_SEED],
        &program_id(),
    )
}

#[cfg(feature = "policy")]
pub fn records_pda() -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[zolana_ring_policy::POLICY_RECORDS_PDA_SEED],
        &program_id(),
    )
}

/// Carries the deployed table's hash, so a fixture reaches the proof.
#[cfg(feature = "policy")]
pub fn initialized_policy_config_account() -> Account {
    let owner =
        zolana_ring_policy::RecordsOwner::new(&records_pda().0.to_bytes()).expect("records owner");
    let state = custom_ring_interface::PolicyConfig {
        discriminator: custom_ring_interface::POLICY_CONFIG,
        policy_hash: custom_ring_interface::POLICY
            .hash(&owner.owner_hash)
            .expect("policy hash"),
        records_tree: Address::new_from_array([41; 32]),
        records_bump: records_pda().1,
        bump: policy_config_pda().1,
    };
    Account {
        lamports: 1_000_000_000,
        data: bytemuck::bytes_of(&state).to_vec(),
        owner: program_id(),
        executable: false,
        rent_epoch: 0,
    }
}

/// The tree records live in. Its bytes need only satisfy the owner and
/// discriminator checks, no fixture here reads a root.
#[cfg(feature = "policy")]
pub fn records_tree() -> Pubkey {
    Pubkey::new_from_array([41; 32])
}

#[cfg(feature = "policy")]
pub fn records_tree_account() -> Account {
    Account {
        lamports: 1_000_000_000,
        data: vec![zolana_interface::state::discriminator::TREE_ACCOUNT_DISCRIMINATOR; 1],
        owner: Pubkey::new_from_array(zolana_interface::SHIELDED_POOL_PROGRAM_ID),
        executable: false,
        rent_epoch: 0,
    }
}

/// Green `create_policy` fixture, `[payer(w,s), authority(s), policy_config(w),
/// records_tree, system_program, program, program_data]`.
#[cfg(feature = "policy")]
pub fn create_policy_fixture() -> Fixture {
    Fixture::new(
        vec![custom_ring_interface::tag::CREATE_POLICY],
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
                label: "records_tree",
                meta: AccountMeta::new_readonly(records_tree(), false),
                account: records_tree_account(),
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

/// The policy artifact, whose transact wire and prefix differ from the
/// audit-only build.
#[cfg(feature = "policy")]
pub fn setup_policy_mollusk() -> (Mollusk, Pubkey) {
    let (mut mollusk, program_id) = zolana_test_utils::mollusk::mollusk_with_program(
        &sbf_dir(),
        *program_id().as_array(),
        "custom_ring_program_policy",
    );
    mollusk.compute_budget.compute_unit_limit = 1_400_000;
    (mollusk, program_id)
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
            #[cfg(feature = "policy")]
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
                meta: AccountMeta::new(Pubkey::new_from_array([41; 32]), false),
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
