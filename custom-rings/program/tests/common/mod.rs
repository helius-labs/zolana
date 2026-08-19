use custom_ring_program::{
    instructions::{
        approve_transact::{ApproveTransactIxData, APPROVAL_PDA_SEED, APPROVAL_SIZE},
        create_config::CreateConfigIxData,
        set_policy::{AssetRule, SetPolicyIxData},
    },
    state::{
        RingProgramConfig, ASSETS_ALLOWLIST, ASSETS_ANY, MAX_ASSETS, RING_PROGRAM_CONFIG,
        TRANSACT_APPROVAL, WITHDRAWALS_OPEN,
    },
    tag, CONFIG_PDA_SEED,
};
use mollusk_svm::Mollusk;
use pinocchio::Address;
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use zolana_interface::{
    BPF_LOADER_UPGRADEABLE_PUBKEY, RING_AUTH_PDA_SEED, SHIELDED_POOL_PROGRAM_ID,
};

const SBF_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/deploy");

pub fn setup_mollusk() -> (Mollusk, Pubkey) {
    zolana_test_utils::mollusk::mollusk_with_program(
        SBF_DIR,
        *custom_ring_program::ID.as_array(),
        "custom_ring_program",
    )
}

pub fn program_id() -> Pubkey {
    Pubkey::new_from_array(*custom_ring_program::ID.as_array())
}

pub fn payer() -> Pubkey {
    Pubkey::new_from_array([21; 32])
}

pub fn authority() -> Pubkey {
    Pubkey::new_from_array([22; 32])
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

pub fn config_pda() -> (Pubkey, u8) {
    Pubkey::find_program_address(&[CONFIG_PDA_SEED], &program_id())
}

pub fn ring_auth_pda() -> (Pubkey, u8) {
    Pubkey::find_program_address(&[RING_AUTH_PDA_SEED], &program_id())
}

/// The ring program's `ProgramData` account under the upgradeable loader.
pub fn program_data_pda() -> Pubkey {
    Pubkey::find_program_address(&[program_id().as_ref()], &BPF_LOADER_UPGRADEABLE_PUBKEY).0
}

/// Loader-v3 `ProgramData` state: u32 tag 3 || slot u64 || u8 option tag ||
/// authority, the bytes a real loader writes. `None` models an immutable
/// program.
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
    let mut key = [7u8; 33];
    if let Some(first) = key.first_mut() {
        *first = prefix;
    }
    key
}

/// An initialized config account as this program would have written it, with
/// the open policy `create_config` starts from.
pub fn initialized_config_account(authority: Pubkey, auditor_pubkey: [u8; 33]) -> Account {
    config_account_with_policy(authority, auditor_pubkey, PolicyFixture::default())
}

/// A config account carrying a policy as `set_policy` would have written it:
/// `allowlist` turns the asset allowlist on over `assets`, `withdrawals` is the
/// default withdrawal rule, `approver` the approval signer.
pub struct PolicyFixture<'a> {
    pub allowlist: bool,
    pub assets: &'a [AssetRule],
    pub withdrawals: u8,
    pub approver: Option<Pubkey>,
}

impl Default for PolicyFixture<'_> {
    fn default() -> Self {
        Self {
            allowlist: false,
            assets: &[],
            withdrawals: WITHDRAWALS_OPEN,
            approver: None,
        }
    }
}

pub fn config_account_with_policy(
    authority: Pubkey,
    auditor_pubkey: [u8; 33],
    policy: PolicyFixture<'_>,
) -> Account {
    let mut assets = [[0u8; 32]; MAX_ASSETS];
    let mut asset_withdrawals = [0u8; MAX_ASSETS];
    for (index, asset) in policy.assets.iter().enumerate() {
        assets[index] = asset.mint;
        asset_withdrawals[index] = asset.withdrawals;
    }
    let state = RingProgramConfig {
        discriminator: RING_PROGRAM_CONFIG,
        authority: Address::new_from_array(authority.to_bytes()),
        auditor_pubkey,
        bump: config_pda().1,
        withdrawals: policy.withdrawals,
        asset_policy: if policy.allowlist {
            ASSETS_ALLOWLIST
        } else {
            ASSETS_ANY
        },
        assets_len: policy.assets.len() as u8,
        approver: policy
            .approver
            .map(|key| Address::new_from_array(key.to_bytes()))
            .unwrap_or_default(),
        assets,
        asset_withdrawals,
    };
    Account {
        lamports: 1_000_000_000,
        data: bytemuck::bytes_of(&state).to_vec(),
        owner: program_id(),
        executable: false,
        rent_epoch: 0,
    }
}

pub fn approver() -> Pubkey {
    Pubkey::new_from_array([23; 32])
}

pub fn approval_pda(private_tx_hash: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[APPROVAL_PDA_SEED, private_tx_hash], &program_id())
}

/// An approval account as `approve_transact` writes it.
pub fn approval_account() -> Account {
    Account {
        lamports: 1_000_000,
        data: vec![TRANSACT_APPROVAL; APPROVAL_SIZE],
        owner: program_id(),
        executable: false,
        rent_epoch: 0,
    }
}

/// `approve_transact` fixture: `[approver(s), payer(w,s), config, approval(w),
/// system_program]` over `config`.
pub fn approve_transact_fixture(
    config: Account,
    private_tx_hash: [u8; 32],
) -> (Instruction, Vec<(Pubkey, Account)>) {
    let (config_key, _) = config_pda();
    let (approval, _) = approval_pda(&private_tx_hash);
    let (system_program, system_program_account) =
        mollusk_svm::program::keyed_account_for_system_program();
    let mut data = vec![tag::APPROVE_TRANSACT];
    data.extend_from_slice(
        &wincode::serialize(&ApproveTransactIxData { private_tx_hash })
            .expect("serialize approve_transact data"),
    );
    (
        Instruction {
            program_id: program_id(),
            accounts: vec![
                AccountMeta::new_readonly(approver(), true),
                AccountMeta::new(payer(), true),
                AccountMeta::new_readonly(config_key, false),
                AccountMeta::new(approval, false),
                AccountMeta::new_readonly(system_program, false),
            ],
            data,
        },
        vec![
            (approver(), account(1_000_000_000)),
            (payer(), account(1_000_000_000)),
            (config_key, config),
            (approval, account(0)),
            (system_program, system_program_account),
        ],
    )
}

pub fn set_policy_data(policy: &SetPolicyIxData) -> Vec<u8> {
    let mut data = vec![tag::SET_POLICY];
    data.extend_from_slice(&wincode::serialize(policy).expect("serialize set_policy data"));
    data
}

/// `set_policy` fixture: `[authority(s), config(w)]` over `config`.
pub fn set_policy_fixture(
    config: Account,
    policy: &SetPolicyIxData,
) -> (Instruction, Vec<(Pubkey, Account)>) {
    let (config_key, _) = config_pda();
    (
        Instruction {
            program_id: program_id(),
            accounts: vec![
                AccountMeta::new_readonly(authority(), true),
                AccountMeta::new(config_key, false),
            ],
            data: set_policy_data(policy),
        },
        vec![(authority(), account(1_000_000_000)), (config_key, config)],
    )
}

pub fn create_config_data(auditor_pubkey: [u8; 33]) -> Vec<u8> {
    let mut data = vec![tag::CREATE_CONFIG];
    data.extend_from_slice(
        &wincode::serialize(&CreateConfigIxData { auditor_pubkey })
            .expect("serialize create_config data"),
    );
    data
}

/// Green `create_config` fixture: `[payer(w,s), authority(s), config(w),
/// system_program, program, program_data]`, deployed as an upgradeable program
/// whose upgrade authority is the fixture `authority`.
pub fn create_config_fixture(auditor_pubkey: [u8; 33]) -> (Instruction, Vec<(Pubkey, Account)>) {
    create_config_fixture_deployed_by(auditor_pubkey, Some(&authority()))
}

/// `create_config` fixture with a chosen `ProgramData` upgrade authority.
pub fn create_config_fixture_deployed_by(
    auditor_pubkey: [u8; 33],
    upgrade_authority: Option<&Pubkey>,
) -> (Instruction, Vec<(Pubkey, Account)>) {
    let (config, _) = config_pda();
    let (system_program, system_program_account) =
        mollusk_svm::program::keyed_account_for_system_program();
    let program_data = program_data_pda();

    (
        Instruction {
            program_id: program_id(),
            accounts: vec![
                AccountMeta::new(payer(), true),
                AccountMeta::new_readonly(authority(), true),
                AccountMeta::new(config, false),
                AccountMeta::new_readonly(system_program, false),
                AccountMeta::new_readonly(program_id(), false),
                AccountMeta::new_readonly(program_data, false),
            ],
            data: create_config_data(auditor_pubkey),
        },
        vec![
            (payer(), account(1_000_000_000)),
            (authority(), account(1_000_000_000)),
            (config, account(0)),
            (system_program, system_program_account),
            (
                program_id(),
                mollusk_svm::program::create_program_account_loader_v3(&program_id()),
            ),
            (program_data, program_data_account(upgrade_authority)),
        ],
    )
}

/// `init_spp_ring_config` fixture: `[payer(w,s), authority(s), config,
/// protocol_config, ring_auth(w), system_program, spp_program]`. `config` is
/// supplied by the caller so negatives can pass an uninitialized or
/// foreign-authority config.
pub fn init_spp_ring_config_fixture(config: Account) -> (Instruction, Vec<(Pubkey, Account)>) {
    let (config_key, _) = config_pda();
    let (ring_auth, _) = ring_auth_pda();
    let protocol_config = zolana_interface::pda::protocol_config();
    let (system_program, system_program_account) =
        mollusk_svm::program::keyed_account_for_system_program();
    let (spp_id, spp_account) = spp_program_account();

    (
        Instruction {
            program_id: program_id(),
            accounts: vec![
                AccountMeta::new(payer(), true),
                AccountMeta::new_readonly(authority(), true),
                AccountMeta::new_readonly(config_key, false),
                AccountMeta::new_readonly(protocol_config, false),
                AccountMeta::new(ring_auth, false),
                AccountMeta::new_readonly(system_program, false),
                AccountMeta::new_readonly(spp_id, false),
            ],
            data: vec![tag::INIT_SPP_RING_CONFIG],
        },
        vec![
            (payer(), account(1_000_000_000)),
            (authority(), account(1_000_000_000)),
            (config_key, config),
            (protocol_config, account(1_000_000_000)),
            (ring_auth, account(0)),
            (system_program, system_program_account),
            (spp_id, spp_account),
        ],
    )
}

/// SOL-only ring-deposit fixture: the ring config first, then SPP's list laid
/// out exactly as its deposit loader wants it: `[tree(w), depositor(w,s),
/// ring_config, spp_program, system_program, sol_interface]`. The instruction
/// data starts with SPP's own `RING_DEPOSIT` tag, which the ring forwards
/// verbatim; `data` is the body after the tag.
pub fn deposit_fixture_with(
    config: Account,
    data: Vec<u8>,
) -> (Instruction, Vec<(Pubkey, Account)>) {
    let (config_key, _) = config_pda();
    let tree = Pubkey::new_from_array([51; 32]);
    let depositor = Pubkey::new_from_array([52; 32]);
    let sol_interface = Pubkey::new_from_array([53; 32]);
    let (ring_auth, _) = ring_auth_pda();
    let (system_program, system_program_account) =
        mollusk_svm::program::keyed_account_for_system_program();
    let (spp_id, spp_account) = spp_program_account();
    let mut instruction_data = vec![tag::DEPOSIT];
    instruction_data.extend_from_slice(&data);

    (
        Instruction {
            program_id: program_id(),
            accounts: vec![
                AccountMeta::new_readonly(config_key, false),
                AccountMeta::new(tree, false),
                AccountMeta::new(depositor, true),
                AccountMeta::new_readonly(ring_auth, false),
                AccountMeta::new_readonly(spp_id, false),
                AccountMeta::new_readonly(system_program, false),
                AccountMeta::new(sol_interface, false),
            ],
            data: instruction_data,
        },
        vec![
            (config_key, config),
            (tree, account(1_000_000_000)),
            (depositor, account(1_000_000_000)),
            (ring_auth, account(1_000_000_000)),
            (spp_id, spp_account),
            (system_program, system_program_account),
            (sol_interface, account(1_000_000_000)),
        ],
    )
}

pub fn deposit_fixture() -> (Instruction, Vec<(Pubkey, Account)>) {
    deposit_fixture_with(
        initialized_config_account(authority(), auditor_pubkey(2)),
        Vec::new(),
    )
}

/// Point the meta at `index` at `replacement` and register a bare account for it,
/// so a fixture can swap in an impostor address.
pub fn substitute_account(
    instruction: &mut Instruction,
    accounts: &mut Vec<(Pubkey, Account)>,
    index: usize,
    replacement: Pubkey,
) {
    instruction
        .accounts
        .get_mut(index)
        .expect("meta index in fixture")
        .pubkey = replacement;
    accounts.push((replacement, account(1_000_000_000)));
}
