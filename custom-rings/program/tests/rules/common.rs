use bytemuck::{Pod, Zeroable};
use custom_ring_interface::{
    compute_unit_limit, tag, AppliedAt, ApplyRecordsIxData, AuthorityWriteRecordsIxData,
    CreateConfigIxData, CustomRingError, InstructionTag, MemberRegistry, MemberWriteIxData,
    PolicyTableIxData, RecordWriteData, RegisterKeyIxData, RingKind, SourceSpec,
    WriteRecordsIxData, CONFIG_PDA_SEED, MEMBER_REGISTRY_PDA_SEED, RECORD_QUEUE_PDA_SEED,
};
use litesvm::LiteSVM;
use solana_account::Account;
use solana_address::Address;
use solana_bn254::compression::prelude::{alt_bn128_g1_decompress_be, alt_bn128_g2_decompress_be};
use solana_instruction::{error::InstructionError, AccountMeta, Instruction};
use solana_keypair::{Keypair, Signer};
use solana_loader_v3_interface::state::UpgradeableLoaderState;
use solana_message::{v1, VersionedMessage};
use solana_transaction::versioned::VersionedTransaction;
use solana_transaction_error::TransactionError;
use zolana_hasher::primitives::right_align;
use zolana_interface::{BPF_LOADER_UPGRADEABLE_ID, RING_AUTH_PDA_SEED};
use zolana_ring_policy::{ListId, OutflowLimit, Rule, RuleTable, Subject};

/// Any address serves as the ring program.
pub const PROGRAM: Address = Address::new_from_array([0x52; 32]);
pub const SYSTEM: Address = Address::new_from_array([0; 32]);
const LOADER: Address = Address::new_from_array(BPF_LOADER_UPGRADEABLE_ID);
const SOL: u64 = 1_000_000_000;
/// What `ComputeBudgetConfig` writes for a ring proof instruction.
const UNITS: u32 = 1_400_000;
const LOADED_ACCOUNTS_DATA: u32 = 64 * 1024 * 1024;

pub fn pda(seed: &[u8]) -> Address {
    Address::find_program_address(&[seed], &PROGRAM).0
}

pub fn config_pda() -> Address {
    pda(CONFIG_PDA_SEED)
}

pub fn registry_pda() -> Address {
    pda(MEMBER_REGISTRY_PDA_SEED)
}

pub fn queue_pda() -> Address {
    pda(RECORD_QUEUE_PDA_SEED)
}

pub fn ring_auth() -> Address {
    pda(RING_AUTH_PDA_SEED)
}

pub fn program_data() -> Address {
    Address::find_program_address(&[PROGRAM.as_ref()], &LOADER).0
}

#[derive(Clone, Copy)]
pub enum Setup {
    AuditOnly,
    Policy,
    /// A policy with an outflow limit row, the approval flag needs one.
    LimitedPolicy,
    Anonymous,
    AnonymousPolicy,
}

impl Setup {
    pub const fn kind(self) -> RingKind {
        match self {
            Self::AuditOnly => RingKind::AuditOnly,
            Self::Policy | Self::LimitedPolicy => RingKind::Policy,
            Self::Anonymous => RingKind::Anonymous,
            Self::AnonymousPolicy => RingKind::AnonymousPolicy,
        }
    }
}

pub type Sent = Result<u64, (TransactionError, u64)>;

pub struct Ring {
    svm: LiteSVM,
    pub payer: Keypair,
    pub authority: Keypair,
}

impl Ring {
    /// A deployed ring whose config, registry and policy came through their instructions.
    pub fn new(setup: Setup) -> Self {
        let mut svm = LiteSVM::new();
        svm.add_program(PROGRAM, &program_bytes())
            .expect("load the ring program");
        let payer = Keypair::new();
        let authority = Keypair::new();
        for wallet in [&payer, &authority] {
            svm.airdrop(&wallet.pubkey(), 100 * SOL)
                .expect("fund the wallet");
        }
        let mut ring = Self {
            svm,
            payer,
            authority,
        };
        ring.set_upgrade_authority();
        let authority = ring.authority.insecure_clone();
        let config = create_config(
            &ring.payer.pubkey(),
            &authority.pubkey(),
            CreateConfigIxData {
                auditor_pubkey: auditor_pubkey(),
                kind: setup.kind(),
            },
        );
        within_budget(
            InstructionTag::CreateConfig,
            ring.send(config, &[&authority]),
        );
        let registry = create_member_registry(&ring.payer.pubkey(), &authority.pubkey());
        within_budget(
            InstructionTag::CreateMemberRegistry,
            ring.send(registry, &[&authority]),
        );
        let limits = match setup {
            Setup::LimitedPolicy => vec![OutflowLimit {
                asset: [7; 32],
                cap: 0,
                cosign_above: 1_000,
            }],
            _ => Vec::new(),
        };
        if setup.kind().has_policy() {
            let policy = policy_write(
                tag::CREATE_POLICY,
                &authority.pubkey(),
                allow_list_table(limits),
                &[],
            );
            within_budget(
                InstructionTag::CreatePolicy,
                ring.send(policy, &[&authority]),
            );
        }
        ring
    }

    pub fn send(&mut self, instruction: Instruction, signers: &[&Keypair]) -> Sent {
        self.svm.expire_blockhash();
        let message = v1::Message::try_compile_with_config(
            &self.payer.pubkey(),
            &[instruction],
            self.svm.latest_blockhash(),
            v1::TransactionConfig::empty()
                .with_compute_unit_limit(UNITS)
                .with_loaded_accounts_data_size_limit(LOADED_ACCOUNTS_DATA),
        )
        .expect("compile the v1 message");
        let mut keys: Vec<&dyn Signer> = vec![&self.payer];
        for signer in signers {
            if !keys.iter().any(|key| key.pubkey() == signer.pubkey()) {
                keys.push(*signer);
            }
        }
        let transaction = VersionedTransaction::try_new(VersionedMessage::V1(message), &keys)
            .expect("sign the v1 transaction");
        self.svm
            .send_transaction(transaction)
            .map(|meta| meta.compute_units_consumed)
            .map_err(|failed| (failed.err, failed.meta.compute_units_consumed))
    }

    pub fn read<T: Pod>(&self, address: &Address) -> T {
        let account = self.svm.get_account(address).expect("account exists");
        *bytemuck::from_bytes(&account.data)
    }

    pub fn lamports(&self, address: &Address) -> u64 {
        self.svm.get_balance(address).unwrap_or_default()
    }

    pub fn rent_exempt_minimum(&self, len: usize) -> u64 {
        self.svm.minimum_balance_for_rent_exemption(len)
    }

    /// Replaces a program account's data, the state a sequence of instructions would reach.
    pub fn write<T: Pod>(&mut self, address: &Address, value: &T) {
        self.store(*address, PROGRAM, bytemuck::bytes_of(value).to_vec());
    }

    pub fn store(&mut self, address: Address, owner: Address, data: Vec<u8>) {
        let account = Account {
            lamports: self.svm.minimum_balance_for_rent_exemption(data.len()),
            data,
            owner,
            executable: false,
            rent_epoch: 0,
        };
        self.svm
            .set_account(address, account)
            .expect("store the account");
    }

    pub fn fund(&mut self, address: &Address) {
        self.svm.airdrop(address, SOL).expect("fund the account");
    }

    /// Leaves `address` an empty system account.
    pub fn drain(&mut self, address: &Address) {
        self.svm
            .set_account(*address, Account::default())
            .expect("drain the account");
    }

    pub fn fee(&self) -> Fee {
        Fee {
            payer: self.payer.pubkey(),
            recipient: self.authority.pubkey(),
        }
    }

    /// An executable account at `address`, for refusals that precede any CPI into it.
    pub fn deploy_stand_in(&mut self, address: Address) {
        self.svm
            .add_program(address, &program_bytes())
            .expect("load the stand-in");
    }

    pub fn warp(&mut self, slot: u64) {
        self.svm.warp_to_slot(slot);
    }

    /// litesvm deploys with no upgrade authority, `CreateConfig` needs one.
    fn set_upgrade_authority(&mut self) {
        let program_data = program_data();
        let mut account = self
            .svm
            .get_account(&program_data)
            .expect("the deploy writes program data");
        let metadata = bincode::serde::encode_to_vec(
            UpgradeableLoaderState::ProgramData {
                slot: 0,
                upgrade_authority_address: Some(self.authority.pubkey()),
            },
            bincode::config::legacy(),
        )
        .expect("encode the loader state");
        account.data[..metadata.len()].copy_from_slice(&metadata);
        self.svm
            .set_account(program_data, account)
            .expect("store the program data");
    }
}

/// The `b` point of groth16-solana's own proof fixture, big-endian and uncompressed.
pub fn on_curve_g2() -> [u8; 128] {
    hex::decode("2839e9cdb42e236fd705175d0c4776e1072ef7932f826abdb85092678d34f21900cb7cb06e2297d442b4ee97ecbd85d11189cdb7a8c45c9f4bae51a81256b038101ad21412517a8e683efba9628d15fd3282b60f216de41f4fb75893ae6c04160e81a80650f6fe64da835e31f7d303f516c8b15b3c9093ae5a1113bd3e939812")
        .unwrap()
        .try_into()
        .unwrap()
}

/// A canonical compressed `x` off the curve.
pub fn off_curve_g1() -> [u8; 32] {
    (1..=u8::MAX)
        .map(|x| {
            let mut point = [0u8; 32];
            point[31] = x;
            point
        })
        .find(|point| alt_bn128_g1_decompress_be(point).is_err())
        .expect("a canonical x off the curve")
}

/// A canonical compressed `x` off the curve.
pub fn off_curve_g2() -> [u8; 64] {
    (1..=u8::MAX)
        .map(|x| {
            let mut point = [0u8; 64];
            point[63] = x;
            point
        })
        .find(|point| alt_bn128_g2_decompress_be(point).is_err())
        .expect("a canonical x off the curve")
}

/// The SBF build, `SBF_OUT_DIR` when set, else the workspace deploy directory.
fn program_bytes() -> Vec<u8> {
    let dir = std::env::var("SBF_OUT_DIR")
        .unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/deploy").into());
    let path = format!("{dir}/custom_ring_program.so");
    std::fs::read(&path).unwrap_or_else(|_| panic!("build the ring program into {path}"))
}

pub fn auditor_pubkey() -> [u8; 33] {
    let secret = x25519_dalek::StaticSecret::from([9u8; 32]);
    custom_ring_interface::tagged_x25519(x25519_dalek::PublicKey::from(&secret).as_bytes())
}

pub fn allow_list_table(limits: Vec<OutflowLimit>) -> PolicyTableIxData {
    list_table(ListId::Allow, limits)
}

/// One rule requiring `list` of every output owner, sourced from the ring's own registry.
pub fn list_table(list: ListId, limits: Vec<OutflowLimit>) -> PolicyTableIxData {
    let table = RuleTable::builder()
        .rule(Rule::require(Subject::OutputOwner, list))
        .build()
        .encode();
    PolicyTableIxData {
        sources: vec![SourceSpec {
            list_id: list as u8,
            source: 0,
        }],
        rules: table.rules[..usize::from(table.rule_count)].to_vec(),
        inline_assets: Vec::new(),
        inline_limits: Vec::new(),
        limits,
    }
}

pub fn refused(sent: Sent, error: CustomRingError) {
    refused_with(sent, InstructionError::Custom(error as u32));
}

pub fn refused_with(sent: Sent, error: InstructionError) {
    let expected = TransactionError::InstructionError(0, error);
    match sent {
        Err((actual, _)) => assert_eq!(actual, expected),
        Ok(units) => panic!("accepted after {units} units, expected {expected:?}"),
    }
}

pub fn within_budget(tag: InstructionTag, sent: Sent) -> u64 {
    let units = sent.unwrap_or_else(|refusal| panic!("{tag:?} refused {refusal:?}"));
    assert!(
        units <= u64::from(compute_unit_limit(tag)),
        "{tag:?} spent {units}"
    );
    units
}

/// History slot 1 applied at `applied` under `floor`.
pub fn floored(base: &MemberRegistry, applied: u64, floor: u64) -> MemberRegistry {
    let mut registry = *base;
    registry.push_root([0x0f; 32], AppliedAt { applied, slot: 10 });
    registry.floor = floor.to_le_bytes();
    registry
}

/// Only a ring proof check raises either code, every earlier check passed.
pub fn reaches_verification(sent: Sent) -> u64 {
    let proof_check = [
        CustomRingError::InvalidRingProofPoint,
        CustomRingError::ProofVerificationFailed,
    ];
    match sent {
        Err((TransactionError::InstructionError(0, InstructionError::Custom(code)), units))
            if proof_check.iter().any(|error| *error as u32 == code) =>
        {
            units
        }
        other => panic!("expected the proof check, got {other:?}"),
    }
}

fn instruction(accounts: Vec<AccountMeta>, data: Vec<u8>) -> Instruction {
    Instruction {
        program_id: PROGRAM,
        accounts,
        data,
    }
}

fn tagged(tag: u8, body: &[u8]) -> Vec<u8> {
    [&[tag][..], body].concat()
}

pub fn create_config(
    payer: &Address,
    authority: &Address,
    data: CreateConfigIxData,
) -> Instruction {
    instruction(
        vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new_readonly(*authority, true),
            AccountMeta::new(config_pda(), false),
            AccountMeta::new_readonly(SYSTEM, false),
            AccountMeta::new_readonly(PROGRAM, false),
            AccountMeta::new_readonly(program_data(), false),
        ],
        tagged(tag::CREATE_CONFIG, &wincode::serialize(&data).unwrap()),
    )
}

pub fn create_member_registry(payer: &Address, authority: &Address) -> Instruction {
    instruction(
        vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new_readonly(*authority, true),
            AccountMeta::new_readonly(config_pda(), false),
            AccountMeta::new(registry_pda(), false),
            AccountMeta::new(queue_pda(), false),
            AccountMeta::new_readonly(SYSTEM, false),
        ],
        vec![tag::CREATE_MEMBER_REGISTRY],
    )
}

/// `CreatePolicy` or `SetPolicyRules`, curators follow the registry.
pub fn policy_write(
    tag: u8,
    authority: &Address,
    table: PolicyTableIxData,
    curators: &[Address],
) -> Instruction {
    let mut accounts = vec![
        AccountMeta::new_readonly(*authority, true),
        AccountMeta::new_readonly(config_pda(), false),
        AccountMeta::new(registry_pda(), false),
    ];
    accounts.extend(
        curators
            .iter()
            .map(|curator| AccountMeta::new_readonly(*curator, false)),
    );
    instruction(accounts, tagged(tag, &wincode::serialize(&table).unwrap()))
}

pub fn config_write(
    tag: u8,
    authority: &Address,
    extra: &[AccountMeta],
    body: &[u8],
) -> Instruction {
    let mut accounts = vec![
        AccountMeta::new_readonly(*authority, true),
        AccountMeta::new(config_pda(), false),
    ];
    accounts.extend_from_slice(extra);
    instruction(accounts, tagged(tag, body))
}

#[derive(Clone, Copy)]
pub struct Fee {
    pub payer: Address,
    pub recipient: Address,
}

fn record_write(tag: u8, signer: &Address, fee: Option<Fee>, body: &[u8]) -> Instruction {
    let mut accounts = vec![
        AccountMeta::new_readonly(*signer, true),
        AccountMeta::new_readonly(config_pda(), false),
        AccountMeta::new_readonly(registry_pda(), false),
        AccountMeta::new(queue_pda(), false),
    ];
    if let Some(fee) = fee {
        accounts.extend([
            AccountMeta::new(fee.payer, true),
            AccountMeta::new(fee.recipient, false),
            AccountMeta::new_readonly(SYSTEM, false),
        ]);
    }
    instruction(accounts, tagged(tag, body))
}

/// A member write accepting any insert fee.
pub fn write_records(member: &Address, lists: WriteRecordsIxData, fee: Option<Fee>) -> Instruction {
    let data = MemberWriteIxData {
        lists,
        max_fee: u64::MAX.to_le_bytes(),
    };
    member_write(member, &data, fee)
}

pub fn member_write(member: &Address, data: &MemberWriteIxData, fee: Option<Fee>) -> Instruction {
    record_write(tag::WRITE_RECORDS, member, fee, bytemuck::bytes_of(data))
}

pub fn register_key(member: &Address, data: &RegisterKeyIxData, fee: Option<Fee>) -> Instruction {
    record_write(tag::REGISTER_KEY, member, fee, bytemuck::bytes_of(data))
}

/// Accepts any insert fee.
pub fn key_registration() -> RegisterKeyIxData {
    RegisterKeyIxData {
        proof: Zeroable::zeroed(),
        nullifier_pk: right_align(&[4]),
        eph_u: [5; 32],
        ciphertext: [6; 32],
        max_fee: u64::MAX.to_le_bytes(),
    }
}

pub fn authority_write_records(
    authority: &Address,
    writes: &[RecordWriteData],
    apply: &ApplyRecordsIxData,
) -> Instruction {
    instruction(
        vec![
            AccountMeta::new_readonly(*authority, true),
            AccountMeta::new_readonly(config_pda(), false),
            AccountMeta::new(registry_pda(), false),
            AccountMeta::new(queue_pda(), false),
        ],
        tagged(
            tag::AUTHORITY_WRITE_RECORDS,
            &AuthorityWriteRecordsIxData { writes, apply }
                .encode()
                .expect("one to sixteen writes"),
        ),
    )
}

pub fn apply_records(apply: &ApplyRecordsIxData) -> Instruction {
    instruction(
        vec![
            AccountMeta::new(registry_pda(), false),
            AccountMeta::new(queue_pda(), false),
        ],
        tagged(tag::APPLY_RECORDS, bytemuck::bytes_of(apply)),
    )
}

pub fn transact(tag: u8, accounts: Vec<AccountMeta>, data: Vec<u8>) -> Instruction {
    instruction(accounts, tagged(tag, &data))
}

/// `SetDelegate` signed by `authority` and `delegate`, accepted only from the upgrade authority.
pub fn set_delegate(authority: &Address, delegate: &Address) -> Instruction {
    config_write(
        tag::SET_DELEGATE,
        authority,
        &[
            AccountMeta::new_readonly(*delegate, true),
            AccountMeta::new_readonly(registry_pda(), false),
            AccountMeta::new_readonly(PROGRAM, false),
            AccountMeta::new_readonly(program_data(), false),
        ],
        &[],
    )
}

/// A policy ring whose delegate put it in registry mode.
pub fn delegate_ring(delegate: &Keypair) -> Ring {
    let mut ring = Ring::new(Setup::Policy);
    let authority = ring.authority.insecure_clone();
    within_budget(
        InstructionTag::SetDelegate,
        ring.send(
            set_delegate(&authority.pubkey(), &delegate.pubkey()),
            &[&authority, delegate],
        ),
    );
    ring
}
