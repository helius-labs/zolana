//! Every proofless builder against the account order, privileges and data its processor parses.

use async_trait::async_trait;
use curve25519_dalek::constants::{ED25519_BASEPOINT_POINT, EIGHT_TORSION};
use custom_ring_interface::{
    CreateConfigIxData, CustomRingMergeIxData, CustomRingMergeIxDataRef, MergeDisclosure,
    PolicyTableIxData, ReadAccessRecord, ReaderIxData, RingMode, RingProgramConfig,
    SetCoSignerIxData, SetInsertFeeIxData, SetPausedIxData, SetPolicySourceIxData, SourceSpec,
    WithdrawalThreshold, WriteRecordsIxData, AUDIT_CIPHERTEXT_LEN, DEFAULT_INSERT_FEE,
    READ_ACCESS_RECORD_PDA_SEED, RING_PROGRAM_CONFIG,
};
use custom_ring_sdk::{
    tag, CoSignScope, CoSignThreshold, CustomRing, CustomRingConfig, CustomRingMergeInstruction,
    MemberListWrite, RingError, RingSetup, SourceOwner,
};
use solana_account::Account;
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use wincode::{config::DefaultConfig, SchemaRead};
use zolana_client::{AsyncRpc, ClientError};
use zolana_hasher::primitives::solana_owner_identity;
use zolana_interface::{
    instruction::instruction_data::merge_transact::{
        MergeOutputEncryption, MergeProof, MergeTransactIxData,
    },
    pda, BPF_LOADER_UPGRADEABLE_ID, SOL_ASSET_FIELD,
};
use zolana_keypair::{SigningKey, X25519Keypair};
use zolana_program::instruction::MergeRing;
use zolana_ring_client::ReaderKey;
use zolana_ring_policy::{
    ListId, ListSet, ListWrite, OutflowLimit, PolicyTableError, Rule, RuleTable, RuleTableError,
    Subject, TableParts, Writer,
};

/// The system program is the all-zero address.
const SYSTEM: Address = Address::new_from_array([0; 32]);

fn program() -> Address {
    Address::new_from_array([10; 32])
}

fn ring() -> CustomRing {
    CustomRing::new(program())
}

fn payer() -> Address {
    Address::new_from_array([11; 32])
}

fn authority() -> Address {
    Address::new_from_array([12; 32])
}

/// SPP's own derivation, independent of the builder's.
fn ring_auth() -> Address {
    pda::ring_auth(&program()).0
}

/// The loader's derivation `UpgradeAuthorityCheck` reads the upgrade authority from.
fn program_data() -> Address {
    Address::find_program_address(
        &[program().as_ref()],
        &Address::new_from_array(BPF_LOADER_UPGRADEABLE_ID),
    )
    .0
}

fn reader() -> ReaderKey {
    let key = SigningKey::from_ed25519_bytes(&[23; 32])
        .pubkey()
        .as_ed25519()
        .unwrap();
    ReaderKey::ed25519(Address::new_from_array(key)).unwrap()
}

fn split(instruction: &Instruction) -> (u8, &[u8]) {
    let (ix_tag, body) = instruction.data.split_first().unwrap();
    (*ix_tag, body)
}

/// The program's own decoder of a wincode body.
fn parse<'a, T: SchemaRead<'a, DefaultConfig, Dst = T>>(body: &'a [u8]) -> T {
    wincode::deserialize_exact(body).unwrap()
}

/// Serves the one config account a member write reads.
struct ConfigRpc(Account);

#[async_trait]
impl AsyncRpc for ConfigRpc {
    async fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
        Ok((address == ring().config_pda()).then(|| self.0.clone()))
    }
}

async fn config(insert_fee: u64) -> CustomRingConfig {
    let (_, bump) = Address::find_program_address(&[RingProgramConfig::SEED], &program());
    let account = RingProgramConfig {
        discriminator: RING_PROGRAM_CONFIG,
        authority: authority(),
        auditor_pubkey: *X25519Keypair::from_bytes(&[5; 32]).pubkey().as_bytes(),
        bump,
        has_policy: 1,
        mode: RingMode::Registry as u8,
        insert_fee: insert_fee.to_le_bytes(),
        ..bytemuck::Zeroable::zeroed()
    };
    let rpc = ConfigRpc(Account {
        lamports: 1,
        data: bytemuck::bytes_of(&account).to_vec(),
        owner: program(),
        executable: false,
        rent_epoch: 0,
    });
    ring().config(&rpc).await.unwrap().unwrap()
}

#[test]
fn create_config_runs_under_the_upgrade_authority_with_the_ring_setup() {
    let auditor_pubkey = X25519Keypair::from_bytes(&[5; 32]).pubkey();
    for (has_policy, anonymous) in [(true, false), (false, true)] {
        let setup = RingSetup {
            auditor_pubkey,
            has_policy,
            anonymous,
        };
        let instruction = ring().create_config(payer(), authority(), setup).unwrap();
        assert_eq!(instruction.program_id, program());
        assert_eq!(
            instruction.accounts,
            vec![
                AccountMeta::new(payer(), true),
                AccountMeta::new_readonly(authority(), true),
                AccountMeta::new(ring().config_pda(), false),
                AccountMeta::new_readonly(SYSTEM, false),
                AccountMeta::new_readonly(program(), false),
                AccountMeta::new_readonly(program_data(), false),
            ]
        );
        let (ix_tag, body) = split(&instruction);
        assert_eq!(ix_tag, tag::CREATE_CONFIG);
        assert_eq!(
            parse::<CreateConfigIxData>(body),
            CreateConfigIxData {
                auditor_pubkey: *auditor_pubkey.as_bytes(),
                has_policy,
                anonymous,
            }
        );
    }
}

#[test]
fn init_spp_ring_config_appends_the_registry_only_on_a_policy_ring() {
    let audit_only = ring().init_spp_ring_config(payer(), authority(), false);
    let accounts = vec![
        AccountMeta::new(payer(), true),
        AccountMeta::new_readonly(authority(), true),
        AccountMeta::new_readonly(ring().config_pda(), false),
        AccountMeta::new_readonly(pda::protocol_config(), false),
        AccountMeta::new(ring_auth(), false),
        AccountMeta::new_readonly(SYSTEM, false),
        AccountMeta::new_readonly(pda::shielded_pool_program_id(), false),
    ];
    assert_eq!(audit_only.accounts, accounts);
    assert_eq!(audit_only.data, [tag::INIT_SPP_RING_CONFIG]);
    let policy = ring().init_spp_ring_config(payer(), authority(), true);
    assert_eq!(
        policy.accounts,
        [
            accounts,
            vec![AccountMeta::new_readonly(ring().registry_pda(), false)]
        ]
        .concat()
    );
    assert_eq!(policy.data, [tag::INIT_SPP_RING_CONFIG]);
}

#[test]
fn create_member_registry_reads_the_config_and_creates_the_registry_and_its_queue() {
    let instruction = ring().create_member_registry(payer(), authority());
    assert_eq!(
        instruction.accounts,
        vec![
            AccountMeta::new(payer(), true),
            AccountMeta::new_readonly(authority(), true),
            AccountMeta::new_readonly(ring().config_pda(), false),
            AccountMeta::new(ring().registry_pda(), false),
            AccountMeta::new(ring().queue_pda(), false),
            AccountMeta::new_readonly(SYSTEM, false),
        ]
    );
    assert_eq!(instruction.data, [tag::CREATE_MEMBER_REGISTRY]);
}

#[test]
fn a_read_access_record_sits_at_the_program_pda_of_the_tagged_reader() {
    let seed_hash = ReadAccessRecord::seed_hash(&reader().to_bytes()).unwrap();
    let record =
        Address::find_program_address(&[READ_ACCESS_RECORD_PDA_SEED, &seed_hash], &program()).0;
    let grant = ring()
        .grant_read_access(payer(), authority(), reader())
        .unwrap();
    assert_eq!(
        grant.accounts,
        vec![
            AccountMeta::new(payer(), true),
            AccountMeta::new_readonly(authority(), true),
            AccountMeta::new_readonly(ring().config_pda(), false),
            AccountMeta::new(record, false),
            AccountMeta::new_readonly(SYSTEM, false),
        ]
    );
    let (ix_tag, body) = split(&grant);
    assert_eq!(ix_tag, tag::GRANT_READ_ACCESS);
    assert_eq!(parse::<ReaderIxData>(body).reader, reader().to_bytes());

    let rent_recipient = Address::new_from_array([24; 32]);
    let revoke = ring()
        .revoke_read_access(authority(), reader(), rent_recipient)
        .unwrap();
    assert_eq!(
        revoke.accounts,
        vec![
            AccountMeta::new_readonly(authority(), true),
            AccountMeta::new_readonly(ring().config_pda(), false),
            AccountMeta::new(record, false),
            AccountMeta::new(rent_recipient, false),
        ]
    );
    let (ix_tag, body) = split(&revoke);
    assert_eq!(ix_tag, tag::REVOKE_READ_ACCESS);
    assert_eq!(parse::<ReaderIxData>(body).reader, reader().to_bytes());
}

#[test]
fn a_grant_takes_only_a_canonical_prime_order_ed25519_reader() {
    let mut small_order = [0; 32];
    small_order[0] = 1;
    let mut noncanonical = [0xff; 32];
    noncanonical[0] = 0xee;
    noncanonical[31] = 0x7f;
    let mixed_torsion = (ED25519_BASEPOINT_POINT + EIGHT_TORSION[1])
        .compress()
        .to_bytes();
    for key in [small_order, noncanonical, mixed_torsion] {
        assert!(ReaderKey::ed25519(Address::new_from_array(key)).is_err());
    }
}

#[test]
fn set_authority_takes_both_signers() {
    let new_authority = Address::new_from_array([31; 32]);
    let instruction = ring().set_authority(authority(), new_authority);
    assert_eq!(
        instruction.accounts,
        vec![
            AccountMeta::new_readonly(authority(), true),
            AccountMeta::new_readonly(new_authority, true),
            AccountMeta::new(ring().config_pda(), false),
        ]
    );
    assert_eq!(instruction.data, [tag::SET_AUTHORITY]);
}

#[test]
fn set_paused_reaches_spp_through_the_ring_auth() {
    for paused in [true, false] {
        let instruction = ring().set_paused(authority(), paused).unwrap();
        assert_eq!(
            instruction.accounts,
            vec![
                AccountMeta::new_readonly(authority(), true),
                AccountMeta::new_readonly(ring().config_pda(), false),
                AccountMeta::new(ring_auth(), false),
                AccountMeta::new_readonly(pda::shielded_pool_program_id(), false),
            ]
        );
        let (ix_tag, body) = split(&instruction);
        assert_eq!(ix_tag, tag::SET_PAUSED);
        assert_eq!(parse::<SetPausedIxData>(body), SetPausedIxData { paused });
    }
}

#[test]
fn co_signer_writes_take_the_authority_and_the_writable_config() {
    let config_write = vec![
        AccountMeta::new_readonly(authority(), true),
        AccountMeta::new(ring().config_pda(), false),
    ];
    let signer = Address::new_from_array([32; 32]);
    let mint = Address::new_from_array([33; 32]);
    let thresholds = [
        CoSignThreshold { mint, amount: 100 },
        CoSignThreshold {
            mint: Address::default(),
            amount: 5,
        },
    ];
    let scope = CoSignScope::TRANSFERS | CoSignScope::WITHDRAWALS;
    let set = ring()
        .set_cosigner(authority(), signer, scope, &thresholds)
        .unwrap();
    assert_eq!(set.accounts, config_write);
    let (ix_tag, body) = split(&set);
    assert_eq!(ix_tag, tag::SET_CO_SIGNER);
    assert_eq!(
        parse::<SetCoSignerIxData>(body),
        SetCoSignerIxData {
            signer: signer.to_bytes(),
            scope: scope.bits(),
            thresholds: vec![
                WithdrawalThreshold {
                    mint: mint.to_bytes(),
                    amount: 100,
                },
                WithdrawalThreshold {
                    mint: [0; 32],
                    amount: 5,
                },
            ],
        }
    );
    let clear = ring().clear_cosigner(authority());
    assert_eq!(clear.accounts, config_write);
    assert_eq!(clear.data, [tag::CLEAR_CO_SIGNER]);
}

#[test]
fn set_insert_fee_writes_the_fee_into_the_config() {
    let fee = 3 * DEFAULT_INSERT_FEE;
    let instruction = ring().set_insert_fee(authority(), fee);
    assert_eq!(
        instruction.accounts,
        vec![
            AccountMeta::new_readonly(authority(), true),
            AccountMeta::new(ring().config_pda(), false),
        ]
    );
    let (ix_tag, body) = split(&instruction);
    assert_eq!(ix_tag, tag::SET_INSERT_FEE);
    assert_eq!(
        SetInsertFeeIxData::parse(body).unwrap().fee,
        fee.to_le_bytes()
    );
}

#[test]
fn set_delegate_runs_under_the_upgrade_authority_beside_the_registry() {
    let delegate = Address::new_from_array([34; 32]);
    let instruction = ring().set_delegate(authority(), delegate);
    assert_eq!(
        instruction.accounts,
        vec![
            AccountMeta::new_readonly(authority(), true),
            AccountMeta::new(ring().config_pda(), false),
            AccountMeta::new_readonly(ring().registry_pda(), false),
            AccountMeta::new_readonly(program(), false),
            AccountMeta::new_readonly(program_data(), false),
        ]
    );
    let (ix_tag, body) = split(&instruction);
    assert_eq!(ix_tag, tag::SET_DELEGATE);
    assert_eq!(body, delegate.as_array());
}

#[test]
fn a_policy_source_names_a_curator_registry_only_when_shared() {
    let policy_write = vec![
        AccountMeta::new_readonly(authority(), true),
        AccountMeta::new_readonly(ring().config_pda(), false),
        AccountMeta::new(ring().registry_pda(), false),
    ];
    let curator = CustomRing::new(Address::new_from_array([35; 32]));
    for (owner, source, curators) in [
        (SourceOwner::Own, 0, vec![]),
        (
            SourceOwner::Shared(curator),
            1,
            vec![AccountMeta::new_readonly(curator.registry_pda(), false)],
        ),
    ] {
        let instruction = ring()
            .set_source_owner(authority(), ListId::Allow, owner)
            .unwrap();
        assert_eq!(
            instruction.accounts,
            [policy_write.clone(), curators].concat()
        );
        let (ix_tag, body) = split(&instruction);
        assert_eq!(ix_tag, tag::SET_POLICY_SOURCE);
        assert_eq!(
            parse::<SetPolicySourceIxData>(body),
            SetPolicySourceIxData {
                list_id: ListId::Allow as u8,
                source,
            }
        );
    }
}

#[test]
fn a_policy_table_names_its_curator_once_and_reproduces_the_pinned_table() {
    let rules = RuleTable::builder()
        .rule(Rule::require(Subject::Sender, ListId::Allow))
        .rule(Rule::forbid(Subject::Sender, ListId::Block))
        .rule(Rule::forbid(Subject::OutputOwner, ListId::Frozen))
        .limits(&[OutflowLimit {
            asset: SOL_ASSET_FIELD,
            cap: 1_000,
            cosign_above: 500,
        }])
        .build();
    let curator = CustomRing::new(Address::new_from_array([36; 32]));
    let shared = [(ListId::Frozen, curator), (ListId::Allow, curator)];
    for (instruction, ix_tag) in [
        (
            ring().create_policy(authority(), &rules, &shared).unwrap(),
            tag::CREATE_POLICY,
        ),
        (
            ring()
                .set_policy_rules(authority(), &rules, &shared)
                .unwrap(),
            tag::SET_POLICY_RULES,
        ),
    ] {
        assert_eq!(
            instruction.accounts,
            vec![
                AccountMeta::new_readonly(authority(), true),
                AccountMeta::new_readonly(ring().config_pda(), false),
                AccountMeta::new(ring().registry_pda(), false),
                AccountMeta::new_readonly(curator.registry_pda(), false),
            ]
        );
        let (found, body) = split(&instruction);
        assert_eq!(found, ix_tag);
        let table: PolicyTableIxData = parse(body);
        assert_eq!(
            table.sources,
            [(ListId::Allow, 1), (ListId::Block, 0), (ListId::Frozen, 1)].map(
                |(list_id, source)| SourceSpec {
                    list_id: list_id as u8,
                    source,
                }
            )
        );
        let stored = TableParts {
            rows: &table.rules,
            inline_assets: &table.inline_assets,
            inline_limits: &table.inline_limits,
            limits: &table.limits,
        }
        .encode()
        .unwrap();
        assert_eq!(stored, rules.encode());
    }
}

#[test]
fn a_shared_source_for_a_list_no_rule_reads_is_refused() {
    let rules = RuleTable::builder()
        .rule(Rule::require(Subject::Sender, ListId::Allow))
        .build();
    let curator = CustomRing::new(Address::new_from_array([37; 32]));
    assert!(matches!(
        ring().create_policy(authority(), &rules, &[(ListId::Reader, curator)]),
        Err(RingError::UnreferencedList(ListId::Reader))
    ));
}

#[test]
fn a_rule_over_a_list_members_write_is_refused_before_the_transaction() {
    let rules = RuleTable::builder()
        .rule(Rule::require(Subject::Sender, ListId::RingViewing))
        .build();
    assert!(matches!(
        ring().create_policy(authority(), &rules, &[]),
        Err(RingError::PolicyTable(PolicyTableError::Table(
            RuleTableError::MemberWrittenList
        )))
    ));
}

#[tokio::test]
async fn a_member_list_write_pays_the_insert_fee_only_when_it_owes_one() {
    let member = Address::new_from_array([40; 32]);
    let lists = ListWrite::new(
        ListSet::single(ListId::RingViewing),
        ListSet::single(ListId::Recovery),
    )
    .unwrap();
    let write = |member| MemberListWrite {
        ring: ring(),
        payer: payer(),
        member,
        lists,
    };
    let record = |member| {
        vec![
            AccountMeta::new_readonly(member, true),
            AccountMeta::new_readonly(ring().config_pda(), false),
            AccountMeta::new_readonly(ring().registry_pda(), false),
            AccountMeta::new(ring().queue_pda(), false),
        ]
    };
    let owed = config(DEFAULT_INSERT_FEE).await;
    let instruction = write(member).instruction(&owed).unwrap();
    assert_eq!(
        instruction.accounts,
        [
            record(member),
            vec![
                AccountMeta::new(payer(), true),
                AccountMeta::new(authority(), false),
                AccountMeta::new_readonly(SYSTEM, false),
            ]
        ]
        .concat()
    );
    let (ix_tag, body) = split(&instruction);
    assert_eq!(ix_tag, tag::WRITE_RECORDS);
    let data = WriteRecordsIxData::parse(body).unwrap();
    assert_eq!((data.mask(), data.value()), (lists.mask(), lists.value()));
    let identity = solana_owner_identity(member.as_array()).unwrap();
    data.entry(identity, Writer::Member).unwrap();

    let by_authority = write(authority()).instruction(&owed).unwrap();
    assert_eq!(by_authority.accounts, record(authority()));
    let free = config(0).await;
    assert_eq!(
        write(member).instruction(&free).unwrap().accounts,
        record(member)
    );
}

#[tokio::test]
async fn a_member_list_write_refuses_a_list_the_authority_writes() {
    let lists = ListWrite::new(ListSet::single(ListId::Allow), ListSet::EMPTY).unwrap();
    let write = MemberListWrite {
        ring: ring(),
        payer: payer(),
        member: Address::new_from_array([41; 32]),
        lists,
    };
    assert!(matches!(
        write.instruction(&config(DEFAULT_INSERT_FEE).await),
        Err(RingError::ListNotWritable {
            list: ListId::Allow,
            writer: Writer::Member,
        })
    ));
}

#[test]
fn an_anonymous_merge_names_no_registry() {
    let (input_tree, output_tree) = (pda::tree(1), pda::tree(2));
    let merge = MergeTransactIxData {
        expiry_unix_ts: u64::MAX,
        proof: MergeProof::zeroed(),
        output_utxo_hash: [0; 32],
        output_encryption: MergeOutputEncryption::PoseidonCtrV1 {
            salt: [0; 16],
            ciphertext: [[0; 32]; 3],
        },
        private_tx_hash: [0; 32],
        nullifiers: vec![[1; 32]],
        utxo_tree_root_index: 0,
        nullifier_tree_root_index: 0,
        cache_slot: None,
    };
    let spp = MergeRing {
        input_tree,
        output_tree,
        ring_program_id: program(),
        payer: payer(),
        data: merge.clone(),
        output_ring_data_hash: [0; 32],
        member_registry_root: [0; 32],
        anonymous: false,
        cache: None,
    }
    .instruction();
    let instruction = CustomRingMergeInstruction {
        ring: ring(),
        input_tree,
        output_tree,
        payer: payer(),
        co_signer: None,
        data: CustomRingMergeIxData {
            registry_root_index: 0,
            output_ring_data_hash: [0; 32],
            disclosure: Some(MergeDisclosure {
                proof: bytemuck::Zeroable::zeroed(),
                eph_pk: [0; 33],
                ciphertext: [0; AUDIT_CIPHERTEXT_LEN],
                fields: vec![[0; 32]],
            }),
            merge,
        },
    }
    .instruction()
    .unwrap();
    assert_eq!(
        instruction.accounts,
        [
            vec![AccountMeta::new_readonly(ring().config_pda(), false)],
            spp.accounts
        ]
        .concat()
    );
}

#[test]
fn a_merge_names_the_config_the_registry_and_the_co_signer_ahead_of_spp() {
    let (input_tree, output_tree) = (pda::tree(1), pda::tree(2));
    let data = CustomRingMergeIxData {
        registry_root_index: 3,
        output_ring_data_hash: [9; 32],
        disclosure: None,
        merge: MergeTransactIxData {
            expiry_unix_ts: u64::MAX,
            proof: MergeProof::zeroed(),
            output_utxo_hash: [0; 32],
            output_encryption: MergeOutputEncryption::PoseidonCtrV1 {
                salt: [0; 16],
                ciphertext: [[0; 32]; 3],
            },
            private_tx_hash: [0; 32],
            nullifiers: vec![[1; 32], [2; 32]],
            utxo_tree_root_index: 0,
            nullifier_tree_root_index: 0,
            cache_slot: None,
        },
    };
    let spp = MergeRing {
        input_tree,
        output_tree,
        ring_program_id: program(),
        payer: payer(),
        data: data.merge.clone(),
        output_ring_data_hash: data.output_ring_data_hash,
        member_registry_root: [0; 32],
        anonymous: false,
        cache: None,
    }
    .instruction();
    for co_signer in [None, Some(Address::new_from_array([50; 32]))] {
        let instruction = CustomRingMergeInstruction {
            ring: ring(),
            input_tree,
            output_tree,
            payer: payer(),
            co_signer,
            data: data.clone(),
        }
        .instruction()
        .unwrap();
        let mut prefix = vec![
            AccountMeta::new_readonly(ring().config_pda(), false),
            AccountMeta::new_readonly(ring().registry_pda(), false),
        ];
        prefix.extend(co_signer.map(|co_signer| AccountMeta::new_readonly(co_signer, true)));
        assert_eq!(
            instruction.accounts,
            [prefix, spp.accounts.clone()].concat()
        );
        let (ix_tag, body) = split(&instruction);
        assert_eq!(ix_tag, tag::MERGE);
        let parsed = CustomRingMergeIxDataRef::from_bytes(body).unwrap();
        assert_eq!(
            (
                parsed.registry_root_index,
                *parsed.output_ring_data_hash,
                parsed.disclosure
            ),
            (3, [9; 32], None)
        );
    }
}
