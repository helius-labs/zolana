//! Config, policy and read access writes and their declared budgets.

use custom_ring_interface::{
    stream::{tag_epoch, EPOCH_SLOTS},
    tag, CreateConfigIxData, CustomRingError, InstructionTag, MemberRegistry, ReadAccessRecord,
    ReaderIxData, RingKind, RingMode, RingProgramConfig, SetCoSignerIxData, SetPausedIxData,
    SetPolicySourceIxData, WithdrawalThreshold, WriteRecordsIxData, DEFAULT_INSERT_FEE,
    READER_KEY_P256, READ_ACCESS_RECORD_PDA_SEED,
};
use solana_address::Address;
use solana_instruction::{error::InstructionError, AccountMeta, Instruction};
use solana_keypair::{Keypair, Signer};
use solana_transaction_error::TransactionError;
use zolana_account_checks::AccountError;
use zolana_ring_policy::{ListChange, ListId, ListSet};

use crate::common::{
    allow_list_table, auditor_pubkey, config_pda, config_write, create_config,
    create_member_registry, list_table, policy_write, program_data_of, queue_pda, refused,
    refused_with, registry_pda, ring_auth, set_delegate, within_budget, write_records, Fee, Ring,
    Sent, Setup, PROGRAM, SYSTEM,
};
use crate::transact_rules::SPP;

fn set_co_signer_data(signer: [u8; 32], scope: u8, mints: &[[u8; 32]]) -> Vec<u8> {
    wincode::serialize(&SetCoSignerIxData {
        signer,
        scope,
        thresholds: mints
            .iter()
            .map(|mint| WithdrawalThreshold {
                mint: *mint,
                amount: 10,
            })
            .collect(),
    })
    .unwrap()
}

fn authority_send(ring: &mut Ring, instruction: Instruction) -> Sent {
    let authority = ring.authority.insecure_clone();
    ring.send(instruction, &[&authority])
}

#[test]
fn only_the_upgrade_authority_creates_a_config_for_a_usable_auditor_key() {
    let ring = Ring::new(Setup::AuditOnly);
    let config: RingProgramConfig = ring.read(&config_pda());
    assert_eq!(config.authority, ring.authority.pubkey());
    assert_eq!(
        (config.co_signer(), config.delegate(), config.insert_fee()),
        (None, None, DEFAULT_INSERT_FEE)
    );

    let mut fresh = Ring::new(Setup::AuditOnly);
    fresh.store(config_pda(), SYSTEM, Vec::new());
    let stranger = Keypair::new();
    let data = CreateConfigIxData {
        auditor_pubkey: auditor_pubkey(),
        kind: RingKind::AuditOnly,
    };
    let payer = fresh.payer.pubkey();
    refused(
        fresh.send(
            create_config(&payer, &stranger.pubkey(), data),
            &[&stranger],
        ),
        CustomRingError::UnauthorizedInitializer,
    );
    let mut low_order = data;
    low_order.auditor_pubkey[1..].fill(0);
    let authority = fresh.authority.pubkey();
    refused(
        authority_send(&mut fresh, create_config(&payer, &authority, low_order)),
        CustomRingError::InvalidAuditorPubkey,
    );
}

#[test]
fn the_upgrade_authority_comes_from_the_ring_programs_own_program_data() {
    let mut ring = Ring::new(Setup::AuditOnly);
    ring.store(config_pda(), SYSTEM, Vec::new());
    let stranger = Keypair::new();
    let stand_in = Address::new_unique();
    ring.deploy_stand_in(stand_in);
    ring.set_upgrade_authority(&stand_in, &stranger.pubkey());
    let data = CreateConfigIxData {
        auditor_pubkey: auditor_pubkey(),
        kind: RingKind::AuditOnly,
    };
    let payer = ring.payer.pubkey();
    for program in [stand_in, PROGRAM] {
        let mut instruction = create_config(&payer, &stranger.pubkey(), data);
        instruction.accounts[4] = AccountMeta::new_readonly(program, false);
        instruction.accounts[5] = AccountMeta::new_readonly(program_data_of(&stand_in), false);
        refused(
            ring.send(instruction, &[&stranger]),
            CustomRingError::UnauthorizedInitializer,
        );
    }
}

#[test]
fn the_config_records_the_slot_it_was_created_in() {
    let mut ring = Ring::new(Setup::Anonymous);
    ring.store(config_pda(), SYSTEM, Vec::new());
    let created = 3 * EPOCH_SLOTS + 7;
    ring.warp(created);
    let (payer, authority) = (ring.payer.pubkey(), ring.authority.pubkey());
    let data = CreateConfigIxData {
        auditor_pubkey: auditor_pubkey(),
        kind: RingKind::Anonymous,
    };
    authority_send(&mut ring, create_config(&payer, &authority, data))
        .expect("the upgrade authority creates the config");
    let config: RingProgramConfig = ring.read(&config_pda());
    assert_eq!(config.created_slot(), created);
    assert_eq!(tag_epoch(config.created_slot()), 3);
}

#[test]
fn the_co_signer_lives_in_the_config_with_distinct_thresholds() {
    let mut ring = Ring::new(Setup::AuditOnly);
    let authority = ring.authority.pubkey();
    let usdc = [7; 32];
    refused(
        authority_send(
            &mut ring,
            config_write(
                tag::SET_CO_SIGNER,
                &authority,
                &[],
                &set_co_signer_data([1; 32], 0, &[]),
            ),
        ),
        CustomRingError::InvalidCoSignerScope,
    );
    refused(
        authority_send(
            &mut ring,
            config_write(
                tag::SET_CO_SIGNER,
                &authority,
                &[],
                &set_co_signer_data([0; 32], 1, &[]),
            ),
        ),
        CustomRingError::InvalidCoSigner,
    );
    refused(
        authority_send(
            &mut ring,
            config_write(
                tag::SET_CO_SIGNER,
                &authority,
                &[],
                &set_co_signer_data([1; 32], 4, &[usdc, usdc]),
            ),
        ),
        CustomRingError::InvalidCoSignerThresholds,
    );
    refused(
        authority_send(
            &mut ring,
            config_write(
                tag::SET_CO_SIGNER,
                &authority,
                &[],
                &set_co_signer_data([1; 32], 3, &[usdc]),
            ),
        ),
        CustomRingError::ThresholdsWithoutWithdrawals,
    );
    within_budget(
        InstructionTag::SetCoSigner,
        authority_send(
            &mut ring,
            config_write(
                tag::SET_CO_SIGNER,
                &authority,
                &[],
                &set_co_signer_data([1; 32], 4, &[usdc]),
            ),
        ),
    );
    let config: RingProgramConfig = ring.read(&config_pda());
    assert_eq!(config.co_signer(), Some(&Address::new_from_array([1; 32])));
    assert_eq!(config.threshold(&Address::new_from_array(usdc)), Some(10));
    within_budget(
        InstructionTag::ClearCoSigner,
        authority_send(
            &mut ring,
            config_write(tag::CLEAR_CO_SIGNER, &authority, &[], &[]),
        ),
    );
    let config: RingProgramConfig = ring.read(&config_pda());
    assert_eq!((config.co_signer(), config.thresholds().len()), (None, 0));
}

fn appoint(ring: &mut Ring, delegate: &Keypair) -> Sent {
    let authority = ring.authority.insecure_clone();
    ring.send(
        set_delegate(&authority.pubkey(), &delegate.pubkey()),
        &[&authority, delegate],
    )
}

#[test]
fn the_delegate_is_permanent_and_needs_a_confidential_policy_ring() {
    let delegate = Keypair::new();
    let mut ring = Ring::new(Setup::Policy);
    within_budget(InstructionTag::SetDelegate, appoint(&mut ring, &delegate));
    let config: RingProgramConfig = ring.read(&config_pda());
    assert_eq!(config.delegate(), Some(&delegate.pubkey()));
    assert_eq!(config.mode(), Ok(RingMode::Registry));
    refused(
        appoint(&mut ring, &Keypair::new()),
        CustomRingError::DelegateAlreadySet,
    );
    refused(
        appoint(&mut Ring::new(Setup::AnonymousPolicy), &delegate),
        CustomRingError::AnonymousRingRefused,
    );
    refused(
        appoint(&mut Ring::new(Setup::AuditOnly), &delegate),
        CustomRingError::DelegateRequiresPolicy,
    );
}

#[test]
fn the_delegate_signs_its_appointment_and_no_data_names_it() {
    let mut ring = Ring::new(Setup::Policy);
    let authority = ring.authority.insecure_clone();
    let delegate = Keypair::new();
    let mut unsigned = set_delegate(&authority.pubkey(), &delegate.pubkey());
    unsigned.accounts[2].is_signer = false;
    refused_with(
        ring.send(unsigned, &[&authority]),
        InstructionError::Custom(u32::from(AccountError::InvalidSigner)),
    );
    let mut named = set_delegate(&authority.pubkey(), &delegate.pubkey());
    named.data.extend_from_slice(delegate.pubkey().as_ref());
    refused(
        ring.send(named, &[&authority, &delegate]),
        CustomRingError::InvalidInstructionData,
    );
    let config: RingProgramConfig = ring.read(&config_pda());
    assert_eq!(config.delegate(), None);
}

#[test]
fn only_the_upgrade_authority_appoints_the_delegate() {
    let mut ring = Ring::new(Setup::Policy);
    let successor = Keypair::new();
    let authority = ring.authority.insecure_clone();
    let handover = Instruction {
        program_id: PROGRAM,
        accounts: vec![
            AccountMeta::new_readonly(authority.pubkey(), true),
            AccountMeta::new_readonly(successor.pubkey(), true),
            AccountMeta::new(config_pda(), false),
        ],
        data: vec![tag::SET_AUTHORITY],
    };
    ring.send(handover, &[&authority, &successor])
        .expect("hand the config to a successor");
    let delegate = Keypair::new();
    refused(
        ring.send(
            set_delegate(&successor.pubkey(), &delegate.pubkey()),
            &[&successor, &delegate],
        ),
        CustomRingError::UnauthorizedInitializer,
    );
    appoint(&mut ring, &delegate).expect("the upgrade authority appoints the delegate");
}

#[test]
fn a_rule_over_a_member_written_list_is_refused() {
    let mut ring = Ring::new(Setup::Policy);
    let authority = ring.authority.pubkey();
    refused(
        authority_send(
            &mut ring,
            policy_write(
                tag::SET_POLICY_RULES,
                &authority,
                list_table(ListId::RingViewing, Vec::new()),
                &[],
            ),
        ),
        CustomRingError::MemberWrittenListRule,
    );
}

#[test]
fn policy_writes_need_a_policy_ring_and_a_foreign_curator() {
    let mut audit_only = Ring::new(Setup::AuditOnly);
    let authority = audit_only.authority.pubkey();
    refused(
        authority_send(
            &mut audit_only,
            policy_write(
                tag::CREATE_POLICY,
                &authority,
                allow_list_table(Vec::new()),
                &[],
            ),
        ),
        CustomRingError::PolicyOnAuditOnlyRing,
    );
    refused(
        authority_send(
            &mut audit_only,
            policy_write(
                tag::SET_POLICY_RULES,
                &authority,
                allow_list_table(Vec::new()),
                &[],
            ),
        ),
        CustomRingError::PolicyNotSet,
    );

    let mut ring = Ring::new(Setup::Policy);
    let authority = ring.authority.pubkey();
    refused(
        authority_send(
            &mut ring,
            policy_write(
                tag::CREATE_POLICY,
                &authority,
                allow_list_table(Vec::new()),
                &[],
            ),
        ),
        CustomRingError::PolicyAlreadySet,
    );
    let before: MemberRegistry = ring.read(&registry_pda());
    let mut own = allow_list_table(Vec::new());
    own.sources[0].source = 1;
    refused(
        authority_send(
            &mut ring,
            policy_write(tag::SET_POLICY_RULES, &authority, own, &[registry_pda()]),
        ),
        CustomRingError::InvalidSource,
    );
    let mut unreferenced = allow_list_table(Vec::new());
    unreferenced.sources[0].list_id = ListId::Block as u8;
    refused(
        authority_send(
            &mut ring,
            policy_write(tag::SET_POLICY_RULES, &authority, unreferenced, &[]),
        ),
        CustomRingError::InvalidSource,
    );
    let mut unsourced = allow_list_table(Vec::new());
    unsourced.sources.clear();
    refused(
        authority_send(
            &mut ring,
            policy_write(tag::SET_POLICY_RULES, &authority, unsourced, &[]),
        ),
        CustomRingError::InvalidSource,
    );
    authority_send(
        &mut ring,
        policy_write(
            tag::SET_POLICY_RULES,
            &authority,
            allow_list_table(Vec::new()),
            &[],
        ),
    )
    .expect("rewrite the table");
    let after: MemberRegistry = ring.read(&registry_pda());
    assert_eq!(after.policy_hash, before.policy_hash);
    assert_eq!(after.generation(), before.generation() + 1);
}

#[test]
fn a_policy_ring_registers_with_spp_once_its_table_is_set() {
    let mut ring = Ring::new(Setup::Policy);
    ring.deploy_stand_in(SPP);
    let mut registry: MemberRegistry = ring.read(&registry_pda());
    registry.policy_hash = [0; 32];
    ring.write(&registry_pda(), &registry);
    let register = init_spp_ring_config(&ring);
    refused(
        authority_send(&mut ring, register),
        CustomRingError::PolicyNotSet,
    );
}

fn init_spp_ring_config(ring: &Ring) -> Instruction {
    Instruction {
        program_id: PROGRAM,
        accounts: vec![
            AccountMeta::new(ring.payer.pubkey(), true),
            AccountMeta::new_readonly(ring.authority.pubkey(), true),
            AccountMeta::new_readonly(config_pda(), false),
            AccountMeta::new_readonly(Address::new_unique(), false),
            AccountMeta::new(ring_auth(), false),
            AccountMeta::new_readonly(SYSTEM, false),
            AccountMeta::new_readonly(SPP, false),
            AccountMeta::new_readonly(registry_pda(), false),
        ],
        data: vec![tag::INIT_SPP_RING_CONFIG],
    }
}

#[test]
fn every_authority_write_refuses_a_stranger() {
    let mut ring = Ring::new(Setup::Policy);
    let stranger = Keypair::new();
    let authority = ring.authority.pubkey();
    let source = SetPolicySourceIxData {
        list_id: ListId::Allow as u8,
        source: 0,
    };
    let co_signer = set_co_signer_data([1; 32], 1, &[]);
    let writes = [
        (
            config_write(tag::SET_CO_SIGNER, &authority, &[], &co_signer),
            0,
        ),
        (config_write(tag::CLEAR_CO_SIGNER, &authority, &[], &[]), 0),
        (
            policy_write(
                tag::CREATE_POLICY,
                &authority,
                allow_list_table(Vec::new()),
                &[],
            ),
            0,
        ),
        (
            policy_write(
                tag::SET_POLICY_RULES,
                &authority,
                allow_list_table(Vec::new()),
                &[],
            ),
            0,
        ),
        (
            config_write(
                tag::SET_POLICY_SOURCE,
                &authority,
                &[AccountMeta::new(registry_pda(), false)],
                &wincode::serialize(&source).unwrap(),
            ),
            0,
        ),
        (grant(&ring), 1),
        (revoke(&ring, Keypair::new().pubkey()), 0),
        (create_member_registry(&ring.payer.pubkey(), &authority), 1),
        (init_spp_ring_config(&ring), 1),
    ];
    let unauthorized = TransactionError::InstructionError(
        0,
        InstructionError::Custom(CustomRingError::UnauthorizedAuthority as u32),
    );
    let refusals: Vec<_> = writes
        .into_iter()
        .map(|(mut instruction, slot)| {
            instruction.accounts[slot] = AccountMeta::new_readonly(stranger.pubkey(), true);
            let tag = instruction.data[0];
            (
                tag,
                ring.send(instruction, &[&stranger])
                    .map_err(|(error, _)| error),
            )
        })
        .collect();
    let expected: Vec<_> = refusals
        .iter()
        .map(|(tag, _)| (*tag, Err(unauthorized.clone())))
        .collect();
    assert_eq!(refusals, expected);
}

fn reader() -> [u8; 34] {
    let mut reader = [0u8; 34];
    reader[0] = READER_KEY_P256;
    reader[1] = 0x02;
    reader[2..].fill(9);
    reader
}

fn read_access(tag: u8, accounts: Vec<AccountMeta>) -> Instruction {
    let mut data = vec![tag];
    data.extend(wincode::serialize(&ReaderIxData { reader: reader() }).unwrap());
    Instruction {
        program_id: PROGRAM,
        accounts,
        data,
    }
}

fn record_pda() -> Address {
    let seed = ReadAccessRecord::seed_hash(&reader()).unwrap();
    Address::find_program_address(&[READ_ACCESS_RECORD_PDA_SEED, &seed], &PROGRAM).0
}

#[test]
fn read_access_is_granted_and_revoked_by_the_authority() {
    let mut ring = Ring::new(Setup::AuditOnly);
    let granted = grant(&ring);
    within_budget(
        InstructionTag::GrantReadAccess,
        authority_send(&mut ring, granted),
    );
    assert_eq!(
        ring.read::<ReadAccessRecord>(&record_pda()).reader,
        reader()
    );
    let revoked = revoke(&ring, Keypair::new().pubkey());
    within_budget(
        InstructionTag::RevokeReadAccess,
        authority_send(&mut ring, revoked),
    );
    assert_eq!(ring.lamports(&record_pda()), 0);
}

#[test]
fn the_authority_moves_only_to_a_cosigning_successor() {
    let mut ring = Ring::new(Setup::AuditOnly);
    let successor = Keypair::new();
    let authority = ring.authority.insecure_clone();
    let handover = |successor: &Address, signs: bool| Instruction {
        program_id: PROGRAM,
        accounts: vec![
            AccountMeta::new_readonly(authority.pubkey(), true),
            AccountMeta::new_readonly(*successor, signs),
            AccountMeta::new(config_pda(), false),
        ],
        data: vec![tag::SET_AUTHORITY],
    };
    let unsigned = ring.send(handover(&successor.pubkey(), false), &[&authority]);
    assert!(unsigned.is_err());
    assert_eq!(
        ring.read::<RingProgramConfig>(&config_pda()).authority,
        authority.pubkey()
    );
    within_budget(
        InstructionTag::SetAuthority,
        ring.send(
            handover(&successor.pubkey(), true),
            &[&authority, &successor],
        ),
    );
    assert_eq!(
        ring.read::<RingProgramConfig>(&config_pda()).authority,
        successor.pubkey()
    );
    let other = Keypair::new();
    refused(
        ring.send(handover(&other.pubkey(), true), &[&authority, &other]),
        CustomRingError::UnauthorizedAuthority,
    );
}

#[test]
fn a_reader_key_that_cannot_authorize_reads_is_refused() {
    let mut ring = Ring::new(Setup::AuditOnly);
    let (payer, authority) = (ring.payer.pubkey(), ring.authority.pubkey());
    let mut uncompressed = reader();
    uncompressed[1] = 0x04;
    let mut data = vec![tag::GRANT_READ_ACCESS];
    data.extend(
        wincode::serialize(&ReaderIxData {
            reader: uncompressed,
        })
        .unwrap(),
    );
    let grant = Instruction {
        program_id: PROGRAM,
        accounts: vec![
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new_readonly(config_pda(), false),
            AccountMeta::new(record_pda(), false),
            AccountMeta::new_readonly(SYSTEM, false),
        ],
        data,
    };
    refused(
        authority_send(&mut ring, grant),
        CustomRingError::InvalidReaderKey,
    );
}

#[test]
fn retired_and_unknown_tags_are_refused() {
    let mut ring = Ring::new(Setup::AuditOnly);
    let instruction = |data: Vec<u8>| Instruction {
        program_id: PROGRAM,
        accounts: Vec::new(),
        data,
    };
    refused(
        ring.send(instruction(vec![tag::DEPOSIT]), &[]),
        CustomRingError::DepositAuditRequired,
    );
    for unknown in [8, 9, 22, 23, 26, 30, 32, 33, 38, u8::MAX] {
        refused(
            ring.send(instruction(vec![unknown]), &[]),
            CustomRingError::InvalidInstructionData,
        );
    }
}

#[test]
fn operator_and_record_instructions_fit_their_declared_budgets() {
    let mut ring = Ring::new(Setup::Policy);
    let authority = ring.authority.pubkey();
    within_budget(
        InstructionTag::SetPolicyRules,
        authority_send(
            &mut ring,
            policy_write(
                tag::SET_POLICY_RULES,
                &authority,
                allow_list_table(Vec::new()),
                &[],
            ),
        ),
    );
    within_budget(
        InstructionTag::SetCoSigner,
        authority_send(
            &mut ring,
            config_write(
                tag::SET_CO_SIGNER,
                &authority,
                &[],
                &set_co_signer_data([1; 32], 4, &[[7; 32]]),
            ),
        ),
    );
    within_budget(
        InstructionTag::SetInsertFee,
        authority_send(
            &mut ring,
            config_write(
                tag::SET_INSERT_FEE,
                &authority,
                &[],
                &(2 * DEFAULT_INSERT_FEE).to_le_bytes(),
            ),
        ),
    );
    let member = Keypair::new();
    let payer = Keypair::new();
    ring.fund(&payer.pubkey());
    let lists = WriteRecordsIxData::new(
        ListChange {
            set: ListSet::single(ListId::RingViewing),
            clear: ListSet::EMPTY,
        }
        .check()
        .unwrap(),
    );
    within_budget(
        InstructionTag::WriteRecords,
        ring.send(
            write_records(
                &member.pubkey(),
                lists,
                Some(Fee {
                    payer: payer.pubkey(),
                    recipient: authority,
                }),
            ),
            &[&member, &payer],
        ),
    );
}

fn audit_only_config() -> CreateConfigIxData {
    CreateConfigIxData {
        auditor_pubkey: auditor_pubkey(),
        kind: RingKind::AuditOnly,
    }
}

#[test]
fn create_config_takes_its_canonical_address_once_beside_the_system_program() {
    let mut ring = Ring::new(Setup::AuditOnly);
    let (payer, authority) = (ring.payer.pubkey(), ring.authority.pubkey());
    let again = create_config(&payer, &authority, audit_only_config());
    refused(
        authority_send(&mut ring, again),
        CustomRingError::ConfigAlreadyInitialized,
    );
    let mut elsewhere = create_config(&payer, &authority, audit_only_config());
    elsewhere.accounts[2] = AccountMeta::new(Address::new_unique(), false);
    refused(
        authority_send(&mut ring, elsewhere),
        CustomRingError::InvalidConfigPda,
    );
    let mut impostor = create_config(&payer, &authority, audit_only_config());
    impostor.accounts[3] = AccountMeta::new_readonly(Address::new_unique(), false);
    refused(
        authority_send(&mut ring, impostor),
        CustomRingError::InvalidSystemProgram,
    );
}

#[test]
fn each_ring_kind_fixes_its_policy_flag_and_mode() {
    for (setup, has_policy, mode) in [
        (Setup::AuditOnly, false, RingMode::Off),
        (Setup::Policy, true, RingMode::Off),
        (Setup::Anonymous, false, RingMode::Anonymous),
        (Setup::AnonymousPolicy, true, RingMode::Anonymous),
    ] {
        let config: RingProgramConfig = Ring::new(setup).read(&config_pda());
        assert_eq!((config.has_policy(), config.mode()), (has_policy, Ok(mode)));
    }
    let mut ring = Ring::new(Setup::AuditOnly);
    ring.store(config_pda(), SYSTEM, Vec::new());
    let (payer, authority) = (ring.payer.pubkey(), ring.authority.pubkey());
    let mut unknown = create_config(&payer, &authority, audit_only_config());
    *unknown.data.last_mut().unwrap() = 4;
    refused(
        authority_send(&mut ring, unknown),
        CustomRingError::InvalidInstructionData,
    );
}

fn grant(ring: &Ring) -> Instruction {
    read_access(
        tag::GRANT_READ_ACCESS,
        vec![
            AccountMeta::new(ring.payer.pubkey(), true),
            AccountMeta::new_readonly(ring.authority.pubkey(), true),
            AccountMeta::new_readonly(config_pda(), false),
            AccountMeta::new(record_pda(), false),
            AccountMeta::new_readonly(SYSTEM, false),
        ],
    )
}

fn revoke(ring: &Ring, rent_recipient: Address) -> Instruction {
    read_access(
        tag::REVOKE_READ_ACCESS,
        vec![
            AccountMeta::new_readonly(ring.authority.pubkey(), true),
            AccountMeta::new_readonly(config_pda(), false),
            AccountMeta::new(record_pda(), false),
            AccountMeta::new(rent_recipient, false),
        ],
    )
}

#[test]
fn a_reader_holds_one_record_revoked_only_under_its_own_key() {
    let mut ring = Ring::new(Setup::AuditOnly);
    let first = grant(&ring);
    authority_send(&mut ring, first).expect("grant the reader");
    let second = grant(&ring);
    refused(
        authority_send(&mut ring, second),
        CustomRingError::ReadAccessRecordAlreadyExists,
    );
    let mut other_reader = revoke(&ring, Keypair::new().pubkey());
    *other_reader.data.last_mut().unwrap() ^= 1;
    refused(
        authority_send(&mut ring, other_reader),
        CustomRingError::InvalidReadAccessRecord,
    );
    let into_itself = revoke(&ring, record_pda());
    refused(
        authority_send(&mut ring, into_itself),
        CustomRingError::InvalidReadAccessRecord,
    );
}

#[test]
fn a_source_write_names_a_known_list() {
    let mut ring = Ring::new(Setup::Policy);
    let authority = ring.authority.pubkey();
    for list_id in [0, u8::MAX] {
        let data = SetPolicySourceIxData { list_id, source: 0 };
        let instruction = Instruction {
            program_id: PROGRAM,
            accounts: vec![
                AccountMeta::new_readonly(authority, true),
                AccountMeta::new_readonly(config_pda(), false),
                AccountMeta::new(registry_pda(), false),
            ],
            data: [
                &[tag::SET_POLICY_SOURCE][..],
                &wincode::serialize(&data).unwrap(),
            ]
            .concat(),
        };
        refused(
            authority_send(&mut ring, instruction),
            CustomRingError::InvalidListId,
        );
    }
}

#[test]
fn a_table_write_decodes_and_counts_its_generation_on_the_own_registry() {
    let mut ring = Ring::new(Setup::Policy);
    let authority = ring.authority.pubkey();
    let mut zero_asset = allow_list_table(Vec::new());
    zero_asset.inline_assets = vec![[0; 32]];
    refused(
        authority_send(
            &mut ring,
            policy_write(tag::SET_POLICY_RULES, &authority, zero_asset, &[]),
        ),
        CustomRingError::InvalidPolicyRules,
    );
    let mut queue_as_registry = policy_write(
        tag::SET_POLICY_RULES,
        &authority,
        allow_list_table(Vec::new()),
        &[],
    );
    queue_as_registry.accounts[2] = AccountMeta::new(queue_pda(), false);
    refused(
        authority_send(&mut ring, queue_as_registry),
        CustomRingError::InvalidMemberRegistry,
    );
    let mut registry: MemberRegistry = ring.read(&registry_pda());
    registry.generation = u32::MAX.to_le_bytes();
    ring.write(&registry_pda(), &registry);
    refused(
        authority_send(
            &mut ring,
            policy_write(
                tag::SET_POLICY_RULES,
                &authority,
                allow_list_table(Vec::new()),
                &[],
            ),
        ),
        CustomRingError::PolicyGenerationOverflow,
    );
}

fn set_paused(ring: &Ring, ring_auth: Address, spp: Address) -> Instruction {
    Instruction {
        program_id: PROGRAM,
        accounts: vec![
            AccountMeta::new_readonly(ring.authority.pubkey(), true),
            AccountMeta::new_readonly(config_pda(), false),
            AccountMeta::new(ring_auth, false),
            AccountMeta::new_readonly(spp, false),
        ],
        data: [
            &[tag::SET_PAUSED][..],
            &wincode::serialize(&SetPausedIxData { paused: true }).unwrap(),
        ]
        .concat(),
    }
}

#[test]
fn only_the_authority_pauses_through_the_ring_pda_and_the_pool() {
    let mut ring = Ring::new(Setup::AuditOnly);
    let spp = Address::new_from_array(zolana_interface::SHIELDED_POOL_PROGRAM_ID);
    ring.deploy_stand_in(spp);
    let stranger = Keypair::new();
    let mut unauthorized = set_paused(&ring, ring_auth(), spp);
    unauthorized.accounts[0] = AccountMeta::new_readonly(stranger.pubkey(), true);
    refused(
        ring.send(unauthorized, &[&stranger]),
        CustomRingError::UnauthorizedAuthority,
    );
    let no_pool = set_paused(&ring, ring_auth(), Address::new_unique());
    refused(
        authority_send(&mut ring, no_pool),
        CustomRingError::InvalidShieldedPoolProgram,
    );
    let no_pda = set_paused(&ring, Address::new_unique(), spp);
    refused(
        authority_send(&mut ring, no_pda),
        CustomRingError::MissingRingAuth,
    );
}

#[test]
fn a_config_with_an_unknown_mode_reads_as_uninitialized() {
    let mut ring = Ring::new(Setup::AuditOnly);
    let mut config: RingProgramConfig = ring.read(&config_pda());
    config.mode = 3;
    ring.write(&config_pda(), &config);
    let authority = ring.authority.pubkey();
    let fee = config_write(
        tag::SET_INSERT_FEE,
        &authority,
        &[],
        &DEFAULT_INSERT_FEE.to_le_bytes(),
    );
    refused(
        authority_send(&mut ring, fee),
        CustomRingError::ConfigNotInitialized,
    );
}
