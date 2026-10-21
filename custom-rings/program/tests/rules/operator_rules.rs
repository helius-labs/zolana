//! Config, policy and read access writes, and the budgets every instruction declares.

use custom_ring_interface::{
    stream::{tag_epoch, EPOCH_SLOTS},
    tag, CreateConfigIxData, CustomRingError, InstructionTag, MemberRegistry, ReadAccessRecord,
    ReaderIxData, RingMode, RingProgramConfig, SetCoSignerIxData, WithdrawalThreshold,
    WriteRecordsIxData, DEFAULT_INSERT_FEE, READER_KEY_P256, READ_ACCESS_RECORD_PDA_SEED,
};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::{Keypair, Signer};
use zolana_ring_policy::{ListId, ListSet, ListWrite};

use crate::common::{
    allow_list_table, auditor_pubkey, config_pda, config_write, create_config, list_table,
    policy_write, refused, registry_pda, set_delegate, within_budget, write_records, Fee, Ring,
    Sent, Setup, PROGRAM, SYSTEM,
};

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
        has_policy: false,
        anonymous: false,
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
fn the_config_records_the_slot_it_was_created_in() {
    let mut ring = Ring::new(Setup::Anonymous);
    ring.store(config_pda(), SYSTEM, Vec::new());
    let created = 3 * EPOCH_SLOTS + 7;
    ring.warp(created);
    let (payer, authority) = (ring.payer.pubkey(), ring.authority.pubkey());
    let data = CreateConfigIxData {
        auditor_pubkey: auditor_pubkey(),
        has_policy: false,
        anonymous: true,
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

#[test]
fn the_delegate_is_permanent_and_needs_a_confidential_policy_ring() {
    let delegate = |ring: &mut Ring, address: [u8; 32]| {
        let authority = ring.authority.pubkey();
        authority_send(
            ring,
            set_delegate(&authority, &Address::new_from_array(address)),
        )
    };
    let mut ring = Ring::new(Setup::Policy);
    refused(
        delegate(&mut ring, [0; 32]),
        CustomRingError::InvalidDelegate,
    );
    within_budget(InstructionTag::SetDelegate, delegate(&mut ring, [5; 32]));
    let config: RingProgramConfig = ring.read(&config_pda());
    assert_eq!(config.mode(), Ok(RingMode::Registry));
    refused(
        delegate(&mut ring, [6; 32]),
        CustomRingError::DelegateAlreadySet,
    );
    refused(
        delegate(&mut Ring::new(Setup::AnonymousPolicy), [5; 32]),
        CustomRingError::AnonymousRingRefused,
    );
    refused(
        delegate(&mut Ring::new(Setup::AuditOnly), [5; 32]),
        CustomRingError::DelegateRequiresPolicy,
    );
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
    refused(
        ring.send(
            set_delegate(&successor.pubkey(), &Address::new_from_array([5; 32])),
            &[&successor],
        ),
        CustomRingError::UnauthorizedInitializer,
    );
    ring.send(
        set_delegate(&authority.pubkey(), &Address::new_from_array([5; 32])),
        &[&authority],
    )
    .expect("the upgrade authority appoints the delegate");
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
    let spp = Address::new_from_array(zolana_interface::SHIELDED_POOL_PROGRAM_ID);
    ring.deploy_stand_in(spp);
    let mut registry: MemberRegistry = ring.read(&registry_pda());
    registry.policy_hash = [0; 32];
    ring.write(&registry_pda(), &registry);
    let (payer, authority) = (ring.payer.pubkey(), ring.authority.pubkey());
    let register = Instruction {
        program_id: PROGRAM,
        accounts: vec![
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new_readonly(config_pda(), false),
            AccountMeta::new_readonly(Address::new_unique(), false),
            AccountMeta::new(crate::common::ring_auth(), false),
            AccountMeta::new_readonly(SYSTEM, false),
            AccountMeta::new_readonly(spp, false),
            AccountMeta::new_readonly(registry_pda(), false),
        ],
        data: vec![tag::INIT_SPP_RING_CONFIG],
    };
    refused(
        authority_send(&mut ring, register),
        CustomRingError::PolicyNotSet,
    );
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
    let (payer, authority) = (ring.payer.pubkey(), ring.authority.pubkey());
    let grant = read_access(
        tag::GRANT_READ_ACCESS,
        vec![
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new_readonly(config_pda(), false),
            AccountMeta::new(record_pda(), false),
            AccountMeta::new_readonly(SYSTEM, false),
        ],
    );
    within_budget(
        InstructionTag::GrantReadAccess,
        authority_send(&mut ring, grant),
    );
    assert_eq!(
        ring.read::<ReadAccessRecord>(&record_pda()).reader,
        reader()
    );
    let recipient = Keypair::new().pubkey();
    let revoke = read_access(
        tag::REVOKE_READ_ACCESS,
        vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new_readonly(config_pda(), false),
            AccountMeta::new(record_pda(), false),
            AccountMeta::new(recipient, false),
        ],
    );
    within_budget(
        InstructionTag::RevokeReadAccess,
        authority_send(&mut ring, revoke),
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
                &1_000u64.to_le_bytes(),
            ),
        ),
    );
    let member = Keypair::new();
    let payer = Keypair::new();
    ring.fund(&payer.pubkey());
    let lists = WriteRecordsIxData::new(
        ListWrite::new(ListSet::single(ListId::RingViewing), ListSet::EMPTY).unwrap(),
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
