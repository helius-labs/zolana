use custom_ring_interface::RingDepositAuditCapsule;
use custom_ring_interface::{
    pda, tag, CustomRingProof, DepositAudit, DEPOSIT_AUDIT, KEY_REGISTRY_ROOT_HISTORY,
};
use custom_ring_program::CustomRingError;
use mollusk_svm::result::ProgramResult;
use solana_account::Account;
use solana_instruction::AccountMeta;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;
use zolana_interface::{
    instruction::instruction_data::deposit::RingDepositIxData, SHIELDED_POOL_PROGRAM_ID,
};

use crate::common::{
    account, audit_only_config_account, auditor_pubkey, authority, config_pda, deposit_fixture,
    escrowed_config_account, key_registry_root_slot, payer, program_id, setup_mollusk,
    system_program_slot, Fixture, Slot,
};

fn audit_account(required: u8) -> Account {
    Account {
        owner: program_id(),
        data: bytemuck::bytes_of(&DepositAudit {
            discriminator: DEPOSIT_AUDIT,
            required,
            bump: pda::deposit_audit(&program_id()).1,
        })
        .to_vec(),
        ..account(1_000_000_000)
    }
}

fn setter(required: u8, existing: Account) -> Fixture {
    Fixture::new(
        vec![tag::SET_DEPOSIT_AUDIT, required],
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
                account: audit_only_config_account(authority(), auditor_pubkey(2)),
            },
            Slot {
                label: "deposit_audit",
                meta: AccountMeta::new(pda::deposit_audit(&program_id()).0, false),
                account: existing,
            },
            system_program_slot(),
        ],
    )
}

/// Offset of the key registry root index in the audited wire.
const REGISTRY_INDEX: usize = 1 + CustomRingProof::SIZE;

fn custom(error: CustomRingError) -> ProgramError {
    ProgramError::Custom(error as u32)
}

fn audited_fixture(count: usize) -> Fixture {
    let mut fixture = deposit_fixture();
    let mut deposit = RingDepositIxData::deserialize(&fixture.instruction().data[1..]).unwrap();
    deposit.deposits = vec![deposit.deposits[0].clone(); count];
    for (index, entry) in deposit.deposits.iter_mut().enumerate() {
        entry.encrypted.ciphertext = RingDepositAuditCapsule {
            slot_index: index as u8,
            eph_pk: &[2; 33],
            ciphertext: &[3; 64],
            recipient_ciphertext: &entry.encrypted.ciphertext,
        }
        .encode();
    }
    let mut wire = vec![tag::AUDITED_DEPOSIT];
    wire.extend_from_slice(&[0; CustomRingProof::SIZE]);
    wire.push(0);
    wire.push(tag::DEPOSIT);
    wire.extend(deposit.serialize().unwrap());
    *fixture.data_mut() = wire;
    fixture
}

fn mutate_deposit(fixture: &mut Fixture, change: impl FnOnce(&mut RingDepositIxData)) {
    let body = REGISTRY_INDEX + 2;
    let mut deposit = RingDepositIxData::deserialize(&fixture.instruction().data[body..]).unwrap();
    change(&mut deposit);
    fixture.data_mut().truncate(body);
    fixture.data_mut().extend(deposit.serialize().unwrap());
}

fn proven_fixture(count: usize) -> Fixture {
    let bytes = match count {
        2 => include_bytes!("../fixtures/deposit-audit/2.bin").as_slice(),
        8 => include_bytes!("../fixtures/deposit-audit/8.bin").as_slice(),
        _ => panic!("unsupported deposit fixture"),
    };
    let auditor = hex::decode("020217e617f0b6443928278f96999e69a23a4f2c152bdf6d6cdf66e5b80282d4ed")
        .unwrap()
        .try_into()
        .unwrap();
    let mut fixture = deposit_fixture();
    assert_eq!(
        program_id().to_string(),
        "6Ckm2BrnXxsSjyG5b17kQQRjoECVrts92RKXVGT8XeqS"
    );
    fixture.substitute(
        "tree",
        "4Ss5JMkXAD9Z7cktFEdrqeMuT6jGMF1pVozTyPHZ6zT4"
            .parse()
            .unwrap(),
    );
    fixture.substitute(
        "depositor",
        "3yS1JFVT284y8z1LC9MRoWxZjzFrdoD5axKsZiyMsfC7"
            .parse()
            .unwrap(),
    );
    fixture.set_account("config", audit_only_config_account(authority(), auditor));
    fixture.set_account("deposit_audit", audit_account(1));
    let mut wire = bytes.to_vec();
    wire.insert(REGISTRY_INDEX, 0);
    *fixture.data_mut() = wire;
    fixture
}

#[test]
fn proven_disclosures_reach_spp_for_two_and_eight_outputs() {
    let (mut mollusk, _) = setup_mollusk();
    let spp_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    mollusk.add_program(&spp_id, "spp_recorder_program");
    for count in [2, 8] {
        let mut fixture = proven_fixture(count);
        let mut recorder = account(1_000_000_000);
        recorder.owner = spp_id;
        recorder.data = vec![0; fixture.instruction().accounts.len() - fixture.position("tree")];
        fixture.set_account("tree", recorder);
        let result = mollusk.process_instruction(fixture.instruction(), fixture.accounts());
        assert_eq!(result.program_result, ProgramResult::Success);
        let tree = result
            .resulting_accounts
            .iter()
            .find(|(key, _)| key == &fixture.account_key("tree"))
            .unwrap();
        assert_eq!(tree.1.data[0], 2);
        assert_eq!(tree.1.data[2], 1);
        assert!(result.compute_units_consumed <= 1_400_000);
        eprintln!(
            "audited deposit {count} outputs: {} CU",
            result.compute_units_consumed
        );
    }
}

#[test]
fn proven_disclosures_reject_changed_tree_auditor_and_deposit_context() {
    let (mollusk, _) = setup_mollusk();
    let mut other_tree = proven_fixture(2);
    other_tree.substitute("tree", Pubkey::new_from_array([99; 32]));
    other_tree.expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
    let mut other_auditor = proven_fixture(2);
    other_auditor.set_account(
        "config",
        audit_only_config_account(authority(), auditor_pubkey(2)),
    );
    other_auditor.expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
    let mut other_amount = proven_fixture(2);
    mutate_deposit(&mut other_amount, |deposit| deposit.deposits[1].amount += 1);
    other_amount.expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
}

#[test]
fn proven_disclosures_bind_each_owner_and_both_ciphertexts() {
    let (mollusk, _) = setup_mollusk();
    for slot in 0..8 {
        let mut owner = proven_fixture(8);
        mutate_deposit(&mut owner, |deposit| {
            deposit.deposits[slot].owner_utxo_hash[31] ^= 1
        });
        owner.expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
        for offset in [42, 106] {
            let mut ciphertext = proven_fixture(8);
            mutate_deposit(&mut ciphertext, |deposit| {
                deposit.deposits[slot].encrypted.ciphertext[offset] ^= 1
            });
            ciphertext.expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
        }
    }
}

#[test]
fn authority_can_create_enable_and_disable_deposit_auditing() {
    let (mollusk, _) = setup_mollusk();
    for initial in [
        account(0),
        account(1_000_000),
        audit_account(0),
        audit_account(1),
    ] {
        for required in [0, 1] {
            let fixture = setter(required, initial.clone());
            let result = mollusk.process_instruction(fixture.instruction(), fixture.accounts());
            assert_eq!(result.program_result, ProgramResult::Success);
            let stored = result
                .resulting_accounts
                .iter()
                .find(|(key, _)| key == &pda::deposit_audit(&program_id()).0)
                .unwrap();
            let value = bytemuck::from_bytes::<DepositAudit>(&stored.1.data);
            assert_eq!(value.required, required);
            assert_eq!(value.bump, pda::deposit_audit(&program_id()).1);
            assert_eq!(stored.1.owner, program_id());
        }
    }
}

#[test]
fn setter_requires_the_config_authority_signature() {
    let (mollusk, _) = setup_mollusk();
    let mut unsigned = setter(1, account(0));
    unsigned.unsign("authority");
    unsigned.expect_err(
        &mollusk,
        ProgramError::Custom(u32::from(
            zolana_account_checks::AccountError::InvalidSigner,
        )),
    );
    let mut other = setter(1, account(0));
    other.substitute("authority", Pubkey::new_from_array([99; 32]));
    other.expect_err(&mollusk, custom(CustomRingError::UnauthorizedAuthority));
}

#[test]
fn setter_rejects_invalid_mode_system_and_pda() {
    let (mollusk, _) = setup_mollusk();
    setter(2, account(0)).expect_err(&mollusk, custom(CustomRingError::InvalidDepositAudit));
    let mut system = setter(1, account(0));
    system.substitute("system_program", Pubkey::new_from_array([99; 32]));
    system.expect_err(&mollusk, custom(CustomRingError::InvalidSystemProgram));
    let mut pda = setter(1, account(0));
    pda.substitute("deposit_audit", Pubkey::new_from_array([98; 32]));
    pda.expect_err(&mollusk, custom(CustomRingError::InvalidDepositAudit));
}

#[test]
fn enabled_setting_refuses_the_proofless_deposit_tag() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = deposit_fixture();
    fixture.set_account("deposit_audit", audit_account(1));
    fixture.expect_err(&mollusk, custom(CustomRingError::DepositAuditRequired));
}

#[test]
fn disabled_and_donated_settings_keep_deposits_proofless() {
    let (mollusk, _) = setup_mollusk();
    for setting in [account(0), account(1_000_000), audit_account(0)] {
        let mut fixture = deposit_fixture();
        fixture.set_account("deposit_audit", setting);
        fixture.expect_spp_cpi(&mollusk);
    }
}

#[test]
fn setting_cannot_be_omitted_or_substituted() {
    let (mollusk, _) = setup_mollusk();
    let mut omitted = deposit_fixture();
    omitted.remove("deposit_audit");
    omitted.expect_err(&mollusk, custom(CustomRingError::InvalidDepositAudit));
    let mut other = deposit_fixture();
    other.substitute("deposit_audit", Pubkey::new_from_array([98; 32]));
    other.expect_err(&mollusk, custom(CustomRingError::InvalidDepositAudit));
}

#[test]
fn malformed_or_foreign_empty_settings_do_not_disable_the_requirement() {
    let (mollusk, _) = setup_mollusk();
    let mut foreign = account(0);
    foreign.owner = Pubkey::new_from_array([98; 32]);
    let mut invalid_mode = audit_account(2);
    for invalid in [foreign, invalid_mode.clone()] {
        let mut fixture = deposit_fixture();
        fixture.set_account("deposit_audit", invalid);
        fixture.expect_err(&mollusk, custom(CustomRingError::InvalidDepositAudit));
    }
    invalid_mode.data.truncate(2);
    let mut fixture = deposit_fixture();
    fixture.set_account("deposit_audit", invalid_mode);
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidDepositAudit));
}

#[test]
fn audited_tag_requires_a_proof_even_when_the_setting_is_off() {
    let (mollusk, _) = setup_mollusk();
    for required in [0, 1] {
        let mut fixture = audited_fixture(1);
        fixture.set_account("deposit_audit", audit_account(required));
        fixture.expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
    }
}

#[test]
fn audited_tag_rejects_truncated_proofs_and_nested_non_deposits() {
    let (mollusk, _) = setup_mollusk();
    let mut truncated = audited_fixture(1);
    truncated.data_mut().truncate(CustomRingProof::SIZE);
    truncated.expect_err(&mollusk, custom(CustomRingError::InvalidInstructionData));
    let mut other = audited_fixture(1);
    other.data_mut()[REGISTRY_INDEX + 1] = tag::MERGE;
    other.expect_err(&mollusk, custom(CustomRingError::InvalidInstructionData));
}

#[test]
fn audited_batch_must_fit_the_circuit() {
    let (mollusk, _) = setup_mollusk();
    for count in [0, 9] {
        audited_fixture(count)
            .expect_err(&mollusk, custom(CustomRingError::InvalidDepositDisclosure));
    }
}

#[test]
fn every_slot_requires_a_capsule_with_its_own_index_and_the_same_key() {
    let (mollusk, _) = setup_mollusk();
    let mut missing = audited_fixture(2);
    mutate_deposit(&mut missing, |deposit| {
        deposit.deposits[1].encrypted.ciphertext.clear()
    });
    missing.expect_err(&mollusk, custom(CustomRingError::InvalidDepositDisclosure));
    let mut duplicate = audited_fixture(2);
    mutate_deposit(&mut duplicate, |deposit| {
        deposit.deposits[1].encrypted.ciphertext[8] = 0
    });
    duplicate.expect_err(&mollusk, custom(CustomRingError::InvalidDepositDisclosure));
    let mut other_key = audited_fixture(2);
    mutate_deposit(&mut other_key, |deposit| {
        deposit.deposits[1].encrypted.ciphertext[10] ^= 1
    });
    other_key.expect_err(&mollusk, custom(CustomRingError::InvalidDepositDisclosure));
}

fn escrowed_fixture(registry_index: u8) -> Fixture {
    let mut fixture = audited_fixture(1);
    fixture.set_account("config", escrowed_config_account());
    fixture.data_mut()[REGISTRY_INDEX] = registry_index;
    let at = fixture.position("deposit_audit") + 1;
    fixture.insert(at, key_registry_root_slot());
    fixture
}

#[test]
fn an_escrowed_audited_deposit_binds_the_registry_root() {
    let (mollusk, _) = setup_mollusk();
    escrowed_fixture(0).expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
    for stale in [1, KEY_REGISTRY_ROOT_HISTORY as u8] {
        escrowed_fixture(stale).expect_err(&mollusk, custom(CustomRingError::StaleKeyRegistryRoot));
    }
    let mut missing = escrowed_fixture(0);
    missing.remove("key_registry_root");
    missing.expect_err(&mollusk, custom(CustomRingError::InvalidKeyRegistryRoot));
}

#[test]
fn a_registry_index_without_escrow_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = audited_fixture(1);
    fixture.data_mut()[REGISTRY_INDEX] = 1;
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidInstructionData));
}
