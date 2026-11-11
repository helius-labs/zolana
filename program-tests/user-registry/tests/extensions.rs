mod common;

use solana_instruction::{error::InstructionError, Instruction};
use solana_keypair::Keypair;
use solana_signer::Signer;
use solana_transaction_error::TransactionError;
use spr_user_registry::error::UserRegistryError;
use spr_user_registry_interface::{
    instruction::{self, AppendData, RegisterData, RotateNullifierKeyData, UpdateKeysData},
    user_record_pda, MergeEncryptionScheme, UserRecord,
};
use user_registry_tests::UserRegistryTestRig;

use common::{funded_keypair, keys, register};

fn append(owner: &Keypair, rent_payer: &Keypair, data: Vec<u8>) -> Instruction {
    instruction::append_data(
        user_record_pda(&owner.pubkey()).0,
        owner.pubkey(),
        rent_payer.pubkey(),
        AppendData { data },
    )
}

fn rotate(owner: &Keypair) -> Instruction {
    instruction::rotate_nullifier_key(
        user_record_pda(&owner.pubkey()).0,
        owner.pubkey(),
        RotateNullifierKeyData {
            nullifier_pubkey: keys(9).nullifier,
        },
    )
}

#[test]
fn append_resizes_a_legacy_record_and_charges_only_the_separate_rent_payer() {
    let mut rig = UserRegistryTestRig::new();
    let owner = Keypair::new();
    let rent_payer = funded_keypair(&mut rig);
    let record_address = user_record_pda(&owner.pubkey()).0;
    let value = keys(1);
    rig.send(
        instruction::register(
            record_address,
            owner.pubkey(),
            rent_payer.pubkey(),
            RegisterData {
                nullifier_pubkey: value.nullifier,
                viewing_pubkey: value.viewing,
            },
        ),
        &[&owner, &rent_payer],
    )
    .unwrap();
    let before = rig.svm.get_account(&record_address).unwrap();
    let payer_before = rig.svm.get_balance(&rent_payer.pubkey()).unwrap();
    let mut expected_bytes = Vec::new();
    for chunk in [vec![0, 1, 255], vec![7; 512]] {
        rig.send(
            append(&owner, &rent_payer, chunk.clone()),
            &[&owner, &rent_payer],
        )
        .unwrap();
        expected_bytes.extend(chunk);
        let account = rig.svm.get_account(&record_address).unwrap();
        let expected_size = UserRecord::SIZE + UserRecord::DATA_LEN_SIZE + expected_bytes.len();
        let rent = rig.svm.minimum_balance_for_rent_exemption(expected_size);
        assert_eq!(
            account.data.len(),
            expected_size,
            "account must grow exactly"
        );
        assert_eq!(account.lamports, rent, "record remains rent exempt");
        assert_eq!(
            UserRecord::try_from_account_data(&account.data).unwrap(),
            UserRecord::try_from_account_data(&before.data).unwrap(),
            "append preserves the complete original header"
        );
        assert_eq!(
            UserRecord::additional_data(&account.data).unwrap(),
            expected_bytes
        );
        assert_eq!(
            rig.svm.get_balance(&rent_payer.pubkey()),
            Some(payer_before - (rent - before.lamports)),
            "only missing rent is charged to the separate payer"
        );
        assert_eq!(rig.svm.get_balance(&owner.pubkey()).unwrap_or(0), 0);
    }
}

#[test]
fn append_uses_existing_excess_lamports_before_charging_the_rent_payer() {
    let mut rig = UserRegistryTestRig::new();
    let owner = funded_keypair(&mut rig);
    let rent_payer = funded_keypair(&mut rig);
    register(&mut rig, &owner, keys(1));
    let address = user_record_pda(&owner.pubkey()).0;
    let mut account = rig.svm.get_account(&address).unwrap();
    account.lamports += 1_000_000;
    rig.svm.set_account(address, account.clone()).unwrap();
    let payer_before = rig.svm.get_account(&rent_payer.pubkey()).unwrap();
    rig.send(
        append(&owner, &rent_payer, vec![42]),
        &[&owner, &rent_payer],
    )
    .unwrap();
    assert_eq!(
        rig.svm.get_account(&rent_payer.pubkey()),
        Some(payer_before)
    );
    assert_eq!(rig.svm.get_balance(&address), Some(account.lamports));
    assert_eq!(
        UserRecord::additional_data(&rig.svm.get_account(&address).unwrap().data).unwrap(),
        [42]
    );
}

#[test]
fn empty_append_preserves_the_entire_account() {
    let mut rig = UserRegistryTestRig::new();
    let owner = funded_keypair(&mut rig);
    let payer = funded_keypair(&mut rig);
    register(&mut rig, &owner, keys(1));
    let address = user_record_pda(&owner.pubkey()).0;
    for data in [Vec::new(), vec![1, 2], Vec::new()] {
        let before = rig.svm.get_account(&address).unwrap();
        let payer_before = rig.svm.get_account(&payer.pubkey()).unwrap();
        rig.send(append(&owner, &payer, data.clone()), &[&owner, &payer])
            .unwrap();
        if data.is_empty() {
            assert_eq!(rig.svm.get_account(&address), Some(before));
            assert_eq!(rig.svm.get_account(&payer.pubkey()), Some(payer_before));
        }
    }
}

#[test]
fn rotation_and_existing_mutations_preserve_appended_data() {
    let mut rig = UserRegistryTestRig::new();
    let owner = funded_keypair(&mut rig);
    let payer = funded_keypair(&mut rig);
    register(&mut rig, &owner, keys(1));
    let address = user_record_pda(&owner.pubkey()).0;
    // Rotation works on the original fixed-size record without migration.
    let before = rig.svm.get_account(&address).unwrap();
    rig.send(rotate(&owner), &[&owner]).unwrap();
    let mut expected = rig.record(&owner.pubkey());
    assert_eq!(
        expected,
        UserRecord {
            nullifier_pubkey: keys(9).nullifier,
            ..UserRecord::try_from_account_data(&before.data).unwrap()
        }
    );
    assert_eq!(
        rig.svm.get_account(&address).unwrap().data.len(),
        UserRecord::SIZE
    );
    rig.send(append(&owner, &payer, vec![3, 4, 5]), &[&owner, &payer])
        .unwrap();
    let before = rig.svm.get_account(&address).unwrap();
    expected.nullifier_pubkey = keys(10).nullifier;
    expected.viewing_pubkey = keys(11).viewing;
    expected.merge_encryption = MergeEncryptionScheme::PoseidonCtrV1;
    rig.send_all(
        &[
            instruction::rotate_nullifier_key(
                address,
                owner.pubkey(),
                RotateNullifierKeyData {
                    nullifier_pubkey: expected.nullifier_pubkey,
                },
            ),
            instruction::update_keys(
                address,
                owner.pubkey(),
                UpdateKeysData {
                    viewing_pubkey: expected.viewing_pubkey,
                },
            ),
            instruction::set_merge_encryption(address, owner.pubkey(), expected.merge_encryption),
        ],
        &[&owner],
    )
    .unwrap();
    let mut expected_account = before;
    let mut header = vec![UserRecord::DISCRIMINATOR];
    header.extend(borsh::to_vec(&expected).unwrap());
    expected_account
        .data
        .get_mut(..UserRecord::SIZE)
        .unwrap()
        .copy_from_slice(&header);
    assert_eq!(rig.svm.get_account(&address), Some(expected_account));
}

#[test]
fn appends_and_key_updates_support_data_larger_than_the_program_heap() {
    let mut rig = UserRegistryTestRig::new();
    let owner = funded_keypair(&mut rig);
    let payer = funded_keypair(&mut rig);
    register(&mut rig, &owner, keys(1));
    let address = user_record_pda(&owner.pubkey()).0;
    let mut expected_data = Vec::new();
    for byte in 0..14 {
        let chunk = vec![byte; 2800];
        rig.send(append(&owner, &payer, chunk.clone()), &[&owner, &payer])
            .unwrap();
        expected_data.extend(chunk);
    }
    // Two appends in one transaction also exercise resizing after a rent CPI
    // has already seen the first instruction's larger account.
    rig.send_all(
        &[
            append(&owner, &payer, vec![254]),
            append(&owner, &payer, vec![255]),
            rotate(&owner),
        ],
        &[&owner, &payer],
    )
    .unwrap();
    expected_data.extend([254, 255]);
    let account = rig.svm.get_account(&address).unwrap();
    assert_eq!(
        UserRecord::additional_data(&account.data).unwrap(),
        expected_data
    );
    assert_eq!(
        rig.record(&owner.pubkey()).nullifier_pubkey,
        keys(9).nullifier
    );
    assert_eq!(
        account.data.len(),
        UserRecord::SIZE + UserRecord::DATA_LEN_SIZE + expected_data.len()
    );
}

#[test]
fn new_instructions_reject_invalid_authorization_and_accounts_atomically() {
    for is_append in [true, false] {
        for case in [
            "owner",
            "unsigned_owner",
            "readonly",
            "wrong_pda",
            "wrong_program",
            "discriminator",
            "extension",
            "missing_accounts",
            "payload",
            "trailing_payload",
        ] {
            let mut rig = UserRegistryTestRig::new();
            let owner = funded_keypair(&mut rig);
            let payer = funded_keypair(&mut rig);
            let stranger = funded_keypair(&mut rig);
            register(&mut rig, &owner, keys(1));
            let address = user_record_pda(&owner.pubkey()).0;
            let mut ix = if is_append {
                append(&owner, &payer, vec![1])
            } else {
                rotate(&owner)
            };
            let mut signers = vec![&owner];
            if is_append {
                signers.push(&payer);
            }
            let expected = match case {
                "owner" => {
                    ix.accounts.get_mut(1).unwrap().pubkey = stranger.pubkey();
                    *signers.first_mut().unwrap() = &stranger;
                    InstructionError::Custom(UserRegistryError::OwnerMismatch as u32)
                }
                "unsigned_owner" => {
                    ix.accounts.get_mut(1).unwrap().is_signer = false;
                    signers.remove(0);
                    InstructionError::MissingRequiredSignature
                }
                "readonly" => {
                    ix.accounts.first_mut().unwrap().is_writable = false;
                    InstructionError::Custom(UserRegistryError::InvalidRecordAccount as u32)
                }
                "wrong_pda" => {
                    let mut record = rig.svm.get_account(&address).unwrap();
                    let mut header = rig.record(&owner.pubkey());
                    header.bump = header.bump.wrapping_sub(1);
                    record.data = vec![UserRecord::DISCRIMINATOR];
                    record.data.extend(borsh::to_vec(&header).unwrap());
                    rig.svm.set_account(address, record).unwrap();
                    InstructionError::Custom(UserRegistryError::InvalidRecordPda as u32)
                }
                "wrong_program" | "discriminator" | "extension" => {
                    let mut record = rig.svm.get_account(&address).unwrap();
                    match case {
                        "wrong_program" => record.owner = solana_pubkey::Pubkey::default(),
                        "discriminator" => *record.data.first_mut().unwrap() = 255,
                        _ => record.data.extend([1, 0, 0, 0]),
                    }
                    rig.svm.set_account(address, record).unwrap();
                    InstructionError::Custom(UserRegistryError::InvalidRecordAccount as u32)
                }
                "missing_accounts" => {
                    ix.accounts.pop();
                    if !is_append {
                        signers.clear();
                    }
                    #[allow(deprecated)]
                    let error = InstructionError::NotEnoughAccountKeys;
                    error
                }
                "payload" => {
                    ix.data.pop();
                    InstructionError::Custom(UserRegistryError::InvalidInstructionData as u32)
                }
                _ => {
                    ix.data.push(0);
                    InstructionError::Custom(UserRegistryError::InvalidInstructionData as u32)
                }
            };
            // Keep only signers whose account still appears as a signer meta.
            signers.retain(|signer| {
                ix.accounts
                    .iter()
                    .any(|meta| meta.pubkey == signer.pubkey() && meta.is_signer)
            });
            let before = rig.svm.get_account(&address).unwrap();
            let payer_before = rig.svm.get_account(&payer.pubkey()).unwrap();
            let failure = rig.send(ix, &signers).expect_err(case);
            assert_eq!(
                failure.err,
                TransactionError::InstructionError(0, expected),
                "append={is_append} case={case}; {}",
                failure.meta.pretty_logs()
            );
            assert_eq!(rig.svm.get_account(&address), Some(before));
            assert_eq!(rig.svm.get_account(&payer.pubkey()), Some(payer_before));
        }
    }
}

#[test]
fn append_rejects_invalid_payer_and_system_program_atomically() {
    for case in [
        "unsigned_payer",
        "readonly_payer",
        "unfunded_payer",
        "system_program",
    ] {
        let mut rig = UserRegistryTestRig::new();
        let owner = funded_keypair(&mut rig);
        let payer = funded_keypair(&mut rig);
        register(&mut rig, &owner, keys(1));
        let address = user_record_pda(&owner.pubkey()).0;
        let mut ix = append(&owner, &payer, vec![7]);
        let mut signers = vec![&owner, &payer];
        let expected = match case {
            "unsigned_payer" => {
                ix.accounts.get_mut(2).unwrap().is_signer = false;
                signers.pop();
                InstructionError::MissingRequiredSignature
            }
            "readonly_payer" => {
                ix.accounts.get_mut(2).unwrap().is_writable = false;
                InstructionError::PrivilegeEscalation
            }
            "unfunded_payer" => {
                rig.svm
                    .set_account(payer.pubkey(), solana_account::Account::default())
                    .unwrap();
                InstructionError::Custom(1) // SystemError::ResultWithNegativeLamports
            }
            _ => {
                ix.accounts.get_mut(3).unwrap().pubkey = owner.pubkey();
                InstructionError::Custom(UserRegistryError::InvalidSystemProgram as u32)
            }
        };
        let before = rig.svm.get_account(&address).unwrap();
        let payer_before = rig.svm.get_account(&payer.pubkey());
        let failure = rig.send(ix, &signers).expect_err(case);
        assert_eq!(
            failure.err,
            TransactionError::InstructionError(0, expected),
            "case={case}; {}",
            failure.meta.pretty_logs()
        );
        assert_eq!(rig.svm.get_account(&address), Some(before));
        assert_eq!(rig.svm.get_account(&payer.pubkey()), payer_before);
    }
}
