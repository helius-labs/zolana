mod common;

use solana_account::Account;
use solana_instruction::{error::InstructionError, Instruction};
use solana_keypair::Keypair;
use solana_signer::Signer;
use solana_transaction_error::TransactionError;
use spr_user_registry::error::UserRegistryError;
use spr_user_registry_interface::{
    instruction::{self, RegisterData, SetData, UpdateKeysData},
    user_record_pda, MergeEncryptionScheme, UserRecord,
};
use user_registry_tests::UserRegistryTestRig;

use common::{funded_keypair, keys, register};

fn set(owner: &Keypair, rent_payer: &Keypair, data: Vec<u8>) -> Instruction {
    instruction::set_data(
        user_record_pda(&owner.pubkey()).0,
        owner.pubkey(),
        rent_payer.pubkey(),
        SetData { data },
    )
}

/// The account bytes after `set_data(data)` on a record with this header.
fn with_data(header: &[u8], data: &[u8]) -> Vec<u8> {
    let mut account = header.to_vec();
    if !data.is_empty() {
        account.extend(u32::try_from(data.len()).unwrap().to_le_bytes());
        account.extend(data);
    }
    account
}

#[test]
fn set_data_resizes_the_record_and_charges_only_missing_rent() {
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
    let registered = rig.svm.get_account(&record_address).unwrap();
    let mut expected_lamports = registered.lamports;
    let mut payer_balance = rig.svm.get_balance(&rent_payer.pubkey()).unwrap();
    // Grow, grow, shrink, then clear back to the header-only layout.
    for data in [vec![0, 1, 255], vec![7; 512], vec![9, 9], Vec::new()] {
        rig.send(
            set(&owner, &rent_payer, data.clone()),
            &[&owner, &rent_payer],
        )
        .unwrap();
        let expected_data = with_data(&registered.data, &data);
        let rent = rig
            .svm
            .minimum_balance_for_rent_exemption(expected_data.len());
        // Growth charges the payer the missing rent; shrinking refunds nothing.
        let top_up = rent.saturating_sub(expected_lamports);
        expected_lamports += top_up;
        payer_balance -= top_up;
        assert_eq!(
            rig.svm.get_account(&record_address),
            Some(Account {
                lamports: expected_lamports,
                data: expected_data,
                ..registered.clone()
            }),
            "data {data:?}"
        );
        assert_eq!(
            rig.svm.get_balance(&rent_payer.pubkey()),
            Some(payer_balance)
        );
        assert_eq!(rig.svm.get_balance(&owner.pubkey()).unwrap_or(0), 0);
    }
}

#[test]
fn set_data_uses_existing_excess_lamports_before_charging_the_rent_payer() {
    let mut rig = UserRegistryTestRig::new();
    let owner = funded_keypair(&mut rig);
    let rent_payer = funded_keypair(&mut rig);
    register(&mut rig, &owner, keys(1));
    let address = user_record_pda(&owner.pubkey()).0;
    let mut account = rig.svm.get_account(&address).unwrap();
    account.lamports += 1_000_000;
    rig.svm.set_account(address, account.clone()).unwrap();
    let payer_before = rig.svm.get_account(&rent_payer.pubkey()).unwrap();
    rig.send(set(&owner, &rent_payer, vec![42]), &[&owner, &rent_payer])
        .unwrap();
    assert_eq!(
        rig.svm.get_account(&rent_payer.pubkey()),
        Some(payer_before)
    );
    assert_eq!(
        rig.svm.get_account(&address),
        Some(Account {
            data: with_data(&account.data, &[42]),
            ..account
        })
    );
}

#[test]
fn existing_mutations_preserve_record_data_and_the_nullifier_key() {
    let mut rig = UserRegistryTestRig::new();
    let owner = funded_keypair(&mut rig);
    let payer = funded_keypair(&mut rig);
    register(&mut rig, &owner, keys(1));
    let address = user_record_pda(&owner.pubkey()).0;
    let mut expected = rig.record(&owner.pubkey());
    rig.send(set(&owner, &payer, vec![3, 4, 5]), &[&owner, &payer])
        .unwrap();
    let before = rig.svm.get_account(&address).unwrap();
    expected.viewing_pubkey = keys(11).viewing;
    expected.merge_encryption = MergeEncryptionScheme::PoseidonCtrV1;
    rig.send_all(
        &[
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
    let mut header = vec![UserRecord::DISCRIMINATOR];
    header.extend(borsh::to_vec(&expected).unwrap());
    assert_eq!(
        rig.svm.get_account(&address),
        Some(Account {
            data: with_data(&header, &[3, 4, 5]),
            ..before
        })
    );
}

#[test]
fn last_set_data_in_a_transaction_replaces_earlier_data() {
    let mut rig = UserRegistryTestRig::new();
    let owner = funded_keypair(&mut rig);
    let payer = funded_keypair(&mut rig);
    register(&mut rig, &owner, keys(1));
    let address = user_record_pda(&owner.pubkey()).0;
    let large = vec![5; 3000];
    rig.send(set(&owner, &payer, large.clone()), &[&owner, &payer])
        .unwrap();
    assert_eq!(
        UserRecord::additional_data(&rig.svm.get_account(&address).unwrap().data).unwrap(),
        large
    );
    let header_before = rig.record(&owner.pubkey());
    rig.send_all(
        &[
            set(&owner, &payer, vec![1; 2000]),
            set(&owner, &payer, vec![254, 255]),
        ],
        &[&owner, &payer],
    )
    .unwrap();
    let account = rig.svm.get_account(&address).unwrap();
    let mut header = vec![UserRecord::DISCRIMINATOR];
    header.extend(borsh::to_vec(&header_before).unwrap());
    assert_eq!(account.data, with_data(&header, &[254, 255]));
}

#[test]
fn unsupported_tag_cannot_change_the_nullifier_key() {
    let mut rig = UserRegistryTestRig::new();
    let owner = funded_keypair(&mut rig);
    let payer = funded_keypair(&mut rig);
    register(&mut rig, &owner, keys(1));
    let address = user_record_pda(&owner.pubkey()).0;
    let before = rig.svm.get_account(&address).unwrap();
    let mut ix = set(&owner, &payer, Vec::new());
    ix.accounts.truncate(2);
    ix.data = vec![4];
    ix.data.extend(keys(9).nullifier);

    let failure = rig
        .send(ix, &[&owner])
        .expect_err("unsupported instruction tag");
    assert_eq!(
        failure.err,
        TransactionError::InstructionError(0, InstructionError::InvalidInstructionData)
    );
    assert_eq!(rig.svm.get_account(&address), Some(before));
}

#[test]
fn set_data_rejects_invalid_authorization_and_accounts_atomically() {
    for case in [
        "owner",
        "unsigned_owner",
        "readonly",
        "wrong_pda",
        "wrong_program",
        "discriminator",
        "extension",
        "trailing_extension",
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
        let mut ix = set(&owner, &payer, vec![1]);
        let mut signers = vec![&owner, &payer];
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
            "wrong_program" | "discriminator" | "extension" | "trailing_extension" => {
                let mut record = rig.svm.get_account(&address).unwrap();
                match case {
                    "wrong_program" => record.owner = solana_pubkey::Pubkey::default(),
                    "discriminator" => *record.data.first_mut().unwrap() = 255,
                    "trailing_extension" => record.data.extend([0, 0, 0, 0, 7]),
                    _ => record.data.extend([1, 0, 0, 0]),
                }
                rig.svm.set_account(address, record).unwrap();
                InstructionError::Custom(UserRegistryError::InvalidRecordAccount as u32)
            }
            "missing_accounts" => {
                ix.accounts.pop();
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
            "case={case}; {}",
            failure.meta.pretty_logs()
        );
        assert_eq!(rig.svm.get_account(&address), Some(before));
        assert_eq!(rig.svm.get_account(&payer.pubkey()), Some(payer_before));
    }
}

#[test]
fn set_data_rejects_invalid_payer_and_system_program_atomically() {
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
        let mut ix = set(&owner, &payer, vec![7]);
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
                    .set_account(payer.pubkey(), Account::default())
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
