#![cfg(feature = "solana")]

use solana_instruction::Instruction;
use solana_pubkey::Pubkey;
use zolana_user_registry_interface::{
    instruction::{register, set_merging_enabled, update_keys, RegisterData, UpdateKeysData},
    user_record_pda,
};

fn instruction_line(name: &str, instruction: Instruction) -> String {
    let hex: String = instruction
        .data
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let accounts = instruction
        .accounts
        .iter()
        .map(|account| {
            format!(
                "{}:{}:{}",
                account.pubkey,
                u8::from(account.is_writable),
                u8::from(account.is_signer)
            )
        })
        .collect::<Vec<_>>()
        .join(" ");
    format!("{name} {} {hex} {accounts}\n", instruction.program_id)
}

#[test]
fn typescript_registry_wire_matches_rust() {
    let mut expected = String::new();
    for byte in [0, 7, 255] {
        let owner = Pubkey::new_from_array([byte; 32]);
        let (record, bump) = user_record_pda(&owner);
        expected.push_str(&format!("pda {owner} {record} {bump}\n"));
    }
    let owner = Pubkey::new_from_array([7; 32]);
    let (record, _) = user_record_pda(&owner);
    let nullifier_pubkey = std::array::from_fn(|index| index as u8);
    let viewing_pubkey = std::array::from_fn(|index| (index + 32) as u8);
    expected.push_str(&instruction_line(
        "register",
        register(
            record,
            owner,
            RegisterData {
                owner_p256: None,
                nullifier_pubkey,
                viewing_pubkey,
            },
        ),
    ));
    expected.push_str(&instruction_line(
        "updateKeys",
        update_keys(
            record,
            owner,
            UpdateKeysData {
                owner_p256: None,
                nullifier_pubkey,
                viewing_pubkey,
            },
        ),
    ));
    expected.push_str(&instruction_line(
        "enableMerging",
        set_merging_enabled(record, owner, true),
    ));
    expected.push_str(&instruction_line(
        "disableMerging",
        set_merging_enabled(record, owner, false),
    ));

    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../sdk-libs/ts/fixtures/user-registry.txt"
    );
    if std::env::var_os("UPDATE_USER_REGISTRY_FIXTURES").is_some() {
        std::fs::write(fixture, &expected).unwrap();
    }
    assert_eq!(std::fs::read_to_string(fixture).unwrap(), expected);
}
