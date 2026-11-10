use serde_json::{json, Value};
use solana_address::Address;
use solana_instruction::Instruction;
use solana_pubkey::Pubkey;
use spr_protocol_instructions::CreateProtocolConfig;

const PROTOCOL_CONFIG_VECTORS_JSON: &str =
    include_str!("../../../test-vectors/create_protocol_config.json");

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn address(seed: u8) -> Address {
    Address::new_from_array([seed; 32])
}

fn instruction_vector(instruction: &Instruction) -> Value {
    json!({
        "programAddress": instruction.program_id.to_string(),
        "data": hex(&instruction.data),
        "accounts": instruction
            .accounts
            .iter()
            .map(|meta| {
                json!({
                    "address": meta.pubkey.to_string(),
                    "signer": meta.is_signer,
                    "writable": meta.is_writable,
                })
            })
            .collect::<Vec<_>>(),
    })
}

fn compute_protocol_config_vectors() -> Value {
    let builder = CreateProtocolConfig {
        fee_payer: Pubkey::new_from_array([0x11; 32]),
        initialization_authority: Pubkey::new_from_array([0x22; 32]),
        protocol_authority: address(1),
        tree_creation_authority: address(2),
        tree_creation_is_permissionless: true,
        forester_authority: address(3),
        ring_creation_authority: address(4),
        ring_activation_is_permissionless: false,
        spl_interface_creation_is_permissionless: true,
        fee_authority: address(5),
    };
    json!({
        "description": "The create_protocol_config instruction the TypeScript SDK must reproduce. Regenerate with `cargo test -p spr-protocol-instructions --test protocol_config_vectors print_protocol_config_vectors -- --ignored --nocapture`.",
        "feePayer": builder.fee_payer.to_string(),
        "initializationAuthority": builder.initialization_authority.to_string(),
        "protocolAuthority": builder.protocol_authority.to_string(),
        "treeCreationAuthority": builder.tree_creation_authority.to_string(),
        "treeCreationIsPermissionless": builder.tree_creation_is_permissionless,
        "foresterAuthority": builder.forester_authority.to_string(),
        "ringCreationAuthority": builder.ring_creation_authority.to_string(),
        "ringActivationIsPermissionless": builder.ring_activation_is_permissionless,
        "splInterfaceCreationIsPermissionless": builder.spl_interface_creation_is_permissionless,
        "feeAuthority": builder.fee_authority.to_string(),
        "instruction": instruction_vector(&builder.instruction()),
    })
}

#[test]
fn create_protocol_config_matches_the_shared_vector() {
    let committed: Value =
        serde_json::from_str(PROTOCOL_CONFIG_VECTORS_JSON).expect("shared protocol config vector");
    assert_eq!(committed, compute_protocol_config_vectors());
}

#[test]
#[ignore = "regenerates test-vectors/create_protocol_config.json; run with --nocapture and commit the output"]
fn print_protocol_config_vectors() {
    println!(
        "{}",
        serde_json::to_string_pretty(&compute_protocol_config_vectors()).expect("json")
    );
}
