//! Post-instruction checks for `create_spl_interface` (registry + vault).

use solana_pubkey::Pubkey;
use zolana_interface::{
    SPL_ASSET_REGISTRY_ASSET_ID_OFFSET, SPL_ASSET_REGISTRY_MAGIC, SPL_ASSET_REGISTRY_MAGIC_END,
    SPL_ASSET_REGISTRY_MAGIC_OFFSET, SPL_ASSET_REGISTRY_MINT_END, SPL_ASSET_REGISTRY_MINT_OFFSET,
};
use zolana_program_test::ZolanaProgramTest;

const TOKEN_ACCOUNT_MINT_OFFSET: usize = 0;
const TOKEN_ACCOUNT_OWNER_OFFSET: usize = 32;
const TOKEN_ACCOUNT_OWNER_END: usize = 64;

fn read_le_u64(data: &[u8], offset: usize) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&data[offset..offset + 8]);
    u64::from_le_bytes(bytes)
}

/// Verify the registry, asset counter, and vault initialized by
/// `create_spl_interface` against the integration-test expectations: the
/// registry carries the magic, the mint, and `expected_asset_id`; the counter
/// now points at `expected_next_asset_id`; and the vault is an empty token
/// account for the mint owned by the SPL vault authority.
#[track_caller]
pub fn assert_create_spl_interface(
    program_test: &ZolanaProgramTest,
    registry: &Pubkey,
    vault: &Pubkey,
    mint: &Pubkey,
    expected_asset_id: u64,
    expected_next_asset_id: u64,
) {
    let registry_data = program_test
        .account_data(registry)
        .expect("registry exists");
    assert_eq!(
        &registry_data[SPL_ASSET_REGISTRY_MAGIC_OFFSET..SPL_ASSET_REGISTRY_MAGIC_END],
        SPL_ASSET_REGISTRY_MAGIC.as_slice(),
        "registry magic"
    );
    assert_eq!(
        &registry_data[SPL_ASSET_REGISTRY_MINT_OFFSET..SPL_ASSET_REGISTRY_MINT_END],
        mint.as_ref(),
        "registry mint"
    );
    assert_eq!(
        read_le_u64(&registry_data, SPL_ASSET_REGISTRY_ASSET_ID_OFFSET),
        expected_asset_id,
        "registry asset id"
    );

    let counter_data = program_test
        .account_data(&program_test.spl_asset_counter_pda())
        .expect("counter exists");
    assert_eq!(
        read_le_u64(&counter_data, 0),
        expected_next_asset_id,
        "next SPL asset id"
    );

    let vault_data = program_test.account_data(vault).expect("vault exists");
    assert_eq!(
        &vault_data[TOKEN_ACCOUNT_MINT_OFFSET..TOKEN_ACCOUNT_OWNER_OFFSET],
        mint.as_ref(),
        "vault mint"
    );
    assert_eq!(
        &vault_data[TOKEN_ACCOUNT_OWNER_OFFSET..TOKEN_ACCOUNT_OWNER_END],
        program_test.spl_vault_authority().as_ref(),
        "vault owner is the SPL vault authority"
    );
    assert_eq!(program_test.token_balance(vault), Some(0), "vault balance");
}
