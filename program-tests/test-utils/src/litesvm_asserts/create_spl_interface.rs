//! Post-instruction checks for `create_spl_interface` (registry + vault).

use solana_pubkey::Pubkey;
use zolana_interface::{
    pda,
    state::{discriminator::SPL_ASSET_REGISTRY, SplAssetCounter, SplAssetRegistry},
};
use zolana_program_test::ZolanaProgramTest;

const TOKEN_ACCOUNT_MINT_OFFSET: usize = 0;
const TOKEN_ACCOUNT_OWNER_OFFSET: usize = 32;
const TOKEN_ACCOUNT_OWNER_END: usize = 64;

/// Verify the registry, asset counter, and vault initialized by
/// `create_spl_interface` against the integration-test expectations: the
/// registry carries the discriminator, the mint, and `expected_asset_id`; the
/// counter now points at `expected_next_asset_id`; and the vault is an empty
/// token account for the mint owned by the SPL vault authority.
#[track_caller]
pub fn litesvm_assert_create_spl_interface(
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
    let record: &SplAssetRegistry = bytemuck::from_bytes(&registry_data);
    assert_eq!(
        record.discriminator, SPL_ASSET_REGISTRY,
        "registry discriminator"
    );
    assert_eq!(record.mint.to_bytes(), mint.to_bytes(), "registry mint");
    assert_eq!(record.asset_id, expected_asset_id, "registry asset id");

    let counter_data = program_test
        .account_data(&pda::spl_asset_counter())
        .expect("counter exists");
    let counter: &SplAssetCounter = bytemuck::from_bytes(&counter_data);
    assert_eq!(counter.next_id, expected_next_asset_id, "next SPL asset id");

    let vault_data = program_test.account_data(vault).expect("vault exists");
    assert_eq!(
        &vault_data[TOKEN_ACCOUNT_MINT_OFFSET..TOKEN_ACCOUNT_OWNER_OFFSET],
        mint.as_ref(),
        "vault mint"
    );
    assert_eq!(
        &vault_data[TOKEN_ACCOUNT_OWNER_OFFSET..TOKEN_ACCOUNT_OWNER_END],
        pda::shielded_pool_cpi_authority().as_ref(),
        "vault owner is the SPL vault authority"
    );
    assert_eq!(program_test.token_balance(vault), Some(0), "vault balance");
}
