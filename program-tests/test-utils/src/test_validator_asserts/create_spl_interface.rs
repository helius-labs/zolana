use rings_client::{ClientError, Rpc};
use rings_interface::{
    pda,
    state::{
        discriminator::{SPL_ASSET_COUNTER, SPL_ASSET_REGISTRY},
        SplAssetCounter, SplAssetRegistry,
    },
};
use solana_address::Address;
use solana_pubkey::Pubkey;

use super::{fetch_account, fetch_state, token_amount};

const TOKEN_ACCOUNT_MINT_OFFSET: usize = 0;
const TOKEN_ACCOUNT_OWNER_OFFSET: usize = 32;
const TOKEN_ACCOUNT_OWNER_END: usize = 64;

#[track_caller]
pub fn assert_create_spl_interface<R: Rpc>(
    rpc: &R,
    registry: &Pubkey,
    vault: &Pubkey,
    mint: &Pubkey,
    expected_asset_id: u64,
    expected_next_asset_id: u64,
) -> Result<(), ClientError> {
    let record: SplAssetRegistry = fetch_state(rpc, registry)?;
    assert_eq!(
        record,
        SplAssetRegistry {
            discriminator: SPL_ASSET_REGISTRY,
            reserved: [0u8; 7],
            mint: Address::new_from_array(mint.to_bytes()),
            asset_id: expected_asset_id,
        },
        "spl asset registry"
    );

    let counter: SplAssetCounter = fetch_state(rpc, &pda::spl_asset_counter())?;
    assert_eq!(
        counter,
        SplAssetCounter {
            discriminator: SPL_ASSET_COUNTER,
            reserved: [0u8; 7],
            next_id: expected_next_asset_id,
        },
        "spl asset counter"
    );

    let vault_account = fetch_account(rpc, vault)?;
    assert_eq!(
        vault_account
            .data
            .get(TOKEN_ACCOUNT_MINT_OFFSET..TOKEN_ACCOUNT_OWNER_OFFSET)
            .expect("vault mint slice"),
        mint.as_ref(),
        "vault mint"
    );
    assert_eq!(
        vault_account
            .data
            .get(TOKEN_ACCOUNT_OWNER_OFFSET..TOKEN_ACCOUNT_OWNER_END)
            .expect("vault owner slice"),
        pda::shielded_pool_cpi_authority().as_ref(),
        "vault owner is the SPL vault authority"
    );
    assert_eq!(token_amount(&vault_account), 0, "vault balance");
    Ok(())
}
