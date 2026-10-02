//! What the chain says about an asset: the token program that owns an SPL
//! mint, and the asset id the shielded pool registered for it.

use solana_address::Address;
use zolana_interface::{pda, state::SplAssetRegistry, PROGRAM_ID_PUBKEY};
use zolana_transaction::{SOL_ASSET_ID, SOL_MINT};

use crate::{error::ClientError, rpc::Rpc};

/// The token program that owns the mint account of `asset`: SPL Token or
/// Token-2022. `None` for SOL, without a request.
pub fn fetch_token_program<R: Rpc>(
    rpc: &R,
    asset: Address,
) -> Result<Option<Address>, ClientError> {
    if asset == SOL_MINT {
        return Ok(None);
    }
    let owner = rpc
        .get_account(asset)?
        .ok_or(ClientError::SplMintNotFound { mint: asset })?
        .owner;
    if owner != pda::spl_token_program_id() && owner != pda::spl_token_2022_program_id() {
        return Err(ClientError::UnsupportedSplTokenProgram { mint: asset, owner });
    }
    Ok(Some(owner))
}

/// The asset id the shielded pool uses for `asset`: [`SOL_ASSET_ID`] for SOL,
/// without a request, and for an SPL mint the id in the registry account the
/// pool wrote when it registered the mint.
pub fn fetch_asset_id<R: Rpc>(rpc: &R, asset: Address) -> Result<u64, ClientError> {
    if asset == SOL_MINT {
        return Ok(SOL_ASSET_ID);
    }
    let not_registered = || ClientError::SplAssetNotRegistered { mint: asset };
    let account = rpc
        .get_account(pda::spl_asset_registry(&asset))?
        .ok_or_else(not_registered)?;
    // Only the pool can create an account at the registry address. Any other
    // owner means lamports were sent there, not that the mint was registered.
    if account.owner != PROGRAM_ID_PUBKEY {
        return Err(not_registered());
    }
    let invalid = || ClientError::InvalidSplAssetRegistry { mint: asset };
    let registry = SplAssetRegistry::from_account_bytes(&account.data).map_err(|_| invalid())?;
    if registry.mint != asset {
        return Err(invalid());
    }
    Ok(registry.asset_id)
}
