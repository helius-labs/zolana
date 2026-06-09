use cucumber::then;
use zolana_transaction::asset::{AssetRegistry, SOL_ASSET_ID};
use zolana_transaction::{Address, TransactionError};

use crate::TransactionWorld;

#[then(expr = "the asset registry resolves SOL to the default address")]
fn sol_resolves(_world: &mut TransactionWorld) {
    let registry = AssetRegistry::default();
    assert_eq!(registry.resolve(SOL_ASSET_ID).unwrap(), Address::default());
}

#[then(expr = "a registered SPL mint resolves both ways")]
fn spl_resolves_both_ways(_world: &mut TransactionWorld) {
    let mint = Address::new_from_array([7u8; 32]);
    let registry = AssetRegistry::new([(2, mint)]);
    assert_eq!(registry.resolve(2).unwrap(), mint);
    assert_eq!(registry.asset_id(&mint).unwrap(), 2);
}

#[then(expr = "resolving an unknown asset id fails")]
fn unknown_asset_id(_world: &mut TransactionWorld) {
    let registry = AssetRegistry::new([(2, Address::new_from_array([7u8; 32]))]);
    assert_eq!(
        registry.resolve(9).unwrap_err(),
        TransactionError::UnknownAsset(9)
    );
}

#[then(expr = "resolving an unknown mint fails")]
fn unknown_mint(_world: &mut TransactionWorld) {
    let registry = AssetRegistry::default();
    let mint = Address::new_from_array([8u8; 32]);
    assert_eq!(
        registry.asset_id(&mint).unwrap_err(),
        TransactionError::UnknownMint(mint)
    );
}

#[then(expr = "SOL stays canonical when a bogus SOL entry is supplied")]
fn sol_canonical(_world: &mut TransactionWorld) {
    let registry = AssetRegistry::new([
        (SOL_ASSET_ID, Address::new_from_array([9u8; 32])),
        (2, Address::new_from_array([7u8; 32])),
    ]);
    assert_eq!(registry.resolve(SOL_ASSET_ID).unwrap(), Address::default());
}
