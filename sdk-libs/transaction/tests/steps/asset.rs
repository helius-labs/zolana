use cucumber::then;
use zolana_transaction::{
    asset::{AssetRegistry, SOL_ASSET_ID},
    Address, TransactionError,
};

use crate::TransactionWorld;

#[then(expr = "the asset registry resolves SOL to the default address")]
fn sol_resolves(_world: &mut TransactionWorld) {
    let registry = AssetRegistry::default();
    assert_eq!(registry.resolve(SOL_ASSET_ID).unwrap(), Address::default());
}

#[then(expr = "a registered SPL mint resolves both ways")]
fn spl_resolves_both_ways(_world: &mut TransactionWorld) {
    let mint = Address::new_from_array([7u8; 32]);
    let registry = AssetRegistry::new([(2, mint)]).unwrap();
    assert_eq!(registry.resolve(2).unwrap(), mint);
    assert_eq!(registry.asset_id(&mint).unwrap(), 2);
}

#[then(expr = "resolving an unknown asset id fails")]
fn unknown_asset_id(_world: &mut TransactionWorld) {
    let registry = AssetRegistry::new([(2, Address::new_from_array([7u8; 32]))]).unwrap();
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

#[then(expr = "a duplicate asset id is rejected")]
fn duplicate_asset_id(_world: &mut TransactionWorld) {
    assert_eq!(
        AssetRegistry::new([
            (2, Address::new_from_array([7u8; 32])),
            (2, Address::new_from_array([8u8; 32])),
        ])
        .unwrap_err(),
        TransactionError::DuplicateAssetId(2)
    );
}

#[then(expr = "a duplicate mint is rejected")]
fn duplicate_mint(_world: &mut TransactionWorld) {
    let mint = Address::new_from_array([7u8; 32]);
    assert_eq!(
        AssetRegistry::new([(2, mint), (3, mint)]).unwrap_err(),
        TransactionError::DuplicateMint(mint)
    );
}

#[then(expr = "a SOL entry is rejected as reserved")]
fn sol_reserved(_world: &mut TransactionWorld) {
    assert_eq!(
        AssetRegistry::new([(SOL_ASSET_ID, Address::new_from_array([9u8; 32]))]).unwrap_err(),
        TransactionError::ReservedAssetId(SOL_ASSET_ID)
    );
    let mut registry = AssetRegistry::default();
    assert_eq!(
        registry
            .insert(SOL_ASSET_ID, Address::new_from_array([9u8; 32]))
            .unwrap_err(),
        TransactionError::ReservedAssetId(SOL_ASSET_ID)
    );
}
