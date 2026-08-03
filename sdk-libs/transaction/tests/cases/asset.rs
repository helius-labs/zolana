use zolana_transaction::{Address, AssetRegistry, TransactionError, SOL_ASSET_ID};

pub(crate) fn sol_resolves() {
    let registry = AssetRegistry::default();
    assert_eq!(registry.resolve(SOL_ASSET_ID).unwrap(), Address::default());
}

pub(crate) fn spl_resolves_both_ways() {
    let mint = Address::new_from_array([7u8; 32]);
    let registry = AssetRegistry::new([(2, mint)]).unwrap();
    assert_eq!(registry.resolve(2).unwrap(), mint);
    assert_eq!(registry.asset_id(&mint).unwrap(), 2);
}

pub(crate) fn unknown_asset_id() {
    let registry = AssetRegistry::new([(2, Address::new_from_array([7u8; 32]))]).unwrap();
    assert_eq!(
        registry.resolve(9).unwrap_err(),
        TransactionError::UnknownAsset(9)
    );
}

pub(crate) fn unknown_mint() {
    let registry = AssetRegistry::default();
    let mint = Address::new_from_array([8u8; 32]);
    assert_eq!(
        registry.asset_id(&mint).unwrap_err(),
        TransactionError::UnknownMint(mint)
    );
}

pub(crate) fn duplicate_asset_id() {
    assert_eq!(
        AssetRegistry::new([
            (2, Address::new_from_array([7u8; 32])),
            (2, Address::new_from_array([8u8; 32])),
        ])
        .unwrap_err(),
        TransactionError::DuplicateAssetId(2)
    );
}

pub(crate) fn duplicate_mint() {
    let mint = Address::new_from_array([7u8; 32]);
    assert_eq!(
        AssetRegistry::new([(2, mint), (3, mint)]).unwrap_err(),
        TransactionError::DuplicateMint(mint)
    );
}

pub(crate) fn sol_reserved() {
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
