use zolana_transaction::{Address, AssetRegistry, Mint, TransactionError, SOL_ASSET_ID, SOL_MINT};

#[test]
fn asset_registry_is_bijective_and_reserves_sol() {
    let a = Address::new_from_array([7; 32]);
    let b = Address::new_from_array([8; 32]);
    let registry = AssetRegistry::new([(2, a), (99, b)]).unwrap();
    for (id, address) in [(SOL_ASSET_ID, SOL_MINT), (2, a), (99, b)] {
        let expected = Mint::new(address, id);
        assert_eq!(registry.resolve(id).unwrap(), expected);
        assert_eq!(registry.mint(&address).unwrap(), expected);
        assert_eq!(registry.asset_id(&address).unwrap(), id);
        let field = zolana_hasher::primitives::hash_bytes(address.as_array()).unwrap();
        assert_eq!(registry.address_for_field(&field).unwrap(), Some(address));
    }
    assert_eq!(registry.resolve(3), Err(TransactionError::UnknownAsset(3)));
    let absent = Address::new_from_array([9; 32]);
    assert_eq!(
        registry.mint(&absent),
        Err(TransactionError::UnknownMint(absent))
    );
    assert_eq!(
        registry.asset_id(&absent),
        Err(TransactionError::UnknownMint(absent))
    );
    assert_eq!(registry.address_for_field(&[255; 32]).unwrap(), None);
}

#[test]
fn rejected_registry_insertions_are_atomic() {
    let a = Address::new_from_array([7; 32]);
    let b = Address::new_from_array([8; 32]);
    let mut registry = AssetRegistry::new([(2, a)]).unwrap();
    for (id, mint, expected) in [
        (
            SOL_ASSET_ID,
            b,
            TransactionError::ReservedAssetId(SOL_ASSET_ID),
        ),
        (2, b, TransactionError::DuplicateAssetId(2)),
        (3, a, TransactionError::DuplicateMint(a)),
        (3, SOL_MINT, TransactionError::DuplicateMint(SOL_MINT)),
    ] {
        let before = registry.clone();
        assert_eq!(registry.insert(id, mint), Err(expected));
        assert_eq!(registry, before);
    }
    registry.insert(3, b).unwrap();
    assert_eq!(registry.resolve(3).unwrap(), Mint::new(b, 3));
}
