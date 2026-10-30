use spr_transaction::{Address, AssetRegistry, Mint, TransactionError, SOL_ASSET_ID, SOL_MINT};

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
        let field = spr_hasher::primitives::hash_bytes(address.as_array()).unwrap();
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
    assert_eq!(registry.asset_id(&b).unwrap(), 3);
    assert_eq!(registry.asset_id(&a).unwrap(), 2);
}

#[test]
fn extending_a_registry_accepts_identical_mappings_and_adds_unknown_ones() {
    let first_mint = Address::new_from_array([7; 32]);
    let second_mint = Address::new_from_array([8; 32]);
    let mut registry = AssetRegistry::new([(2, first_mint)]).unwrap();
    let discoveries = AssetRegistry::new([(2, first_mint), (3, second_mint)]).unwrap();
    registry.extend(&discoveries).unwrap();
    registry.extend(&discoveries).unwrap();
    assert_eq!(registry, discoveries);
}

#[test]
fn conflicting_registry_extensions_leave_every_mapping_unchanged() {
    let first_mint = Address::new_from_array([7; 32]);
    let second_mint = Address::new_from_array([8; 32]);
    let third_mint = Address::new_from_array([9; 32]);
    for (conflict, expected) in [
        ((2, third_mint), TransactionError::DuplicateAssetId(2)),
        ((4, first_mint), TransactionError::DuplicateMint(first_mint)),
    ] {
        let mut registry = AssetRegistry::new([(2, first_mint)]).unwrap();
        let before = registry.clone();
        let discoveries = AssetRegistry::new([(3, second_mint), conflict]).unwrap();
        assert_eq!(registry.extend(&discoveries), Err(expected));
        assert_eq!(registry, before);
    }
}
