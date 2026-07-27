use zolana_interface::instruction::{
    DepositAssetKind, DepositEntry, DepositIxData, DepositIxDataRef, UtxoData, ZoneDepositEntry,
    ZoneDepositIxData, ZoneDepositIxDataRef,
};

fn entry(seed: u8) -> DepositEntry {
    DepositEntry {
        asset_index: 0,
        view_tag: [seed; 32],
        owner: [seed.wrapping_add(1); 32],
        blinding: [seed.wrapping_add(2); 32],
        amount: u64::from(seed) + 1,
        utxo_data: Some(UtxoData {
            data_hash: [seed.wrapping_add(3); 32],
            data: vec![seed, seed.wrapping_add(1)],
        }),
        memo: Some(vec![seed.wrapping_add(2), seed.wrapping_add(3)]),
    }
}

fn aliases(buffer: &[u8], borrowed: &[u8]) -> bool {
    let start = buffer.as_ptr() as usize;
    let end = start + buffer.len();
    let borrowed_start = borrowed.as_ptr() as usize;
    let borrowed_end = borrowed_start + borrowed.len();
    borrowed_start >= start && borrowed_end <= end
}

#[test]
fn deposit_ref_borrows_variable_payloads() {
    let owned = DepositIxData {
        assets: vec![DepositAssetKind::Sol],
        deposits: vec![entry(7)],
    };
    let bytes = owned.serialize().unwrap();
    let borrowed = DepositIxDataRef::from_bytes(&bytes).unwrap();

    assert_eq!(borrowed.assets, owned.assets);
    assert_eq!(borrowed.deposits.len(), 1);
    let actual = borrowed.deposits[0];
    let expected = &owned.deposits[0];
    assert_eq!(actual.asset_index, expected.asset_index);
    assert_eq!(actual.view_tag, &expected.view_tag);
    assert_eq!(actual.owner, &expected.owner);
    assert_eq!(actual.blinding, &expected.blinding);
    assert_eq!(actual.amount, expected.amount);

    let actual_utxo = actual.utxo_data.unwrap();
    let expected_utxo = expected.utxo_data.as_ref().unwrap();
    assert_eq!(actual_utxo.data_hash, &expected_utxo.data_hash);
    assert_eq!(actual_utxo.data, expected_utxo.data);
    assert_eq!(actual.memo.unwrap(), expected.memo.as_deref().unwrap());
    assert!(aliases(&bytes, actual_utxo.data));
    assert!(aliases(&bytes, actual.memo.unwrap()));
    assert!(aliases(&bytes, actual.owner));
}

#[test]
fn zone_deposit_ref_borrows_zone_payload() {
    let owned = ZoneDepositIxData {
        assets: vec![DepositAssetKind::Spl { vault_bump: 42 }],
        deposits: vec![ZoneDepositEntry {
            deposit: entry(9),
            zone_data_hash: [10; 32],
            zone_data: vec![11, 12, 13],
        }],
    };
    let bytes = owned.serialize().unwrap();
    let borrowed = ZoneDepositIxDataRef::from_bytes(&bytes).unwrap();

    assert_eq!(borrowed.assets, owned.assets);
    assert_eq!(borrowed.deposits.len(), 1);
    let actual = borrowed.deposits[0];
    assert_eq!(actual.zone_data_hash, &owned.deposits[0].zone_data_hash);
    assert_eq!(actual.zone_data, owned.deposits[0].zone_data);
    assert!(aliases(&bytes, actual.zone_data_hash));
    assert!(aliases(&bytes, actual.zone_data));
}

#[test]
fn deposit_ref_rejects_trailing_bytes() {
    let mut bytes = DepositIxData {
        assets: vec![DepositAssetKind::Sol],
        deposits: vec![entry(1)],
    }
    .serialize()
    .unwrap();
    bytes.push(0xff);

    assert!(DepositIxDataRef::from_bytes(&bytes).is_err());
}
