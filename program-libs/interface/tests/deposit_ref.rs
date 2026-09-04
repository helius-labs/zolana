use zolana_interface::instruction::{
    DepositAssetKind, DepositEntry, DepositIxData, DepositIxDataRef, EncryptedRingDepositData,
    RingDepositEntry, RingDepositIxData, RingDepositIxDataRef, UtxoData,
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

    assert_eq!(
        borrowed
            .assets
            .try_iter()
            .collect::<Result<Vec<_>, _>>()
            .unwrap(),
        owned.assets,
    );
    assert_eq!(borrowed.deposits.len(), 1);
    let actual = borrowed.deposits.first().unwrap().unwrap();
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
fn ring_deposit_ref_borrows_ring_payload() {
    let owned = RingDepositIxData {
        assets: vec![DepositAssetKind::Spl {
            spl_interface_bump: 42,
        }],
        deposits: vec![RingDepositEntry {
            asset_index: 0,
            view_tag: [9; 32],
            owner_utxo_hash: [10; 32],
            amount: 12,
            data_hash: Some([13; 32]),
            ring_data_hash: [10; 32],
            encrypted: EncryptedRingDepositData {
                tx_viewing_pk: [8; 33],
                salt: [9; 16],
                ciphertext: vec![11, 12, 13],
            },
        }],
    };
    let bytes = owned.serialize().unwrap();
    let borrowed = RingDepositIxDataRef::from_bytes(&bytes).unwrap();

    assert_eq!(
        borrowed
            .assets
            .try_iter()
            .collect::<Result<Vec<_>, _>>()
            .unwrap(),
        owned.assets,
    );
    assert_eq!(borrowed.deposits.len(), 1);
    let actual = borrowed.deposits.first().unwrap().unwrap();
    assert_eq!(actual.owner_utxo_hash, &owned.deposits[0].owner_utxo_hash);
    assert_eq!(actual.ring_data_hash, &owned.deposits[0].ring_data_hash);
    assert_eq!(
        actual.encrypted.tx_viewing_pk,
        &owned.deposits[0].encrypted.tx_viewing_pk
    );
    assert_eq!(actual.encrypted.salt, &owned.deposits[0].encrypted.salt);
    assert_eq!(
        actual.encrypted.ciphertext,
        owned.deposits[0].encrypted.ciphertext
    );
    assert!(aliases(&bytes, actual.ring_data_hash));
    assert!(aliases(&bytes, actual.encrypted.ciphertext));
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
