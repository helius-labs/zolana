use zolana_squads_client::DecryptedUtxo;

#[test]
fn decrypted_utxo_fields_round_trip() {
    let utxo = DecryptedUtxo {
        utxo_hash: [7u8; 32],
        asset_id: 2,
        amount: 1_000,
        blinding: [3u8; 31],
    };
    let copy = utxo;
    assert_eq!(copy, utxo);
    assert_eq!(copy.asset_id, 2);
    assert_eq!(copy.amount, 1_000);
    assert_eq!(copy.blinding, [3u8; 31]);
}
