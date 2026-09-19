use zolana_keypair::PublicKey;
use zolana_transaction::{
    serialization::proofless::*, AssetRegistry, Data, DataRecord, Mint, OwnerCx, Utxo,
    UtxoSerialization,
};

#[test]
fn memo_round_trips_through_proofless_serialization() {
    let owner = PublicKey::zeroed();
    let utxo = Utxo {
        owner,
        asset: Mint::SOL,
        amount: 42,
        blinding: [3u8; 32],
        ring_program_id: None,
        data: Data::new(vec![DataRecord::Memo(b"gm".to_vec())]),
    };
    let assets = AssetRegistry::default();
    let owner_cx = OwnerCx {
        owner,
        assets: &assets,
        ring_program_id: None,
        // A proofless deposit carries its blinding literally.
        first_nullifier: None,
    };
    let encode_cx = ProoflessEncode {
        owner_hash: [0u8; 32],
        data_hash: None,
        ring_data_hash: None,
    };

    let plaintext = Proofless::from_utxos(&[utxo], &owner_cx, &encode_cx).unwrap();
    assert_eq!(plaintext.memo.as_deref(), Some(b"gm".as_slice()));

    let bytes = Proofless::serialize(&plaintext).unwrap();
    let parsed = Proofless::deserialize(&bytes).unwrap();
    let utxos = Proofless::into_utxos(parsed, &owner_cx).unwrap();
    let recovered = utxos.first().expect("one utxo");
    assert_eq!(recovered.data.memo(), Some(b"gm".as_slice()));
}
