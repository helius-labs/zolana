use zolana_keypair::{PublicKey, ViewingKey};
use zolana_transaction::{
    serialization::anonymous::*, utxo::derive_transact_output_blinding, AssetRegistry, Data,
    DataRecord, Mint, OwnerCx, TransactionError, Utxo, UtxoSerialization, SOL_ASSET_ID,
};
const SOL_CHANGE_SLOT: u32 = 1;

fn plaintext(data: Data) -> AnonymousTransferRecipientPlaintext {
    AnonymousTransferRecipientPlaintext {
        owner_pubkey: PublicKey::zeroed(),
        sender_pubkey: ViewingKey::new().pubkey(),
        asset_id: SOL_ASSET_ID,
        amount: 7,
        blinding: [3u8; 32],
        data,
    }
}

#[test]
fn memo_only_recipient_is_accepted() {
    let assets = AssetRegistry::default();
    let utxo = plaintext(Data::new(vec![DataRecord::Memo(b"hello".to_vec())]))
        .into_utxo(&assets, None)
        .unwrap();
    assert_eq!(utxo.data.memo(), Some(b"hello".as_slice()));
}

fn sender_plaintext() -> AnonymousTransferSenderPlaintext {
    AnonymousTransferSenderPlaintext {
        owner_pubkey: PublicKey::zeroed(),
        spl_asset_id: 0,
        spl_amount: 0,
        sol_amount: 9,
        blinding_seed: [5u8; 32],
        recipient_viewing_pks: Vec::new(),
        spl_data: Data::default(),
        sol_data: Data::default(),
    }
}

/// Decoding cannot derive a blinding without the transaction's first
/// nullifier, so a context that omits it is refused rather than falling back
/// to a value the circuit would never have accepted.
#[test]
fn sender_bundle_without_first_nullifier_is_rejected() {
    let assets = AssetRegistry::default();
    let owner_cx = OwnerCx {
        owner: PublicKey::zeroed(),
        assets: &assets,
        ring_program_id: None,
        first_nullifier: None,
    };
    assert_eq!(
        AnonymousSenderBundle::into_utxos(sender_plaintext(), &owner_cx).unwrap_err(),
        TransactionError::MissingFirstNullifier
    );
}

/// Each change slot takes the blinding the circuit recomputes for its
/// physical output index.
#[test]
fn sender_change_takes_the_derived_blinding() {
    let assets = AssetRegistry::default();
    let first_nullifier = [7u8; 32];
    let utxos = sender_plaintext()
        .into_utxos(&first_nullifier, &assets, None)
        .unwrap();
    let expected = vec![Utxo {
        owner: PublicKey::zeroed(),
        asset: Mint::SOL,
        amount: 9,
        blinding: derive_transact_output_blinding(&first_nullifier, &[5u8; 32], SOL_CHANGE_SLOT)
            .unwrap(),
        ring_program_id: None,
        data: Data::default(),
    }];
    assert_eq!(utxos, expected, "decoded sender change");
}

#[test]
fn ring_or_utxo_data_recipient_is_rejected() {
    let assets = AssetRegistry::default();
    for data in [
        Data::new(vec![DataRecord::UtxoData(vec![1])]),
        Data::new(vec![DataRecord::RingData(vec![1])]),
    ] {
        assert_eq!(
            plaintext(data).into_utxo(&assets, None).unwrap_err(),
            TransactionError::UnsupportedOutputData
        );
    }
}
