use solana_address::Address;
use solana_signature::Signature;
use zolana_transaction::{
    instructions::transact::SettlementTransfer, Data, DataRecord, Mint, Utxo, WalletUtxo,
};

fn without_indexer_metadata(utxo: &WalletUtxo) -> serde_json::Value {
    let mut json = serde_json::to_value(utxo).unwrap();
    if let Some(object) = json.as_object_mut() {
        object.remove("slot");
        object.remove("txSignature");
        object.remove("slotIndex");
    }
    json
}

#[test]
fn a_wallet_utxo_decodes_without_indexer_metadata() {
    let dummy = WalletUtxo::dummy(3).unwrap();
    let decoded: WalletUtxo = serde_json::from_value(without_indexer_metadata(&dummy)).unwrap();

    assert_eq!(
        (
            decoded.slot,
            decoded.tx_signature,
            decoded.slot_index,
            decoded.latest_tree_id,
            decoded.utxo_hash,
            decoded.utxo.owner,
        ),
        (
            0,
            Signature::default(),
            0,
            None,
            dummy.utxo_hash,
            dummy.utxo.owner,
        ),
    );
}

#[test]
fn data_records_are_tagged_by_kind() {
    let data: Data = serde_json::from_value(serde_json::json!({
        "records": [
            { "kind": "ringData", "bytes": [1] },
            { "kind": "utxoData", "bytes": [2, 3] },
            { "kind": "memo", "bytes": [] },
        ]
    }))
    .unwrap();
    let unknown = serde_json::from_value::<DataRecord>(serde_json::json!({
        "kind": "secret",
        "bytes": [1],
    }));

    assert_eq!(
        (data, unknown.is_err()),
        (
            Data::new(vec![
                DataRecord::RingData(vec![1]),
                DataRecord::UtxoData(vec![2, 3]),
                DataRecord::Memo(vec![]),
            ]),
            true,
        ),
    );
}

#[test]
fn settlement_transfers_are_tagged_by_kind() {
    let account = Address::new_from_array([5; 32]);
    let mint = Address::new_from_array([6; 32]);

    assert_eq!(
        (
            serde_json::to_value(SettlementTransfer::Sol {
                is_deposit: true,
                amount: 10,
                user_sol_account: account,
            })
            .unwrap(),
            serde_json::to_value(SettlementTransfer::Spl {
                mint,
                is_deposit: false,
                amount: 11,
                user_spl_token: account,
            })
            .unwrap(),
        ),
        (
            serde_json::json!({
                "kind": "sol",
                "isDeposit": true,
                "amount": 10,
                "userSolAccount": account.to_string(),
            }),
            serde_json::json!({
                "kind": "spl",
                "mint": mint.to_string(),
                "isDeposit": false,
                "amount": 11,
                "userSplToken": account.to_string(),
            }),
        ),
    );
}

#[test]
fn decoded_notes_reject_unknown_fields() {
    let dummy = WalletUtxo::dummy(3).unwrap();
    let mut wallet = without_indexer_metadata(&dummy);
    wallet["ownerAddress"] = serde_json::json!("typo");
    let mut note = wallet["utxo"].clone();
    note["extra"] = serde_json::json!(1);
    let mut mint = serde_json::to_value(Mint::SOL).unwrap();
    mint["extra"] = serde_json::json!(1);

    assert_eq!(
        (
            serde_json::from_value::<WalletUtxo>(wallet).unwrap_err().to_string(),
            serde_json::from_value::<Utxo>(note).unwrap_err().to_string(),
            serde_json::from_value::<Mint>(mint).unwrap_err().to_string(),
            serde_json::from_value::<Data>(serde_json::json!({"records": [], "extra": 1}))
                .unwrap_err()
                .to_string(),
            serde_json::from_value::<DataRecord>(serde_json::json!({
                "kind": "memo",
                "bytes": [],
                "extra": 1,
            }))
            .unwrap_err()
            .to_string(),
        ),
        (
            "unknown field `ownerAddress`, expected one of `utxo`, `nullifierPubkey`, `utxoHash`, `nullifier`, `txViewingKey`, `dataHash`, `ringDataHash`, `treeId`, `leafIndex`, `latestTreeId`, `slot`, `txSignature`, `slotIndex`".to_string(),
            "unknown field `extra`, expected one of `owner`, `asset`, `amount`, `blinding`, `ringProgramId`, `data`".to_string(),
            "unknown field `extra`, expected `asset` or `assetId`".to_string(),
            "unknown field `extra`, expected `records`".to_string(),
            "invalid value: string \"extra\", expected \"kind\" or \"bytes\"".to_string(),
        ),
    );
}

#[test]
fn a_mint_names_its_asset_in_base58() {
    let asset = Address::new_from_array([9; 32]);
    let mint = Mint::new(asset, 7);

    assert_eq!(
        (
            serde_json::to_value(mint).unwrap(),
            serde_json::from_value::<Mint>(serde_json::json!({
                "asset": asset.to_string(),
                "assetId": 7,
            }))
            .unwrap(),
        ),
        (
            serde_json::json!({ "asset": asset.to_string(), "assetId": 7 }),
            mint,
        ),
    );
}
