use zolana_transaction::{Data, DataRecord, TransactionError};

#[test]
fn memo_round_trips_and_is_readable() {
    let data = Data::new(vec![
        DataRecord::RingData(vec![9, 9]),
        DataRecord::UtxoData(vec![1]),
        DataRecord::Memo(b"gm".to_vec()),
    ]);
    data.validate().unwrap();
    let bytes = wincode::serialize(&data).unwrap();
    let parsed: Data = wincode::deserialize_exact(&bytes).unwrap();
    assert_eq!(parsed, data);
    assert_eq!(parsed.memo(), Some(b"gm".as_slice()));
}

#[test]
fn memo_only_is_valid() {
    let data = Data::new(vec![DataRecord::Memo(vec![7; 300])]);
    data.validate().unwrap();
    assert_eq!(data.memo(), Some([7u8; 300].as_slice()));
    assert!(data.ring_data().is_none());
    assert!(data.utxo_data().is_none());
}

#[test]
fn duplicate_memo_is_rejected() {
    let data = Data::new(vec![DataRecord::Memo(vec![1]), DataRecord::Memo(vec![2])]);
    assert_eq!(
        data.validate().unwrap_err(),
        TransactionError::DuplicateDataRecord
    );
}

#[test]
fn record_after_memo_is_non_canonical() {
    for trailing in [DataRecord::RingData(vec![1]), DataRecord::UtxoData(vec![1])] {
        let data = Data::new(vec![DataRecord::Memo(vec![0]), trailing]);
        assert_eq!(
            data.validate().unwrap_err(),
            TransactionError::NonCanonicalDataOrder
        );
    }
}

#[test]
fn every_record_kind_rejects_duplicates() {
    for record in [
        DataRecord::RingData(vec![1]),
        DataRecord::UtxoData(vec![2]),
        DataRecord::Memo(vec![3]),
    ] {
        assert_eq!(
            Data::new(vec![record.clone(), record]).validate(),
            Err(TransactionError::DuplicateDataRecord)
        );
    }
}

#[test]
fn record_order_accepts_canonical_subsets_and_rejects_every_other_permutation() {
    let ring = DataRecord::RingData(vec![1]);
    let utxo = DataRecord::UtxoData(vec![2]);
    let memo = DataRecord::Memo(vec![3]);
    for records in [
        vec![],
        vec![ring.clone()],
        vec![utxo.clone()],
        vec![memo.clone()],
        vec![ring.clone(), utxo.clone()],
        vec![ring.clone(), memo.clone()],
        vec![utxo.clone(), memo.clone()],
        vec![ring.clone(), utxo.clone(), memo.clone()],
    ] {
        assert_eq!(Data::new(records).validate(), Ok(()));
    }
    for records in [
        vec![utxo.clone(), ring.clone()],
        vec![memo.clone(), ring.clone()],
        vec![memo.clone(), utxo.clone()],
        vec![ring.clone(), memo.clone(), utxo.clone()],
        vec![utxo.clone(), ring.clone(), memo.clone()],
        vec![utxo.clone(), memo.clone(), ring.clone()],
        vec![memo.clone(), ring.clone(), utxo.clone()],
        vec![memo, utxo, ring],
    ] {
        assert_eq!(
            Data::new(records).validate(),
            Err(TransactionError::NonCanonicalDataOrder)
        );
    }
}
