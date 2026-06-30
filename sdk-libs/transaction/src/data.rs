use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};

use crate::error::TransactionError;

#[derive(SchemaWrite, SchemaRead, Clone, Debug, PartialEq, Eq)]
#[wincode(tag_encoding = "u8")]
pub enum DataRecord {
    #[wincode(tag = 1)]
    ZoneData(#[wincode(with = "containers::Vec<u8, FixIntLen<u16>>")] Vec<u8>),
    #[wincode(tag = 2)]
    UtxoData(#[wincode(with = "containers::Vec<u8, FixIntLen<u16>>")] Vec<u8>),
    /// Free-form note for the output recipient. Encrypted into the output note
    /// but not bound by the on-chain commitment (`data_hash`/`zone_data_hash`
    /// cover only `UtxoData`/`ZoneData`), so it is informational only.
    #[wincode(tag = 3)]
    Memo(#[wincode(with = "containers::Vec<u8, FixIntLen<u16>>")] Vec<u8>),
}

#[derive(SchemaWrite, SchemaRead, Clone, Debug, Default, PartialEq, Eq)]
pub struct Data {
    #[wincode(with = "containers::Vec<DataRecord, FixIntLen<u8>>")]
    pub records: Vec<DataRecord>,
}

impl Data {
    pub fn new(records: Vec<DataRecord>) -> Self {
        Self { records }
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Records must appear at most once and in canonical tag order:
    /// `ZoneData` (1) < `UtxoData` (2) < `Memo` (3).
    pub fn validate(&self) -> Result<(), TransactionError> {
        let mut zone_seen = false;
        let mut utxo_seen = false;
        let mut memo_seen = false;
        for record in &self.records {
            match record {
                DataRecord::ZoneData(_) => {
                    if zone_seen {
                        return Err(TransactionError::DuplicateDataRecord);
                    }
                    if utxo_seen || memo_seen {
                        return Err(TransactionError::NonCanonicalDataOrder);
                    }
                    zone_seen = true;
                }
                DataRecord::UtxoData(_) => {
                    if utxo_seen {
                        return Err(TransactionError::DuplicateDataRecord);
                    }
                    if memo_seen {
                        return Err(TransactionError::NonCanonicalDataOrder);
                    }
                    utxo_seen = true;
                }
                DataRecord::Memo(_) => {
                    if memo_seen {
                        return Err(TransactionError::DuplicateDataRecord);
                    }
                    memo_seen = true;
                }
            }
        }
        Ok(())
    }

    pub fn zone_data(&self) -> Option<&[u8]> {
        self.records.iter().find_map(|record| match record {
            DataRecord::ZoneData(bytes) => Some(bytes.as_slice()),
            _ => None,
        })
    }

    pub fn utxo_data(&self) -> Option<&[u8]> {
        self.records.iter().find_map(|record| match record {
            DataRecord::UtxoData(bytes) => Some(bytes.as_slice()),
            _ => None,
        })
    }

    pub fn memo(&self) -> Option<&[u8]> {
        self.records.iter().find_map(|record| match record {
            DataRecord::Memo(bytes) => Some(bytes.as_slice()),
            _ => None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memo_round_trips_and_is_readable() {
        let data = Data::new(vec![
            DataRecord::ZoneData(vec![9, 9]),
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
        assert!(data.zone_data().is_none());
        assert!(data.utxo_data().is_none());
    }

    #[test]
    fn duplicate_memo_is_rejected() {
        let data = Data::new(vec![
            DataRecord::Memo(vec![1]),
            DataRecord::Memo(vec![2]),
        ]);
        assert_eq!(
            data.validate().unwrap_err(),
            TransactionError::DuplicateDataRecord
        );
    }

    #[test]
    fn record_after_memo_is_non_canonical() {
        for trailing in [DataRecord::ZoneData(vec![1]), DataRecord::UtxoData(vec![1])] {
            let data = Data::new(vec![DataRecord::Memo(vec![0]), trailing]);
            assert_eq!(
                data.validate().unwrap_err(),
                TransactionError::NonCanonicalDataOrder
            );
        }
    }
}
