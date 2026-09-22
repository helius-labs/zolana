use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};

use crate::error::TransactionError;

#[derive(SchemaWrite, SchemaRead, Clone, Debug, PartialEq, Eq)]
#[wincode(tag_encoding = "u8")]
pub enum DataRecord {
    #[wincode(tag = 1)]
    RingData(#[wincode(with = "containers::Vec<u8, FixIntLen<u16>>")] Vec<u8>),
    #[wincode(tag = 2)]
    UtxoData(#[wincode(with = "containers::Vec<u8, FixIntLen<u16>>")] Vec<u8>),
    /// Free-form note for the output recipient. Encrypted into the output note
    /// but not bound by the on-chain commitment (`data_hash`/`ring_data_hash`
    /// cover only `UtxoData`/`RingData`), so it is informational only.
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
    /// `RingData` (1) < `UtxoData` (2) < `Memo` (3).
    pub fn validate(&self) -> Result<(), TransactionError> {
        let mut ring_seen = false;
        let mut utxo_seen = false;
        let mut memo_seen = false;
        for record in &self.records {
            match record {
                DataRecord::RingData(_) => {
                    if ring_seen {
                        return Err(TransactionError::DuplicateDataRecord);
                    }
                    if utxo_seen || memo_seen {
                        return Err(TransactionError::NonCanonicalDataOrder);
                    }
                    ring_seen = true;
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

    pub fn ring_data(&self) -> Option<&[u8]> {
        self.records.iter().find_map(|record| match record {
            DataRecord::RingData(bytes) => Some(bytes.as_slice()),
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
