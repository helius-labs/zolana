use wincode::containers;
use wincode::len::FixIntLen;
use wincode::{SchemaRead, SchemaWrite};

use crate::error::TransactionError;

#[derive(SchemaWrite, SchemaRead, Clone, Debug, PartialEq, Eq)]
#[wincode(tag_encoding = "u8")]
pub enum DataRecord {
    #[wincode(tag = 1)]
    ZoneData(#[wincode(with = "containers::Vec<u8, FixIntLen<u16>>")] Vec<u8>),
    #[wincode(tag = 2)]
    ProgramData(#[wincode(with = "containers::Vec<u8, FixIntLen<u16>>")] Vec<u8>),
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

    pub fn validate(&self) -> Result<(), TransactionError> {
        let mut zone_seen = false;
        let mut program_seen = false;
        for record in &self.records {
            match record {
                DataRecord::ZoneData(_) => {
                    if zone_seen {
                        return Err(TransactionError::DuplicateDataRecord);
                    }
                    if program_seen {
                        return Err(TransactionError::NonCanonicalDataOrder);
                    }
                    zone_seen = true;
                }
                DataRecord::ProgramData(_) => {
                    if program_seen {
                        return Err(TransactionError::DuplicateDataRecord);
                    }
                    program_seen = true;
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

    pub fn program_data(&self) -> Option<&[u8]> {
        self.records.iter().find_map(|record| match record {
            DataRecord::ProgramData(bytes) => Some(bytes.as_slice()),
            _ => None,
        })
    }
}
