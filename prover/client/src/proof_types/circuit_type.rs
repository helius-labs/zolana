#[derive(Debug, PartialEq, Eq)]
pub enum CircuitType {
    BatchAddressAppend,
    Transfer,
    TransferEddsa,
}

impl CircuitType {
    #[allow(clippy::inherent_to_string)]
    pub fn to_string(&self) -> String {
        match self {
            Self::BatchAddressAppend => "address-append".to_string(),
            Self::Transfer => "transfer".to_string(),
            Self::TransferEddsa => "transfer-eddsa".to_string(),
        }
    }
}
