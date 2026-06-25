use crate::error::TransactionError;

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncryptedScheme {
    Proofless = 0,
    AnonymousRecipient = 1,
    AnonymousSender = 2,
    ConfidentialRecipient = 3,
    ConfidentialSender = 4,
    Split = 5,
    Merge = 6,
    PlaintextTransfer = 7,
}

impl EncryptedScheme {
    pub fn from_byte(byte: u8) -> Result<Self, TransactionError> {
        match byte {
            0 => Ok(Self::Proofless),
            1 => Ok(Self::AnonymousRecipient),
            2 => Ok(Self::AnonymousSender),
            3 => Ok(Self::ConfidentialRecipient),
            4 => Ok(Self::ConfidentialSender),
            5 => Ok(Self::Split),
            6 => Ok(Self::Merge),
            7 => Ok(Self::PlaintextTransfer),
            other => Err(TransactionError::BadDiscriminator(other)),
        }
    }

    pub fn as_byte(self) -> u8 {
        self as u8
    }
}
