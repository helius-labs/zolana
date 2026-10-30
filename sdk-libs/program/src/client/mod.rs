mod data_utxo;
pub(crate) mod transaction;
mod program_owner;

pub use transaction::{ClientError, InputRecords, ProgramProofInputs, ProgramTransaction, TransactionOptions};
pub use program_owner::ProgramOwner;

pub use data_utxo::DataUtxo;

pub trait ClientInputs: Sized {
    type Client;
    fn from_client(client: Self::Client, records: &mut InputRecords) -> Result<Self, ClientError>;
}
use crate::EncryptionCodec;
