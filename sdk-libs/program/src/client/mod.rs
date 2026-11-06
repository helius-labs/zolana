mod data_utxo;
mod program_owner;
pub(crate) mod transaction;

pub use program_owner::ProgramOwner;
pub use transaction::{
    ClientError, InputRecords, ProgramProofInputs, ProgramTransaction, TransactionOptions,
};

pub use data_utxo::DataUtxo;

pub trait ClientInputs: Sized {
    type Client;
    fn from_client(client: Self::Client, records: &mut InputRecords) -> Result<Self, ClientError>;
}
use crate::EncryptionCodec;
