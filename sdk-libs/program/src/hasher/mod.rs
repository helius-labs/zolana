mod data_hasher;
mod discriminator;
#[cfg(feature = "circuit")]
mod to_byte_array;
mod utxo_data_hash;

pub use data_hasher::DataHasher;
pub use discriminator::Discriminator;
#[cfg(feature = "circuit")]
pub use to_byte_array::ToByteArray;
pub use utxo_data_hash::{
    data_hash, unique_data_hash, CLOSED_DATA_HASH_DOMAIN, DATA_HASH_DOMAIN, UNIQUE_DATA_HASH_DOMAIN,
};
pub use zolana_hasher::sha256::Sha256BE;
pub use zolana_hasher::state_discriminator;
pub use zolana_hasher::{Hasher, HasherError, Poseidon, Sha256};
