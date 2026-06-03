pub mod constants;
pub(crate) mod encryption;
pub mod error;
pub mod hash;
pub mod nullifier_key;
pub mod pubkey;
pub mod shielded;
pub mod signing_key;
pub mod viewing_key;

pub use error::KeypairError;
pub use hash::{owner_hash, pubkey_field, sha256_be};
pub use nullifier_key::NullifierKey;
pub use pubkey::{P256Pubkey, PublicKey, SignatureType};
pub use shielded::{CompressedShieldedAddress, ShieldedAddress, ShieldedKeypair};
pub use signing_key::SigningKey;
pub use viewing_key::ViewingKey;

pub type Signature = [u8; 64];

pub type ECDSASignature = [u8; 64];
