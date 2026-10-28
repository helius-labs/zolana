use core::mem::MaybeUninit;

use spr_keypair::{constants::PUBLIC_KEY_LEN, PublicKey};
use wincode::{
    config::ConfigCore,
    error::{ReadError, ReadResult, WriteResult},
    io::{Reader, Writer},
    SchemaRead, SchemaWrite,
};

pub mod asset;
#[cfg(feature = "circuit")]
pub mod circuit;
pub mod data;
pub mod decrypt;
pub mod error;
pub mod field;
pub mod history;
pub mod indexer_types;
pub mod instructions;
pub mod keys;
pub mod selection;
#[cfg(feature = "serde")]
mod serde_helpers;
pub mod serialization;
pub mod utxo;

pub use asset::{AssetAmount, AssetBalance, AssetRegistry, Balances, Mint, SOL_ASSET_ID, SOL_MINT};
pub use data::{Data, DataRecord};
pub use decrypt::{
    decrypt, decrypt_spendable, verify_owned, verify_spendable, DecryptionResult, OwnedUtxos,
    SpendableDecryptionResult,
};
pub use error::{AddressInputError, TransactionError};
pub use history::{History, HistoryEntry, HistoryKind};
pub use indexer_types::{DepositPayload, OutputContext, OutputSlot, ShieldedTransaction};
pub use instructions::transact::{ExternalData, SppProofOutputUtxo};
pub use keys::{
    DecryptLabel, DecryptRequest, DeriveRequest, LocalShieldedKeys, ShieldedKeys,
    TransactionKeyRequest,
};
pub use selection::{select_merge, select_spend, select_spend_excluding};
pub use serialization::{scheme::EncryptedScheme, DecodeCx, OwnerCx, UtxoSerialization};
pub use solana_address::Address;
pub use spr_keypair::constants::VIEW_TAG_LEN;
pub use utxo::wallet as spendable;
pub use utxo::{
    derive_output_blinding_seed, derive_private_tx_blinding, owner_utxo_hash, Blinding, Utxo,
    WalletUtxo,
};

pub const TRANSFER: u8 = 1;
pub const MERGE: u8 = 3;
pub const TRANSFER_PLAINTEXT: u8 = 4;

pub(crate) struct PublicKeySchema;

unsafe impl<C: ConfigCore> SchemaWrite<C> for PublicKeySchema {
    type Src = PublicKey;

    fn size_of(_: &PublicKey) -> WriteResult<usize> {
        Ok(PUBLIC_KEY_LEN)
    }

    fn write(writer: impl Writer, src: &PublicKey) -> WriteResult<()> {
        <[u8; PUBLIC_KEY_LEN] as SchemaWrite<C>>::write(writer, src.as_bytes())
    }
}

unsafe impl<'de, C: ConfigCore> SchemaRead<'de, C> for PublicKeySchema {
    type Dst = PublicKey;

    fn read(reader: impl Reader<'de>, dst: &mut MaybeUninit<PublicKey>) -> ReadResult<()> {
        let mut bytes = MaybeUninit::<[u8; PUBLIC_KEY_LEN]>::uninit();
        <[u8; PUBLIC_KEY_LEN] as SchemaRead<'de, C>>::read(reader, &mut bytes)?;
        let pubkey = PublicKey::from_bytes(unsafe { bytes.assume_init() })
            .map_err(|_| ReadError::Custom("invalid public key"))?;
        dst.write(pubkey);
        Ok(())
    }
}
