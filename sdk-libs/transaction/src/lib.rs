use core::mem::MaybeUninit;

use wincode::{
    config::ConfigCore,
    error::{ReadError, ReadResult, WriteResult},
    io::{Reader, Writer},
    SchemaRead, SchemaWrite,
};
use zolana_keypair::{
    constants::{P256_PUBKEY_LEN, PUBLIC_KEY_LEN},
    P256Pubkey, PublicKey,
};

pub mod data;
pub mod error;
pub mod instructions;
pub mod serialization;
pub mod utxo;
pub mod wallet;

pub use data::{Data, DataRecord};
pub use error::TransactionError;
pub use instructions::transact::{
    EncryptedTransaction, ExternalData, InputUtxo, OutputContext, OutputSlot, OutputUtxo,
    ShieldedTransaction,
};
pub use serialization::{scheme::EncryptedScheme, DecodeCx, OwnerCx, UtxoSerialization};
pub use solana_address::Address;
pub use utxo::{derive_blinding, owner_utxo_hash, utxo_hash, Blinding, Utxo};
pub use wallet::{
    asset::{AssetRegistry, SOL_ASSET_ID, SOL_MINT},
    AssetBalance, PrivateTransaction, PrivateTransactionDirection, PrivateTransactionId,
    PrivateTransactionKind, PrivateTransactionStatus, SpendableUtxo, SyncReport, ViewingKeyEntry,
    Wallet, WalletUtxo, DEFAULT_TAG_WINDOW,
};
pub use zolana_keypair::constants::VIEW_TAG_LEN;

pub const TRANSFER: u8 = 1;
pub const SPLIT: u8 = 2;
pub const MERGE: u8 = 3;
pub const TRANSFER_PLAINTEXT: u8 = 4;

pub(crate) struct P256PubkeySchema;
pub(crate) struct PublicKeySchema;

unsafe impl<C: ConfigCore> SchemaWrite<C> for P256PubkeySchema {
    type Src = P256Pubkey;

    fn size_of(_: &P256Pubkey) -> WriteResult<usize> {
        Ok(P256_PUBKEY_LEN)
    }

    fn write(writer: impl Writer, src: &P256Pubkey) -> WriteResult<()> {
        <[u8; P256_PUBKEY_LEN] as SchemaWrite<C>>::write(writer, src.as_bytes())
    }
}

unsafe impl<'de, C: ConfigCore> SchemaRead<'de, C> for P256PubkeySchema {
    type Dst = P256Pubkey;

    fn read(reader: impl Reader<'de>, dst: &mut MaybeUninit<P256Pubkey>) -> ReadResult<()> {
        let mut bytes = MaybeUninit::<[u8; P256_PUBKEY_LEN]>::uninit();
        <[u8; P256_PUBKEY_LEN] as SchemaRead<'de, C>>::read(reader, &mut bytes)?;
        let pubkey = P256Pubkey::from_bytes(unsafe { bytes.assume_init() })
            .map_err(|_| ReadError::Custom("invalid p256 public key"))?;
        dst.write(pubkey);
        Ok(())
    }
}

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
