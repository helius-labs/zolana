use alloc::vec::Vec;
use borsh::io;

/// The plaintext encoding used for a state's encrypted UTXO data.
///
/// Decoding must consume the entire payload and reconstruct every committed
/// value using only that payload. The reconstructed state's hash must equal
/// the original state's hash. The SDK checks this before accepting an output.
///
/// `UtxoState` implements this trait using Borsh by default. Use
/// `#[utxo_state(custom_codec)]` and a manual implementation to encode a smaller
/// payload without changing the state's ordinary Borsh representation.
pub trait EncryptionCodec: Sized {
    fn serialize_for_encryption(&self) -> io::Result<Vec<u8>>;

    fn deserialize_after_decryption(bytes: &[u8]) -> io::Result<Self>;
}
