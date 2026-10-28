use spr_hasher::HasherError;

/// A program state's commitment, including its type tag, as a canonical
/// big-endian BN254 scalar. Native programs can use Poseidon or SHA-256 through
/// [`super::Sha256BE`], which clears the digest's first byte to fit the field.
///
/// The implementation selects the state hash algorithm; UTXO builders and
/// readers use it consistently. A state shared with a circuit must match that
/// circuit's hash. The `UtxoState` derive currently generates Poseidon hashes.
pub trait DataHasher {
    fn hash(&self) -> Result<[u8; 32], HasherError>;
}
