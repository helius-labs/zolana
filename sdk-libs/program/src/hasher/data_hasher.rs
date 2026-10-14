use zolana_hasher::HasherError;

/// The native Poseidon commitment matching a program state's circuit hash.
// TODO: Support more hash functions with an explicit choice shared by circuit and client.
pub trait DataHasher {
    fn hash(&self) -> Result<[u8; 32], HasherError>;
}
