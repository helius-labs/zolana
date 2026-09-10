use crate::{Hasher, HasherError, Poseidon};

/// Creates a hash chain from an array of [u8;32] arrays.
///
/// # Parameters
/// - `inputs`: An array of [u8;32] arrays to be hashed.
///
/// # Returns
/// - `Result<[u8; 32], HasherError>`: The resulting hash chain or an error.
pub fn create_hash_chain_from_array<const T: usize>(
    inputs: [[u8; 32]; T],
) -> Result<[u8; 32], HasherError> {
    create_hash_chain_from_slice(&inputs)
}

/// Creates a hash chain from a slice of [u8;32] arrays.
///
/// # Parameters
/// - `inputs`: A slice of [u8;32] array to be hashed.
///
/// # Returns
/// - `Result<[u8; 32], HasherError>`: The resulting hash chain or an error.
pub fn create_hash_chain_from_slice(inputs: &[[u8; 32]]) -> Result<[u8; 32], HasherError> {
    create_hash_chain(inputs.iter())
}

/// Creates a hash chain from a slice of borrowed [u8; 32] arrays.
pub fn create_hash_chain_from_slice_ref(inputs: &[&[u8; 32]]) -> Result<[u8; 32], HasherError> {
    create_hash_chain(inputs.iter().copied())
}

/// Folds Poseidon from right to left. The fixed-width signer transcript uses
/// this direction so the on-chain verifier can replace the zero-padded suffix
/// with a precomputed chain value.
pub fn create_right_hash_chain_from_slice(inputs: &[[u8; 32]]) -> Result<[u8; 32], HasherError> {
    let Some((last, prefix)) = inputs.split_last() else {
        return Ok([0u8; 32]);
    };
    let mut hash_chain = *last;
    for input in prefix.iter().rev() {
        hash_chain = Poseidon::hashv(&[input, &hash_chain])?;
    }
    Ok(hash_chain)
}

/// Incremental left-fold Poseidon chain, for callers that produce elements one
/// at a time inside a loop and cannot hand over an iterator.
///
/// The first element is stored verbatim; only the second and later elements
/// hash. Seeding with `[0u8; 32]` instead would change every chain in the
/// protocol, because `Poseidon(0, x)` is not `x`.
#[derive(Clone, Copy, Debug, Default)]
pub struct HashChain {
    chain: Option<[u8; 32]>,
}

impl HashChain {
    pub const fn new() -> Self {
        Self { chain: None }
    }

    pub fn push(&mut self, value: &[u8; 32]) -> Result<(), HasherError> {
        self.chain = Some(match self.chain {
            None => *value,
            Some(chain) => Poseidon::hashv(&[&chain, value])?,
        });
        Ok(())
    }

    /// An empty chain folds to zero, matching [`create_hash_chain_from_slice`].
    pub fn finish(self) -> [u8; 32] {
        self.chain.unwrap_or([0u8; 32])
    }
}

fn create_hash_chain<'a>(
    mut inputs: impl Iterator<Item = &'a [u8; 32]>,
) -> Result<[u8; 32], HasherError> {
    let Some(first) = inputs.next() else {
        return Ok([0u8; 32]);
    };
    let mut hash_chain = *first;
    for input in inputs {
        hash_chain = Poseidon::hashv(&[&hash_chain, input])?;
    }
    Ok(hash_chain)
}

/// Creates a two inputs hash chain from two slices of [u8;32] arrays.
/// The two slices must have the same length.
/// Hashes are hashed in pairs, with the first hash from
/// the first slice and the second hash from the second slice.
/// H(i) = H(H(i-1), hashes_first[i], hashes_second[i])
///
/// # Parameters
/// - `hashes_first`: A slice of [u8;32] arrays to be hashed first.
/// - `hashes_second`: A slice of [u8;32] arrays to be hashed second.
///
/// # Returns
/// - `Result<[u8; 32], HasherError>`: The resulting hash chain or an error.
pub fn create_two_inputs_hash_chain(
    hashes_first: &[[u8; 32]],
    hashes_second: &[[u8; 32]],
) -> Result<[u8; 32], HasherError> {
    let first_len = hashes_first.len();
    if first_len != hashes_second.len() {
        return Err(HasherError::InvalidInputLength(
            first_len,
            hashes_second.len(),
        ));
    }
    if hashes_first.is_empty() {
        return Ok([0u8; 32]);
    }
    let mut hash_chain = Poseidon::hashv(&[&hashes_first[0], &hashes_second[0]])?;

    if first_len == 1 {
        return Ok(hash_chain);
    }

    for i in 1..first_len {
        hash_chain = Poseidon::hashv(&[&hash_chain, &hashes_first[i], &hashes_second[i]])?;
    }
    Ok(hash_chain)
}
