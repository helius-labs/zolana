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

/// Folds a slice of [u8; 32] elements three at a time with the 4-input
/// Poseidon hash.
///
/// `hash_chain_4([])` is zero and `hash_chain_4([e])` is `e`, as for the
/// binary chain. Otherwise the chain starts at `e[0]` and every group of up to
/// three following elements is absorbed with one call,
/// `h = Poseidon(h, g[0], g[1] or 0, g[2] or 0)`; a partial trailing group is
/// zero-padded so the 4-input permutation is used for every step.
///
/// # Security
///
/// The fold carries no length tag and no domain separation. It is injective
/// only over inputs of one fixed length: the callers are the public-input
/// chains whose length is fixed by the compiled circuit (the shape fixes the
/// input, output and public element counts) and verified against that
/// circuit's verifying key. Do not use it where a variable-length input could
/// be zero-padded to look like a fixed-length one, since `[a, b]` and
/// `[a, b, 0, 0]` hash to the same value.
pub fn create_hash_chain_4_from_slice(inputs: &[[u8; 32]]) -> Result<[u8; 32], HasherError> {
    create_hash_chain_4(inputs.iter())
}

static HASH_CHAIN_4_PADDING: [u8; 32] = [0u8; 32];

/// Iterator variant of [`create_hash_chain_4_from_slice`]; see its security
/// note.
pub fn create_hash_chain_4<'a>(
    mut inputs: impl Iterator<Item = &'a [u8; 32]>,
) -> Result<[u8; 32], HasherError> {
    let Some(first) = inputs.next() else {
        return Ok([0u8; 32]);
    };
    let mut hash_chain = *first;
    while let Some(g0) = inputs.next() {
        let g1 = inputs.next().unwrap_or(&HASH_CHAIN_4_PADDING);
        let g2 = inputs.next().unwrap_or(&HASH_CHAIN_4_PADDING);
        hash_chain = Poseidon::hashv(&[&hash_chain, g0, g1, g2])?;
    }
    Ok(hash_chain)
}

/// Folds a slice of [u8; 32] elements three at a time with the 4-input
/// Poseidon hash, from right to left.
///
/// `right_hash_chain_4([])` is zero and `right_hash_chain_4([e])` is `e`, as
/// for the left fold. Otherwise the chain starts at the last element and every
/// group of up to three preceding elements is absorbed with one call,
/// `h = Poseidon(g[0], g[1] or 0, g[2] or 0, h)`, walking backwards. The
/// leftmost group is the short one and its elements stay left-aligned:
///
/// ```text
/// [a, b, c, d]    -> P(a, b, c, d)
/// [a, b, c, d, e] -> P(a, 0, 0, P(b, c, d, e))
/// ```
///
/// The direction is what makes an all-zero suffix foldable in advance: its
/// value depends on the suffix length alone, so an on-chain verifier seeds the
/// fold from that constant and hashes only the populated prefix. The call
/// count is `ceil((n - 1) / 3)` either way, so a circuit pays the same.
///
/// # Security
///
/// Like the left fold, this carries no length tag and no domain separation, so
/// it is injective only over inputs of one fixed length. Here the ambiguity
/// sits in the leftmost group rather than the trailing one: `[a, b]` and
/// `[0, a, b]` both fold to `Poseidon(a, 0, 0, b)`. Every caller's length is
/// fixed by the compiled circuit and verified against that circuit's verifying
/// key.
pub fn create_right_hash_chain_4_from_slice(inputs: &[[u8; 32]]) -> Result<[u8; 32], HasherError> {
    let Some((last, prefix)) = inputs.split_last() else {
        return Ok([0u8; 32]);
    };
    create_right_hash_chain_4_from_seed(prefix, *last)
}

/// Folds `prefix` into `seed`, an already-folded suffix of the same chain.
///
/// [`create_right_hash_chain_4_from_slice`] is this with the chain's last
/// element as the seed. A caller that knows the chain ends in zeros passes the
/// precomputed fold of that all-zero suffix together with the prefix it
/// covers, which skips those groups without changing the result: removing a
/// multiple of three elements from the right of `prefix` leaves the remaining
/// group boundaries where they were.
pub fn create_right_hash_chain_4_from_seed(
    prefix: &[[u8; 32]],
    seed: [u8; 32],
) -> Result<[u8; 32], HasherError> {
    let mut hash_chain = seed;
    // `rchunks` walks the groups the fold visits, in order: full groups of
    // three from the right, then the short leftmost one with its elements
    // still left-aligned.
    for group in prefix.rchunks(3) {
        hash_chain = Poseidon::hashv(&[
            group.first().unwrap_or(&HASH_CHAIN_4_PADDING),
            group.get(1).unwrap_or(&HASH_CHAIN_4_PADDING),
            group.get(2).unwrap_or(&HASH_CHAIN_4_PADDING),
            &hash_chain,
        ])?;
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
