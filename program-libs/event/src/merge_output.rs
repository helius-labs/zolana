/// Length of a merge's mask seed.
pub const MERGE_MASK_SEED_LEN: usize = 31;

/// What a merge publishes so its owner can rebuild the output: the masked
/// output amount, the two masked mint chunks, the seed of their mask nonces
/// and, for `merge_ring`, the output `ring_data_hash`. An indexer republishes
/// it as the single message of the rebuilt merge event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MergeOutputDerivation {
    pub masked_amount: [u8; 32],
    pub masked_mint: [[u8; 32]; 2],
    pub mask_seed: [u8; MERGE_MASK_SEED_LEN],
    pub output_ring_data_hash: Option<[u8; 32]>,
}

/// Encoded length without the ring-data hash.
const DEFAULT_LEN: usize = 32 + 64 + MERGE_MASK_SEED_LEN;

impl MergeOutputDerivation {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(DEFAULT_LEN + 32);
        out.extend_from_slice(&self.masked_amount);
        for chunk in &self.masked_mint {
            out.extend_from_slice(chunk);
        }
        out.extend_from_slice(&self.mask_seed);
        if let Some(ring_data_hash) = self.output_ring_data_hash {
            out.extend_from_slice(&ring_data_hash);
        }
        out
    }

    /// `None` unless `data` is exactly the default or the ring length.
    pub fn decode(data: &[u8]) -> Option<Self> {
        let (masked_amount, rest) = data.split_first_chunk::<32>()?;
        let (masked_mint_prefix, rest) = rest.split_first_chunk::<32>()?;
        let (masked_mint_last, rest) = rest.split_first_chunk::<32>()?;
        let (mask_seed, rest) = rest.split_first_chunk::<MERGE_MASK_SEED_LEN>()?;
        let output_ring_data_hash = match rest.len() {
            0 => None,
            32 => Some(<[u8; 32]>::try_from(rest).ok()?),
            _ => return None,
        };
        Some(Self {
            masked_amount: *masked_amount,
            masked_mint: [*masked_mint_prefix, *masked_mint_last],
            mask_seed: *mask_seed,
            output_ring_data_hash,
        })
    }
}
