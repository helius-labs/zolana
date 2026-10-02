/// What a merge publishes so its owner can rebuild the output without the
/// ciphertext: the masked output amount and, for `merge_ring`, the output
/// `ring_data_hash`. An indexer republishes it as the single message of the
/// rebuilt merge event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MergeOutputDerivation {
    pub masked_amount: [u8; 32],
    pub output_ring_data_hash: Option<[u8; 32]>,
}

impl MergeOutputDerivation {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.masked_amount.to_vec();
        if let Some(ring_data_hash) = self.output_ring_data_hash {
            out.extend_from_slice(&ring_data_hash);
        }
        out
    }

    /// `None` unless `data` is exactly 32 or 64 bytes.
    pub fn decode(data: &[u8]) -> Option<Self> {
        let (masked_amount, rest) = data.split_first_chunk::<32>()?;
        let output_ring_data_hash = match rest.len() {
            0 => None,
            32 => Some(<[u8; 32]>::try_from(rest).ok()?),
            _ => return None,
        };
        Some(Self {
            masked_amount: *masked_amount,
            output_ring_data_hash,
        })
    }
}
