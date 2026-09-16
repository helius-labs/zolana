//! Experimental negative filter. Positives require exact spentness checks.
use thiserror::Error;
use zolana_hasher::{primitives::is_canonical_bn254_scalar_be, Hasher, Keccak};

const HEADER: usize = 48;
const MAGIC: &[u8; 8] = b"ZNFBLOM1";
const HASH_DOMAIN: &[u8] = b"SPP nullifier filter v1";
pub const MAX_BATCH: usize = 512;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FilterError {
    #[error("invalid nullifier filter layout or domain")]
    InvalidFilter,
    #[error("invalid nullifier batch")]
    InvalidBatch,
    #[error("duplicate nullifier")]
    Duplicate,
    #[error("nullifier hashing failed")]
    Hash,
}

pub struct NullifierFilter<'a> {
    bits: &'a mut [u8],
    domain: [u8; 32],
    hashes: u8,
}

impl<'a> NullifierFilter<'a> {
    pub fn account_size(bit_bytes: usize) -> Option<usize> {
        if !bit_bytes.is_power_of_two() || bit_bytes.checked_mul(8).is_none() {
            return None;
        }
        HEADER.checked_add(bit_bytes)
    }

    pub fn init(bytes: &'a mut [u8], domain: &[u8; 32], hashes: u8) -> Result<Self, FilterError> {
        let bit_bytes = bytes
            .len()
            .checked_sub(HEADER)
            .ok_or(FilterError::InvalidFilter)?;
        if Self::account_size(bit_bytes) != Some(bytes.len())
            || !(1..=32).contains(&hashes)
            || usize::from(hashes) > bit_bytes * 8
            || bytes.iter().any(|byte| *byte != 0)
        {
            return Err(FilterError::InvalidFilter);
        }
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..40].copy_from_slice(domain);
        bytes[40] = hashes;
        Self::from_bytes(bytes, domain)
    }

    pub fn from_bytes(bytes: &'a mut [u8], domain: &[u8; 32]) -> Result<Self, FilterError> {
        let bit_bytes = bytes
            .len()
            .checked_sub(HEADER)
            .ok_or(FilterError::InvalidFilter)?;
        if Self::account_size(bit_bytes) != Some(bytes.len())
            || bytes[..8] != *MAGIC
            || bytes[8..40] != *domain
            || !(1..=32).contains(&bytes[40])
            || usize::from(bytes[40]) > bit_bytes * 8
            || bytes[41..HEADER].iter().any(|byte| *byte != 0)
        {
            return Err(FilterError::InvalidFilter);
        }
        let hashes = bytes[40];
        Ok(Self {
            bits: &mut bytes[HEADER..],
            domain: *domain,
            hashes,
        })
    }

    /// Return ambiguous input indexes without modifying the filter.
    pub fn check_batch(&self, nullifiers: &[[u8; 32]]) -> Result<Vec<usize>, FilterError> {
        validate_batch(nullifiers)?;
        let mask = self.bits.len() * 8 - 1;
        let mut positives = Vec::new();
        for (index, nullifier) in nullifiers.iter().enumerate() {
            let (start, step) = self.hash(nullifier)?;
            if (0..usize::from(self.hashes)).all(|i| {
                let bit = start.wrapping_add(step.wrapping_mul(i)) & mask;
                self.bits[bit / 8] & (1 << (bit % 8)) != 0
            }) {
                positives.push(index);
            }
        }
        Ok(positives)
    }

    /// Call only after the complete batch passes proof and exact-fallback admission.
    pub fn record_spent_batch(&mut self, nullifiers: &[[u8; 32]]) -> Result<(), FilterError> {
        validate_batch(nullifiers)?;
        let hashes: Vec<_> = nullifiers
            .iter()
            .map(|nf| self.hash(nf))
            .collect::<Result<_, _>>()?;
        let mask = self.bits.len() * 8 - 1;
        for (start, step) in hashes {
            for i in 0..usize::from(self.hashes) {
                let bit = start.wrapping_add(step.wrapping_mul(i)) & mask;
                self.bits[bit / 8] |= 1 << (bit % 8);
            }
        }
        Ok(())
    }

    fn hash(&self, nullifier: &[u8; 32]) -> Result<(usize, usize), FilterError> {
        let digest = Keccak::hashv(&[HASH_DOMAIN, &self.domain, nullifier])
            .map_err(|_| FilterError::Hash)?;
        Ok((
            u64::from_le_bytes(digest[..8].try_into().unwrap()) as usize,
            u64::from_le_bytes(digest[8..16].try_into().unwrap()) as usize | 1,
        ))
    }
}

fn validate_batch(nullifiers: &[[u8; 32]]) -> Result<(), FilterError> {
    if nullifiers.len() > MAX_BATCH
        || nullifiers
            .iter()
            .any(|nf| *nf == [0; 32] || !is_canonical_bn254_scalar_be(nf))
    {
        return Err(FilterError::InvalidBatch);
    }
    let mut ordered: Vec<_> = nullifiers.iter().collect();
    ordered.sort_unstable();
    if ordered.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(FilterError::Duplicate);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn nf(value: u64) -> [u8; 32] {
        let mut bytes = [0; 32];
        bytes[24..].copy_from_slice(&value.to_be_bytes());
        bytes
    }

    fn init(bit_bytes: usize, hashes: u8) -> Vec<u8> {
        let mut bytes = vec![0; NullifierFilter::account_size(bit_bytes).unwrap()];
        NullifierFilter::init(&mut bytes, &[1; 32], hashes).unwrap();
        bytes
    }

    #[test]
    fn replays_are_positive_and_queries_do_not_mutate() {
        let mut bytes = init(1024, 7);
        let batch: Vec<_> = (1..=128).map(nf).collect();
        let mut filter = NullifierFilter::from_bytes(&mut bytes, &[1; 32]).unwrap();
        assert!(filter.check_batch(&batch).unwrap().is_empty());
        filter.record_spent_batch(&batch).unwrap();
        let before = bytes.clone();
        let filter = NullifierFilter::from_bytes(&mut bytes, &[1; 32]).unwrap();
        assert_eq!(
            filter.check_batch(&batch).unwrap(),
            (0..128).collect::<Vec<_>>()
        );
        assert_eq!(bytes, before);
    }

    #[test]
    fn later_insertions_never_hide_prior_spends() {
        let mut bytes = init(1024, 7);
        let mut filter = NullifierFilter::from_bytes(&mut bytes, &[1; 32]).unwrap();
        let history: Vec<_> = (1..=2048).map(nf).collect();
        for end in (512..=2048).step_by(512) {
            filter.record_spent_batch(&history[end - 512..end]).unwrap();
            for batch in history[..end].chunks(512) {
                assert_eq!(filter.check_batch(batch).unwrap().len(), batch.len());
            }
        }
    }

    #[test]
    fn duplicate_and_invalid_batches_do_not_write() {
        let mut bytes = init(32, 7);
        let before = bytes.clone();
        for (batch, error) in [
            (vec![nf(1), nf(1)], FilterError::Duplicate),
            (vec![nf(1), [0; 32]], FilterError::InvalidBatch),
            (vec![nf(1), [255; 32]], FilterError::InvalidBatch),
            ((1..=513).map(nf).collect(), FilterError::InvalidBatch),
        ] {
            let mut filter = NullifierFilter::from_bytes(&mut bytes, &[1; 32]).unwrap();
            assert_eq!(filter.check_batch(&batch), Err(error));
            assert!(filter.record_spent_batch(&batch).is_err());
            assert_eq!(bytes, before);
        }
    }

    #[test]
    fn domain_and_layout_are_bound() {
        let bytes = init(32, 7);
        assert!(NullifierFilter::from_bytes(&mut bytes.clone(), &[2; 32]).is_err());
        for index in [0, 8, 40, 41] {
            let mut corrupt = bytes.clone();
            corrupt[index] = 255;
            assert!(NullifierFilter::from_bytes(&mut corrupt, &[1; 32]).is_err());
        }
        assert!(
            NullifierFilter::from_bytes(&mut bytes[..bytes.len() - 1].to_vec(), &[1; 32]).is_err()
        );
        assert!(NullifierFilter::from_bytes(&mut [0; 10], &[1; 32]).is_err());
        assert!(NullifierFilter::init(&mut bytes.clone(), &[1; 32], 7).is_err());
        assert_eq!(NullifierFilter::account_size(0), None);
        assert_eq!(NullifierFilter::account_size(3), None);
        let mut other = vec![0; bytes.len()];
        let mut first = bytes.clone();
        let mut a = NullifierFilter::from_bytes(&mut first, &[1; 32]).unwrap();
        let mut b = NullifierFilter::init(&mut other, &[2; 32], 7).unwrap();
        a.record_spent_batch(&[nf(42)]).unwrap();
        b.record_spent_batch(&[nf(42)]).unwrap();
        assert_ne!(&first[HEADER..], &other[HEADER..]);
    }

    #[test]
    fn saturation_requests_fallback_without_rejecting_fresh_inputs() {
        let mut bytes = init(1, 8);
        let mut filter = NullifierFilter::from_bytes(&mut bytes, &[1; 32]).unwrap();
        filter.record_spent_batch(&[nf(1)]).unwrap();
        assert_eq!(
            filter.check_batch(&[nf(1), nf(2), nf(3)]).unwrap(),
            vec![0, 1, 2]
        );
        let before = bytes.clone();
        let filter = NullifierFilter::from_bytes(&mut bytes, &[1; 32]).unwrap();
        assert_eq!(filter.check_batch(&[nf(2)]).unwrap(), vec![0]);
        assert_eq!(bytes, before);
    }

    #[test]
    fn batch_is_checked_before_any_bits_change() {
        let mut bytes = init(1, 8);
        let mut filter = NullifierFilter::from_bytes(&mut bytes, &[1; 32]).unwrap();
        assert!(filter.check_batch(&[nf(1), nf(2)]).unwrap().is_empty());
        filter.record_spent_batch(&[nf(1), nf(2)]).unwrap();
        assert_eq!(filter.check_batch(&[nf(1), nf(2)]).unwrap(), vec![0, 1]);
    }

    #[test]
    fn native_transaction_snapshot_can_discard_recorded_bits() {
        let mut committed = init(1024, 7);
        let mut working = committed.clone();
        NullifierFilter::from_bytes(&mut working, &[1; 32])
            .unwrap()
            .record_spent_batch(&[nf(1)])
            .unwrap();
        assert_ne!(working, committed);
        assert!(NullifierFilter::from_bytes(&mut committed, &[1; 32])
            .unwrap()
            .check_batch(&[nf(1)])
            .unwrap()
            .is_empty());
    }

    #[test]
    #[ignore]
    fn native_benchmark() {
        let mut bytes = init(4 * 1024 * 1024, 23);
        let mut filter = NullifierFilter::from_bytes(&mut bytes, &[1; 32]).unwrap();
        let start = Instant::now();
        for offset in (0..1_000_000).step_by(MAX_BATCH) {
            let batch: Vec<_> = (offset + 1..=(offset + MAX_BATCH).min(1_000_000))
                .map(|n| nf(n as u64))
                .collect();
            filter.record_spent_batch(&batch).unwrap();
        }
        println!(
            "FILTER_NATIVE seed_entries=1000000 bytes={} hash_calls=1000000 elapsed_ms={}",
            HEADER + 4 * 1024 * 1024,
            start.elapsed().as_millis()
        );
        for count in [36, 144, 512] {
            let batches: Vec<Vec<_>> = (0..1000)
                .map(|round| {
                    (0..count)
                        .map(|i| nf(2_000_000 + (round * count + i) as u64))
                        .collect()
                })
                .collect();
            let start = Instant::now();
            let positives: usize = batches
                .iter()
                .map(|batch| filter.check_batch(batch).unwrap().len())
                .sum();
            println!("FILTER_NATIVE inputs={count} rounds=1000 positives={positives} hash_calls={} mean_query_us={:.3}", count * 1000, start.elapsed().as_secs_f64() * 1000.0);
        }
    }
}
