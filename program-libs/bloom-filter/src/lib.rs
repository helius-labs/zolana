//! # light-bloom-filter
//!
//! Experimental bloom filter using keccak hashing.
//!
//! The store is owned inline as `[u8; BYTES]` and the number of hash
//! iterations is the const generic `NUM_ITERS`, so a `BloomFilter` is a plain
//! `Pod` value that can live directly inside a zero-copy account layout.

use std::f64::consts::LN_2;

use bytemuck::{Pod, Zeroable};
use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum BloomFilterError {
    #[error("Bloom filter is full")]
    Full,
}

impl From<BloomFilterError> for u32 {
    fn from(e: BloomFilterError) -> u32 {
        match e {
            BloomFilterError::Full => 14201,
        }
    }
}

impl From<BloomFilterError> for solana_program_error::ProgramError {
    fn from(e: BloomFilterError) -> Self {
        solana_program_error::ProgramError::Custom(e.into())
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BloomFilter<const NUM_ITERS: usize, const BYTES: usize> {
    store: [u8; BYTES],
}

// Safety: the only field is `[u8; BYTES]`, which is `Pod` for any `BYTES`. The
// struct is `#[repr(C)]` with no padding and `NUM_ITERS` does not affect the
// layout, so every bit pattern is valid and the value is safe to treat as bytes.
unsafe impl<const NUM_ITERS: usize, const BYTES: usize> Zeroable for BloomFilter<NUM_ITERS, BYTES> {}
unsafe impl<const NUM_ITERS: usize, const BYTES: usize> Pod for BloomFilter<NUM_ITERS, BYTES> {}

impl<const NUM_ITERS: usize, const BYTES: usize> BloomFilter<NUM_ITERS, BYTES> {
    pub fn calculate_bloom_filter_size(n: usize, p: f64) -> usize {
        let m = -((n as f64) * p.ln()) / (LN_2 * LN_2);
        m.ceil() as usize
    }

    pub fn calculate_optimal_hash_functions(n: usize, m: usize) -> usize {
        let k = (m as f64 / n as f64) * LN_2;
        k.ceil() as usize
    }

    pub const fn new() -> Self {
        Self {
            store: [0u8; BYTES],
        }
    }

    /// Reinterpret raw account bytes as a `BloomFilter` in place. This is the
    /// single zero-copy boundary cast; callers that already hold a typed layout
    /// (e.g. a tree account) reach the bloom filter by field access instead.
    pub fn from_bytes_mut(bytes: &mut [u8]) -> &mut Self {
        bytemuck::from_bytes_mut(bytes)
    }

    pub fn zero(&mut self) {
        self.store = [0u8; BYTES];
    }

    pub fn is_zeroed(&self) -> bool {
        self.store.iter().all(|&b| b == 0)
    }

    pub fn insert(&mut self, value: &[u8; 32]) -> Result<(), BloomFilterError> {
        let hash = solana_nostd_keccak::hash(value);
        let h1 = u64::from_le_bytes(hash[0..8].try_into().unwrap());
        let h2 = u64::from_le_bytes(hash[8..16].try_into().unwrap());
        let num_bits = BYTES as u64 * 8;

        let mut probe = h1;
        let mut all_bits_set = true;
        for _ in 0..NUM_ITERS {
            let probe_index = (probe % num_bits) as usize;
            probe = probe.wrapping_add(h2);

            let byte_index = probe_index >> 3;
            let mask = 1u8 << (probe_index & 7);
            match self.store.get_mut(byte_index) {
                Some(byte) => {
                    if *byte & mask == 0 {
                        all_bits_set = false;
                        *byte |= mask;
                    }
                }
                None => return Err(BloomFilterError::Full),
            }
        }

        if all_bits_set {
            Err(BloomFilterError::Full)
        } else {
            Ok(())
        }
    }

    pub fn contains(&self, value: &[u8; 32]) -> bool {
        let hash = solana_nostd_keccak::hash(value);
        let h1 = u64::from_le_bytes(hash[0..8].try_into().unwrap());
        let h2 = u64::from_le_bytes(hash[8..16].try_into().unwrap());
        let num_bits = BYTES as u64 * 8;

        let mut probe = h1;
        for _ in 0..NUM_ITERS {
            let probe_index = (probe % num_bits) as usize;
            probe = probe.wrapping_add(h2);

            let byte_index = probe_index >> 3;
            let mask = 1u8 << (probe_index & 7);
            match self.store.get(byte_index) {
                Some(byte) if *byte & mask != 0 => {}
                _ => return false,
            }
        }
        true
    }
}

impl<const NUM_ITERS: usize, const BYTES: usize> Default for BloomFilter<NUM_ITERS, BYTES> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod test {
    use num_bigint::{RandBigInt, ToBigUint};
    use rand::thread_rng;
    use rings_hasher::bigint::bigint_to_be_bytes_array;

    use super::*;

    #[test]
    fn test_insert_and_contains() -> Result<(), BloomFilterError> {
        let mut bf = Box::new(BloomFilter::<3, 128_000>::new());

        let value1 = [1u8; 32];
        let value2 = [2u8; 32];

        bf.insert(&value1)?;
        assert!(bf.contains(&value1));
        assert!(!bf.contains(&value2));

        Ok(())
    }

    #[test]
    fn short_rnd_test() {
        // capacity 500 elements, store 20_000 bytes, 3 hash functions.
        rnd_test::<3, 20_000>(1000, 500);
    }

    fn rnd_test<const NUM_ITERS: usize, const BYTES: usize>(rounds: usize, capacity: usize) {
        println!("Optimal hash functions: {}", NUM_ITERS);
        println!("Bloom filter capacity (kb): {}", BYTES / 1_000);
        let mut num_total_txs = 0;
        let mut rng = thread_rng();
        for j in 0..rounds {
            let mut inserted_values = Vec::new();
            let mut bf = Box::new(BloomFilter::<NUM_ITERS, BYTES>::new());
            if j == 0 {
                println!("Bloom filter size: {}", BYTES);
                println!("num iters: {}", NUM_ITERS);
            }
            for _ in 0..capacity {
                num_total_txs += 1;
                let value = {
                    let mut _value = 0u64.to_biguint().unwrap();
                    while inserted_values.contains(&_value.clone()) {
                        _value = rng.gen_biguint(254);
                    }
                    inserted_values.push(_value.clone());

                    _value
                };
                let value: [u8; 32] = bigint_to_be_bytes_array(&value).unwrap();
                bf.insert(&value).ok();
                assert!(bf.contains(&value));
                assert!(bf.insert(&value).is_err());
            }
        }
        println!("total num tx {}", num_total_txs);
    }
}
