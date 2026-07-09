use light_program_profiler::profile;
use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use rings_bloom_filter::BloomFilter;

#[cfg(not(feature = "no-entrypoint"))]
mod entrypoint {
    pinocchio::entrypoint!(crate::process_instruction);
}

pub const MISS_BASE: u64 = 10_000_000;

const NUM_ITERS: usize = 10;
const STATE_BLOOM_BYTES: usize = 287_692;
const ADDRESS_BLOOM_BYTES: usize = 575_384;

pub fn process_instruction(
    _program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    // First byte is the historical num-hashes selector; it is now the const
    // generic NUM_ITERS and only the supported shapes are benchmarked.
    let _num_iters = *data.first().ok_or(ProgramError::InvalidInstructionData)?;
    let n = {
        let bytes = data.get(1..3).ok_or(ProgramError::InvalidInstructionData)?;
        let arr: [u8; 2] = bytes
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        u16::from_le_bytes(arr) as u64
    };

    let store_account = accounts
        .first_mut()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let mut store = store_account
        .try_borrow_mut()
        .map_err(|_| ProgramError::AccountBorrowFailed)?;

    if store.len() == STATE_BLOOM_BYTES {
        run::<NUM_ITERS, STATE_BLOOM_BYTES>(&mut store, n)
    } else if store.len() == ADDRESS_BLOOM_BYTES {
        run::<NUM_ITERS, ADDRESS_BLOOM_BYTES>(&mut store, n)
    } else {
        Err(ProgramError::InvalidInstructionData)
    }
}

fn run<const NUM_ITERS: usize, const BYTES: usize>(store: &mut [u8], n: u64) -> ProgramResult {
    let mut values: Vec<[u8; 32]> = (0..n).map(derive_value).collect();

    // Single zero-copy cast: the store account becomes a `BloomFilter` once and
    // is reused for every benchmarked operation.
    let filter = BloomFilter::<NUM_ITERS, BYTES>::from_bytes_mut(store);
    bench_insert(filter, &values)?;
    let hits = bench_contains_hit(filter, &values)?;

    for (i, value) in values.iter_mut().enumerate() {
        *value = derive_value(MISS_BASE.wrapping_add(i as u64));
    }
    let misses = bench_contains_miss(filter, &values)?;
    core::hint::black_box((hits, misses));

    Ok(())
}

#[profile]
fn bench_insert<const NUM_ITERS: usize, const BYTES: usize>(
    filter: &mut BloomFilter<NUM_ITERS, BYTES>,
    values: &[[u8; 32]],
) -> ProgramResult {
    for value in values {
        filter.insert(value)?;
    }
    Ok(())
}

#[profile]
fn bench_contains_hit<const NUM_ITERS: usize, const BYTES: usize>(
    filter: &BloomFilter<NUM_ITERS, BYTES>,
    values: &[[u8; 32]],
) -> Result<u64, ProgramError> {
    let mut hits = 0u64;
    for value in values {
        if filter.contains(value) {
            hits = hits.wrapping_add(1);
        }
    }
    Ok(hits)
}

#[profile]
fn bench_contains_miss<const NUM_ITERS: usize, const BYTES: usize>(
    filter: &BloomFilter<NUM_ITERS, BYTES>,
    values: &[[u8; 32]],
) -> Result<u64, ProgramError> {
    let mut misses = 0u64;
    for value in values {
        if !filter.contains(value) {
            misses = misses.wrapping_add(1);
        }
    }
    Ok(misses)
}

fn derive_value(counter: u64) -> [u8; 32] {
    let mut value = [0u8; 32];
    for (dst, src) in value.iter_mut().zip(counter.to_le_bytes().iter()) {
        *dst = *src;
    }
    value
}
