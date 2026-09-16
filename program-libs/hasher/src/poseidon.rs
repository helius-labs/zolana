use thiserror::{self, Error};

use crate::{
    errors::HasherError,
    zero_bytes::{poseidon::ZERO_BYTES, ZeroBytes},
    Hash, Hasher,
};

#[derive(Debug, Error, PartialEq)]
pub enum PoseidonSyscallError {
    #[error("Invalid parameters.")]
    InvalidParameters,
    #[error("Invalid endianness.")]
    InvalidEndianness,
    #[error("Invalid number of inputs. Maximum allowed is 12.")]
    InvalidNumberOfInputs,
    #[error("Input is an empty slice.")]
    EmptyInput,
    #[error(
        "Invalid length of the input. The length matching the modulus of the prime field is 32."
    )]
    InvalidInputLength,
    #[error("Failed to convert bytest into a prime field element.")]
    BytesToPrimeFieldElement,
    #[error("Input is larger than the modulus of the prime field.")]
    InputLargerThanModulus,
    #[error("Failed to convert a vector of bytes into an array.")]
    VecToArray,
    #[error("Failed to convert the number of inputs from u64 to u8.")]
    U64Tou8,
    #[error("Failed to convert bytes to BigInt")]
    BytesToBigInt,
    #[error("Invalid width. Choose a width between 2 and 16 for 1 to 15 inputs.")]
    InvalidWidthCircom,
    #[error("Unexpected error")]
    Unexpected,
}

impl From<u64> for PoseidonSyscallError {
    fn from(error: u64) -> Self {
        match error {
            1 => PoseidonSyscallError::InvalidParameters,
            2 => PoseidonSyscallError::InvalidEndianness,
            3 => PoseidonSyscallError::InvalidNumberOfInputs,
            4 => PoseidonSyscallError::EmptyInput,
            5 => PoseidonSyscallError::InvalidInputLength,
            6 => PoseidonSyscallError::BytesToPrimeFieldElement,
            7 => PoseidonSyscallError::InputLargerThanModulus,
            8 => PoseidonSyscallError::VecToArray,
            9 => PoseidonSyscallError::U64Tou8,
            10 => PoseidonSyscallError::BytesToBigInt,
            11 => PoseidonSyscallError::InvalidWidthCircom,
            _ => PoseidonSyscallError::Unexpected,
        }
    }
}

impl From<PoseidonSyscallError> for u64 {
    fn from(error: PoseidonSyscallError) -> Self {
        match error {
            PoseidonSyscallError::InvalidParameters => 1,
            PoseidonSyscallError::InvalidEndianness => 2,
            PoseidonSyscallError::InvalidNumberOfInputs => 3,
            PoseidonSyscallError::EmptyInput => 4,
            PoseidonSyscallError::InvalidInputLength => 5,
            PoseidonSyscallError::BytesToPrimeFieldElement => 6,
            PoseidonSyscallError::InputLargerThanModulus => 7,
            PoseidonSyscallError::VecToArray => 8,
            PoseidonSyscallError::U64Tou8 => 9,
            PoseidonSyscallError::BytesToBigInt => 10,
            PoseidonSyscallError::InvalidWidthCircom => 11,
            PoseidonSyscallError::Unexpected => 12,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Poseidon;

#[cfg(all(feature = "std", not(target_os = "solana")))]
mod native {
    use super::*;
    use ark_bn254::Fr;
    use light_poseidon::{Poseidon as NativePoseidon, PoseidonBytesHasher, MAX_X5_LEN};
    use std::cell::RefCell;

    thread_local! {
        static HASHERS: RefCell<[Option<NativePoseidon<Fr>>; MAX_X5_LEN]> =
            RefCell::new(std::array::from_fn(|_| None));
    }

    pub(super) fn hash(inputs: &[&[u8]]) -> Result<Hash, HasherError> {
        HASHERS.with(|hashers| {
            let Ok(mut hashers) = hashers.try_borrow_mut() else {
                return fresh(inputs);
            };
            let Some(slot) = hashers.get_mut(inputs.len()) else {
                return fresh(inputs);
            };
            if slot.is_none() {
                *slot = Some(NativePoseidon::<Fr>::new_circom(inputs.len())?);
            }
            Ok(slot.as_mut().unwrap().hash_bytes_be(inputs)?)
        })
    }

    fn fresh(inputs: &[&[u8]]) -> Result<Hash, HasherError> {
        Ok(NativePoseidon::<Fr>::new_circom(inputs.len())?.hash_bytes_be(inputs)?)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn cached_hashes_match_fresh_hashes() {
            for seed in 0..3u8 {
                for arity in 1..MAX_X5_LEN {
                    let values = (0..arity)
                        .map(|index| [seed + index as u8; 32])
                        .collect::<Vec<_>>();
                    let inputs = values
                        .iter()
                        .map(|value| value.as_slice())
                        .collect::<Vec<_>>();
                    assert_eq!(hash(&inputs), fresh(&inputs));
                }
            }
        }

        #[test]
        fn errors_and_reentrant_calls_preserve_cached_state() {
            for values in [
                vec![],
                vec![&[0u8; 32][..]; MAX_X5_LEN],
                vec![&[0u8; 31][..]],
                vec![&[255u8; 32][..]],
            ] {
                assert_eq!(hash(&values), fresh(&values));
                assert!(hash(&values).is_err());
                assert_eq!(hash(&[&[1; 32]]), fresh(&[&[1; 32]]));
            }
            HASHERS.with(|hashers| {
                let _borrow = hashers.borrow_mut();
                assert_eq!(hash(&[&[2; 32]]), fresh(&[&[2; 32]]));
            });
            std::thread::spawn(|| assert_eq!(hash(&[&[3; 32]]), fresh(&[&[3; 32]])))
                .join()
                .unwrap();
        }

        #[test]
        #[ignore]
        fn benchmark_native_poseidon_reuse() {
            for arity in [2, 3, 4, 5, 9] {
                let values = vec![[7u8; 32]; arity];
                let inputs = values
                    .iter()
                    .map(|value| value.as_slice())
                    .collect::<Vec<_>>();
                let mut elapsed = Vec::new();
                for run in [fresh, hash] {
                    let started = std::time::Instant::now();
                    for _ in 0..512 {
                        std::hint::black_box(run(&inputs).unwrap());
                    }
                    elapsed.push(started.elapsed().as_micros());
                }
                println!(
                    "POSEIDON_REUSE arity={arity} hashes=512 fresh_us={} reused_us={}",
                    elapsed[0], elapsed[1]
                );
            }
        }
    }
}

impl Hasher for Poseidon {
    const ID: u8 = 0;

    fn hash(val: &[u8]) -> Result<Hash, HasherError> {
        Self::hashv(&[val])
    }

    fn hashv(_vals: &[&[u8]]) -> Result<Hash, HasherError> {
        // Perform the calculation inline, calling this from within a program is
        // not supported.
        #[cfg(all(feature = "std", not(target_os = "solana")))]
        {
            native::hash(_vals)
        }
        #[cfg(all(not(feature = "std"), not(target_os = "solana")))]
        {
            use ark_bn254::Fr;
            use light_poseidon::{Poseidon, PoseidonBytesHasher};

            let mut hasher = Poseidon::<Fr>::new_circom(_vals.len())?;
            let res = hasher.hash_bytes_be(_vals)?;

            Ok(res)
        }
        // Call via a system call to perform the calculation.
        #[cfg(target_os = "solana")]
        {
            use crate::HASH_BYTES;
            for val in _vals {
                if val.len() != 32 {
                    return Err(HasherError::InvalidInputLength(val.len(), 32));
                }
            }
            let mut hash_result = [0; HASH_BYTES];
            let result = unsafe {
                crate::syscalls::sol_poseidon(
                    0, // bn254
                    0, // big-endian
                    _vals as *const _ as *const u8,
                    _vals.len() as u64,
                    &mut hash_result as *mut _ as *mut u8,
                )
            };

            match result {
                0 => Ok(hash_result),
                e => Err(HasherError::from(PoseidonSyscallError::from(e))),
            }
        }
    }

    fn zero_bytes() -> &'static ZeroBytes {
        &ZERO_BYTES
    }
}
