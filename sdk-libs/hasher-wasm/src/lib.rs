//! The Poseidon the TypeScript SDK hashes with, compiled from the same
//! `zolana_hasher::Poseidon` the program and the Rust SDK call.
//!
//! The interface is deliberately raw rather than `wasm-bindgen`: the module has
//! to load from a package that ships plain `tsc` output, with no bundler plugin
//! and no asset fetch, so it exports C functions over two fixed buffers and the
//! caller copies bytes in and out. There is no allocator on this path and no
//! import object, so the module instantiates against an empty environment.
//!
//! `MAX_INPUTS` is the arity ceiling in the ABI rather than in a table a caller
//! could get wrong: `light_poseidon` caps the width at 13 and the `sol_poseidon`
//! syscall takes at most twelve inputs, so a thirteen-input digest is one no
//! verifier can reproduce.

use zolana_hasher::{errors::HasherError, Hasher, Poseidon};

const MAX_INPUTS: usize = 12;
const FIELD_BYTES: usize = 32;

/// Returned when the caller asks for an arity the hasher cannot serve. Distinct
/// from the `HasherError` space, which starts at 7001.
const ERROR_ARITY: u32 = 1;

static mut INPUT: [u8; MAX_INPUTS * FIELD_BYTES] = [0; MAX_INPUTS * FIELD_BYTES];
static mut OUTPUT: [u8; FIELD_BYTES] = [0; FIELD_BYTES];

/// Where the caller writes `count * 32` big-endian field elements.
#[no_mangle]
pub extern "C" fn zolana_poseidon_input() -> *mut u8 {
    core::ptr::addr_of_mut!(INPUT).cast()
}

/// Where the caller reads the 32-byte digest after a zero return.
#[no_mangle]
pub extern "C" fn zolana_poseidon_output() -> *mut u8 {
    core::ptr::addr_of_mut!(OUTPUT).cast()
}

/// The arity ceiling, so the port reads the bound off the module rather than
/// keeping its own copy of it.
#[no_mangle]
pub extern "C" fn zolana_poseidon_max_inputs() -> u32 {
    MAX_INPUTS as u32
}

/// Hashes the first `count` field elements of the input buffer, leaving the
/// digest in the output buffer. Returns 0 on success, otherwise the
/// `HasherError` code, so a rejection reaches TypeScript as the number Rust
/// gives it.
///
/// # Safety
///
/// WebAssembly gives this module a single thread and no reentrancy, so the two
/// static buffers have one live borrow at a time by construction.
#[no_mangle]
pub extern "C" fn zolana_poseidon_hashv(count: u32) -> u32 {
    let count = count as usize;
    if count == 0 || count > MAX_INPUTS {
        return ERROR_ARITY;
    }

    let input = unsafe { &*core::ptr::addr_of!(INPUT) };
    let mut elements: [&[u8]; MAX_INPUTS] = [&[]; MAX_INPUTS];
    for (index, element) in elements.iter_mut().enumerate().take(count) {
        *element = &input[index * FIELD_BYTES..(index + 1) * FIELD_BYTES];
    }

    match Poseidon::hashv(&elements[..count]) {
        Ok(digest) => {
            unsafe { core::ptr::addr_of_mut!(OUTPUT).write(digest) };
            0
        }
        Err(error) => u32::from(error),
    }
}

/// Reports the `HasherError` code for an input the hasher refuses, without
/// hashing. The port has no other way to learn Rust's code for a rejection it
/// screens out before the call.
#[no_mangle]
pub extern "C" fn zolana_poseidon_error_non_canonical() -> u32 {
    u32::from(HasherError::InvalidInputLength(
        FIELD_BYTES,
        FIELD_BYTES + 1,
    ))
}
