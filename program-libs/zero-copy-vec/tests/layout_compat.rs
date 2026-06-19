//! Layout compatibility gate.
//!
//! Bit-for-bit cross-validation between the new in-crate types
//! (`BoundedSliceMut`, `CyclicSliceMut`) and the released crates.io
//! `light-zero-copy 0.6.0` types (`ZeroCopyVecU64`, `ZeroCopyCyclicVecU64`).
//! Both write/read directions are exercised for every (T, capacity) pair.
//!
//! If any test in this file fails, deployed Solana accounts written by the
//! released crate will not be readable by the new crate (or vice versa) —
//! "no state layout change" is violated.

use light_zero_copy::{
    cyclic_vec::ZeroCopyCyclicVecU64 as OldCyclic, vec::ZeroCopyVecU64 as OldBounded,
};
use light_zero_copy_vec::{
    bounded_slice::BoundedSliceMut as NewBounded, cyclic_slice::CyclicSliceMut as NewCyclic,
};

// --- BoundedSlice ---

fn bounded_new_to_old<T>(capacity: u64, values: &[T])
where
    T: Copy
        + PartialEq
        + core::fmt::Debug
        + zerocopy::FromBytes
        + zerocopy::IntoBytes
        + zerocopy::Immutable
        + zerocopy::KnownLayout,
{
    let size = NewBounded::<T>::required_size_for_capacity(capacity);
    assert_eq!(size, OldBounded::<T>::required_size_for_capacity(capacity));

    let mut buf = vec![0u8; size];
    {
        let mut v = NewBounded::<T>::new(capacity, &mut buf).unwrap();
        for x in values {
            v.push(*x).unwrap();
        }
    }
    // Parse the same bytes with the released parser.
    let parsed = OldBounded::<T>::from_bytes(&mut buf).unwrap();
    assert_eq!(parsed.len(), values.len(), "len mismatch");
    assert_eq!(parsed.capacity() as u64, capacity, "capacity mismatch");
    assert_eq!(parsed.as_slice(), values, "data mismatch");
}

fn bounded_old_to_new<T>(capacity: u64, values: &[T])
where
    T: Copy
        + PartialEq
        + core::fmt::Debug
        + zerocopy::FromBytes
        + zerocopy::IntoBytes
        + zerocopy::Immutable
        + zerocopy::KnownLayout,
{
    let size = OldBounded::<T>::required_size_for_capacity(capacity);
    let mut buf = vec![0u8; size];
    {
        let mut v = OldBounded::<T>::new(capacity, &mut buf).unwrap();
        for x in values {
            v.push(*x).unwrap();
        }
    }
    let parsed = NewBounded::<T>::from_bytes(&mut buf).unwrap();
    assert_eq!(parsed.len(), values.len());
    assert_eq!(parsed.capacity() as u64, capacity);
    assert_eq!(parsed.as_slice(), values);
}

#[test]
fn bounded_u8_both_directions() {
    for cap in [1u64, 7, 64, 512] {
        let values: Vec<u8> = (0..cap.min(5) as u8).collect();
        bounded_new_to_old::<u8>(cap, &values);
        bounded_old_to_new::<u8>(cap, &values);
    }
}

#[test]
fn bounded_u32_both_directions() {
    for cap in [1u64, 7, 64, 512] {
        let values: Vec<u32> = (0..cap.min(5) as u32).map(|i| i * 1_000_000).collect();
        bounded_new_to_old::<u32>(cap, &values);
        bounded_old_to_new::<u32>(cap, &values);
    }
}

#[test]
fn bounded_u64_both_directions() {
    for cap in [1u64, 7, 64, 512] {
        let values: Vec<u64> = (0..cap.min(5)).map(|i| i * 0x0102030405060708).collect();
        bounded_new_to_old::<u64>(cap, &values);
        bounded_old_to_new::<u64>(cap, &values);
    }
}

#[test]
fn bounded_array_32_both_directions() {
    // Mirror BMT's usage exactly.
    for cap in [1u64, 7, 64, 512] {
        let values: Vec<[u8; 32]> = (0..cap.min(5))
            .map(|i| {
                let mut a = [0u8; 32];
                a[0] = i as u8;
                a[31] = (cap & 0xff) as u8;
                a
            })
            .collect();
        bounded_new_to_old::<[u8; 32]>(cap, &values);
        bounded_old_to_new::<[u8; 32]>(cap, &values);
    }
}

#[test]
fn bounded_byte_identical_for_array_32() {
    // The strongest assertion: side-by-side bytes from new and old are equal.
    let capacity = 64u64;
    let values: Vec<[u8; 32]> = (0..16u64)
        .map(|i| {
            let mut a = [0u8; 32];
            a[0..8].copy_from_slice(&i.to_le_bytes());
            a
        })
        .collect();

    let size = NewBounded::<[u8; 32]>::required_size_for_capacity(capacity);
    let mut new_buf = vec![0u8; size];
    let mut old_buf = vec![0u8; size];
    {
        let mut v = NewBounded::<[u8; 32]>::new(capacity, &mut new_buf).unwrap();
        for x in &values {
            v.push(*x).unwrap();
        }
    }
    {
        let mut v = OldBounded::<[u8; 32]>::new(capacity, &mut old_buf).unwrap();
        for x in &values {
            v.push(*x).unwrap();
        }
    }
    assert_eq!(new_buf, old_buf, "byte-level layout divergence");
}

// --- CyclicSlice ---

fn cyclic_new_to_old<T>(capacity: u64, values: &[T])
where
    T: Copy
        + PartialEq
        + core::fmt::Debug
        + zerocopy::FromBytes
        + zerocopy::IntoBytes
        + zerocopy::Immutable
        + zerocopy::KnownLayout,
{
    let size = NewCyclic::<T>::required_size_for_capacity(capacity);
    assert_eq!(size, OldCyclic::<T>::required_size_for_capacity(capacity));
    let mut buf = vec![0u8; size];
    {
        let mut v = NewCyclic::<T>::new(capacity, &mut buf).unwrap();
        for x in values {
            v.push(*x);
        }
    }
    let parsed = OldCyclic::<T>::from_bytes(&mut buf).unwrap();
    assert_eq!(parsed.len(), values.len().min(capacity as usize));
    assert_eq!(parsed.capacity() as u64, capacity);
}

fn cyclic_old_to_new<T>(capacity: u64, values: &[T])
where
    T: Copy
        + PartialEq
        + core::fmt::Debug
        + zerocopy::FromBytes
        + zerocopy::IntoBytes
        + zerocopy::Immutable
        + zerocopy::KnownLayout,
{
    let size = OldCyclic::<T>::required_size_for_capacity(capacity);
    let mut buf = vec![0u8; size];
    {
        let mut v = OldCyclic::<T>::new(capacity, &mut buf).unwrap();
        for x in values {
            v.push(*x);
        }
    }
    let parsed = NewCyclic::<T>::from_bytes(&mut buf).unwrap();
    assert_eq!(parsed.len(), values.len().min(capacity as usize));
    assert_eq!(parsed.capacity() as u64, capacity);
}

#[test]
fn cyclic_u8_under_capacity() {
    for cap in [1u64, 7, 64, 512] {
        let values: Vec<u8> = (0..cap.min(3) as u8).collect();
        cyclic_new_to_old::<u8>(cap, &values);
        cyclic_old_to_new::<u8>(cap, &values);
    }
}

#[test]
fn cyclic_u64_under_capacity() {
    for cap in [1u64, 7, 64, 512] {
        let values: Vec<u64> = (0..cap.min(3)).collect();
        cyclic_new_to_old::<u64>(cap, &values);
        cyclic_old_to_new::<u64>(cap, &values);
    }
}

#[test]
fn cyclic_array_32_under_capacity() {
    for cap in [1u64, 7, 64, 512] {
        let values: Vec<[u8; 32]> = (0..cap.min(3))
            .map(|i| {
                let mut a = [0u8; 32];
                a[0] = i as u8;
                a
            })
            .collect();
        cyclic_new_to_old::<[u8; 32]>(cap, &values);
        cyclic_old_to_new::<[u8; 32]>(cap, &values);
    }
}

#[test]
fn cyclic_array_32_wraparound() {
    // Push past capacity to exercise the wrap; both ends must agree.
    let cap = 4u64;
    let values: Vec<[u8; 32]> = (0..(cap * 2 + 1) as u8)
        .map(|i| {
            let mut a = [0u8; 32];
            a[0] = i;
            a
        })
        .collect();
    cyclic_new_to_old::<[u8; 32]>(cap, &values);
    cyclic_old_to_new::<[u8; 32]>(cap, &values);
}

#[test]
fn cyclic_byte_identical_for_array_32() {
    let capacity = 32u64;
    let values: Vec<[u8; 32]> = (0..40u8)
        .map(|i| {
            let mut a = [0u8; 32];
            a[0] = i;
            a
        })
        .collect();

    let size = NewCyclic::<[u8; 32]>::required_size_for_capacity(capacity);
    let mut new_buf = vec![0u8; size];
    let mut old_buf = vec![0u8; size];
    {
        let mut v = NewCyclic::<[u8; 32]>::new(capacity, &mut new_buf).unwrap();
        for x in &values {
            v.push(*x);
        }
    }
    {
        let mut v = OldCyclic::<[u8; 32]>::new(capacity, &mut old_buf).unwrap();
        for x in &values {
            v.push(*x);
        }
    }
    assert_eq!(new_buf, old_buf, "byte-level layout divergence (cyclic)");
}
