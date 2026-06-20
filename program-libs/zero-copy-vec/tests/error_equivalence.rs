//! Error-variant equivalence audit.
//!
//! For each BMT code path that produces a `ZeroCopyError`, verify the new
//! `BoundedSliceMut` / `CyclicSliceMut` emit the same variant with the same
//! payload as crates.io `light-zero-copy 0.6.0`'s `ZeroCopyVecU64` /
//! `ZeroCopyCyclicVecU64`. This preserves the error codes surfaced by
//! `BatchedMerkleTreeError::From<ZeroCopyError>`.
//!
//! Note: the new and old crates have distinct `ZeroCopyError` enums (different
//! crates), but identical variant names and payloads since the new one is a
//! verbatim port. We compare variant tags and payloads side by side.

use light_zero_copy::{
    cyclic_vec::ZeroCopyCyclicVecU64 as OldCyclic, errors::ZeroCopyError as OldErr,
    vec::ZeroCopyVecU64 as OldBounded,
};
use light_zero_copy_vec::{
    bounded_slice::BoundedSliceMut, cyclic_slice::CyclicSliceMut, errors::ZeroCopyError as NewErr,
};

#[test]
fn bounded_new_insufficient_memory() {
    // Buffer smaller than metadata_size (16 bytes).
    let mut old_buf = vec![0u8; 8];
    let mut new_buf = vec![0u8; 8];
    let old = OldBounded::<u64>::new(4, &mut old_buf);
    let new = BoundedSliceMut::<u64>::new(4, &mut new_buf);
    assert!(matches!(
        old,
        Err(OldErr::InsufficientMemoryAllocated(8, 16))
    ));
    assert!(matches!(
        new,
        Err(NewErr::InsufficientMemoryAllocated(8, 16))
    ));
}

#[test]
fn bounded_new_memory_not_zeroed() {
    let mut old_buf = vec![1u8; OldBounded::<u64>::required_size_for_capacity(4)];
    let mut new_buf = vec![1u8; BoundedSliceMut::<u64>::required_size_for_capacity(4)];
    let old = OldBounded::<u64>::new(4, &mut old_buf);
    let new = BoundedSliceMut::<u64>::new(4, &mut new_buf);
    assert!(matches!(old, Err(OldErr::MemoryNotZeroed)));
    assert!(matches!(new, Err(NewErr::MemoryNotZeroed)));
}

#[test]
fn bounded_from_bytes_length_gt_capacity() {
    let mut old_buf = vec![0u8; OldBounded::<u64>::required_size_for_capacity(4)];
    let mut new_buf = vec![0u8; BoundedSliceMut::<u64>::required_size_for_capacity(4)];
    // Plant length=5, capacity=4.
    old_buf[0..8].copy_from_slice(&5u64.to_le_bytes());
    old_buf[8..16].copy_from_slice(&4u64.to_le_bytes());
    new_buf[0..8].copy_from_slice(&5u64.to_le_bytes());
    new_buf[8..16].copy_from_slice(&4u64.to_le_bytes());
    let old = OldBounded::<u64>::from_bytes(&mut old_buf);
    let new = BoundedSliceMut::<u64>::from_bytes(&mut new_buf);
    assert!(matches!(old, Err(OldErr::LengthGreaterThanCapacity)));
    assert!(matches!(new, Err(NewErr::LengthGreaterThanCapacity)));
}

#[test]
fn bounded_push_full() {
    let mut old_buf = vec![0u8; OldBounded::<u64>::required_size_for_capacity(2)];
    let mut new_buf = vec![0u8; BoundedSliceMut::<u64>::required_size_for_capacity(2)];
    let mut old = OldBounded::<u64>::new(2, &mut old_buf).unwrap();
    let mut new = BoundedSliceMut::<u64>::new(2, &mut new_buf).unwrap();
    old.push(1).unwrap();
    old.push(2).unwrap();
    new.push(1).unwrap();
    new.push(2).unwrap();
    assert!(matches!(old.push(3), Err(OldErr::Full)));
    assert!(matches!(new.push(3), Err(NewErr::Full)));
}

#[test]
fn cyclic_new_invalid_capacity_zero() {
    let mut old_buf = vec![0u8; 64];
    let mut new_buf = vec![0u8; 64];
    let old = OldCyclic::<u64>::new(0, &mut old_buf);
    let new = CyclicSliceMut::<u64>::new(0, &mut new_buf);
    assert!(matches!(old, Err(OldErr::InvalidCapacity)));
    assert!(matches!(new, Err(NewErr::InvalidCapacity)));
}

#[test]
fn cyclic_new_insufficient_memory() {
    let mut old_buf = vec![0u8; 8];
    let mut new_buf = vec![0u8; 8];
    let old = OldCyclic::<u64>::new(4, &mut old_buf);
    let new = CyclicSliceMut::<u64>::new(4, &mut new_buf);
    assert!(matches!(
        old,
        Err(OldErr::InsufficientMemoryAllocated(8, 24))
    ));
    assert!(matches!(
        new,
        Err(NewErr::InsufficientMemoryAllocated(8, 24))
    ));
}

#[test]
fn cyclic_new_memory_not_zeroed() {
    let mut old_buf = vec![1u8; OldCyclic::<u64>::required_size_for_capacity(4)];
    let mut new_buf = vec![1u8; CyclicSliceMut::<u64>::required_size_for_capacity(4)];
    let old = OldCyclic::<u64>::new(4, &mut old_buf);
    let new = CyclicSliceMut::<u64>::new(4, &mut new_buf);
    assert!(matches!(old, Err(OldErr::MemoryNotZeroed)));
    assert!(matches!(new, Err(NewErr::MemoryNotZeroed)));
}

#[test]
fn cyclic_from_bytes_length_gt_capacity() {
    let mut old_buf = vec![0u8; OldCyclic::<u64>::required_size_for_capacity(4)];
    let mut new_buf = vec![0u8; CyclicSliceMut::<u64>::required_size_for_capacity(4)];
    // current_index=0, length=5, capacity=4.
    for buf in [&mut old_buf, &mut new_buf] {
        buf[0..8].copy_from_slice(&0u64.to_le_bytes());
        buf[8..16].copy_from_slice(&5u64.to_le_bytes());
        buf[16..24].copy_from_slice(&4u64.to_le_bytes());
    }
    let old = OldCyclic::<u64>::from_bytes(&mut old_buf);
    let new = CyclicSliceMut::<u64>::from_bytes(&mut new_buf);
    assert!(matches!(old, Err(OldErr::LengthGreaterThanCapacity)));
    assert!(matches!(new, Err(NewErr::LengthGreaterThanCapacity)));
}

#[test]
fn cyclic_from_bytes_current_gt_length() {
    let mut old_buf = vec![0u8; OldCyclic::<u64>::required_size_for_capacity(4)];
    let mut new_buf = vec![0u8; CyclicSliceMut::<u64>::required_size_for_capacity(4)];
    // current_index=3, length=2, capacity=4.
    for buf in [&mut old_buf, &mut new_buf] {
        buf[0..8].copy_from_slice(&3u64.to_le_bytes());
        buf[8..16].copy_from_slice(&2u64.to_le_bytes());
        buf[16..24].copy_from_slice(&4u64.to_le_bytes());
    }
    let old = OldCyclic::<u64>::from_bytes(&mut old_buf);
    let new = CyclicSliceMut::<u64>::from_bytes(&mut new_buf);
    assert!(matches!(old, Err(OldErr::CurrentIndexGreaterThanLength)));
    assert!(matches!(new, Err(NewErr::CurrentIndexGreaterThanLength)));
}

#[test]
fn error_codes_match_between_crates() {
    // BatchedMerkleTreeError::From<ZeroCopyError> ultimately surfaces the
    // numeric code via `u32::from(e)`. The new and old crates must agree on
    // these codes for every variant the new crate still defines.
    use NewErr as N;
    use OldErr as O;

    let pairs: [(u32, OldErr, NewErr); 10] = [
        (15001, O::Full, N::Full),
        (
            15004,
            O::InsufficientMemoryAllocated(1, 2),
            N::InsufficientMemoryAllocated(1, 2),
        ),
        (15006, O::UnalignedPointer, N::UnalignedPointer),
        (15007, O::MemoryNotZeroed, N::MemoryNotZeroed),
        (15008, O::InvalidConversion, N::InvalidConversion),
        (15010, O::Size, N::Size),
        (15012, O::InvalidCapacity, N::InvalidCapacity),
        (
            15013,
            O::LengthGreaterThanCapacity,
            N::LengthGreaterThanCapacity,
        ),
        (
            15014,
            O::CurrentIndexGreaterThanLength,
            N::CurrentIndexGreaterThanLength,
        ),
        (15016, O::InsufficientCapacity, N::InsufficientCapacity),
    ];
    for (code, old, new) in pairs {
        assert_eq!(u32::from(old), code, "old crate code mismatch");
        assert_eq!(u32::from(new), code, "new crate code mismatch");
    }
}
