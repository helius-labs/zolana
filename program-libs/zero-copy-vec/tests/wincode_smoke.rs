//! Smoke test: confirm `BoundedSliceMut` and `CyclicSliceMut` compose into
//! wincode-derived structs via `#[derive(SchemaRead)]`.

use light_zero_copy_vec::{bounded_slice::BoundedSliceMut, cyclic_slice::CyclicSliceMut};
use wincode::SchemaRead;

#[derive(SchemaRead)]
pub struct SmokeBounded<'a> {
    pub values: BoundedSliceMut<'a, u8>,
}

#[derive(SchemaRead)]
pub struct SmokeCyclic<'a> {
    pub history: CyclicSliceMut<'a, u8>,
}

#[derive(SchemaRead)]
pub struct SmokeMixed<'a> {
    pub a: BoundedSliceMut<'a, u8>,
    pub b: CyclicSliceMut<'a, u8>,
}

#[test]
fn smoke_bounded_derive_deserialize_mut() {
    let capacity: u64 = 4;
    let mut buf = vec![0u8; BoundedSliceMut::<u8>::required_size_for_capacity(capacity)];
    // Pre-populate header manually so the slice payload can be read.
    buf[0..8].copy_from_slice(&3u64.to_le_bytes()); // length = 3
    buf[8..16].copy_from_slice(&capacity.to_le_bytes()); // capacity = 4
    buf[16..20].copy_from_slice(&[1, 2, 3, 0]); // 3 elements + padding

    let s: SmokeBounded = wincode::deserialize_mut(&mut buf).expect("deserialize SmokeBounded");
    assert_eq!(s.values.len(), 3);
    assert_eq!(s.values.capacity(), 4);
    assert_eq!(s.values.as_slice(), &[1, 2, 3]);
}

#[test]
fn smoke_cyclic_derive_deserialize_mut() {
    let capacity: u64 = 3;
    let mut buf = vec![0u8; CyclicSliceMut::<u8>::required_size_for_capacity(capacity)];
    buf[0..8].copy_from_slice(&0u64.to_le_bytes()); // current_index = 0
    buf[8..16].copy_from_slice(&2u64.to_le_bytes()); // length = 2
    buf[16..24].copy_from_slice(&capacity.to_le_bytes()); // capacity = 3
    buf[24..27].copy_from_slice(&[7, 8, 0]);

    let s: SmokeCyclic = wincode::deserialize_mut(&mut buf).expect("deserialize SmokeCyclic");
    assert_eq!(s.history.len(), 2);
    assert_eq!(s.history.capacity(), 3);
    assert_eq!(*s.history.get(0).unwrap(), 7);
    assert_eq!(*s.history.get(1).unwrap(), 8);
}

#[test]
fn smoke_mixed_derive_deserialize_mut() {
    // Use cap=8 for the bounded section so the cyclic header starts at offset
    // 24 (u64-aligned).
    let bounded_sz = BoundedSliceMut::<u8>::required_size_for_capacity(8);
    let cyclic_sz = CyclicSliceMut::<u8>::required_size_for_capacity(2);
    let mut buf = vec![0u8; bounded_sz + cyclic_sz];

    // a: length=1, capacity=8
    buf[0..8].copy_from_slice(&1u64.to_le_bytes());
    buf[8..16].copy_from_slice(&8u64.to_le_bytes());
    buf[16] = 10;
    // b: current_index=0, length=1, capacity=2
    let off = bounded_sz;
    buf[off..off + 8].copy_from_slice(&0u64.to_le_bytes());
    buf[off + 8..off + 16].copy_from_slice(&1u64.to_le_bytes());
    buf[off + 16..off + 24].copy_from_slice(&2u64.to_le_bytes());
    buf[off + 24] = 20;

    let s: SmokeMixed = wincode::deserialize_mut(&mut buf).expect("deserialize SmokeMixed");
    assert_eq!(s.a.as_slice(), &[10]);
    assert_eq!(s.b.as_slice(), &[20]);
}
