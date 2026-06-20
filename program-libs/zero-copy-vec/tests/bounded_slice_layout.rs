use light_zero_copy_vec::{bounded_slice::BoundedSliceMut, errors::ZeroCopyError};

// Wire format pins:
//   `[length: u64 LE][capacity: u64 LE][padding for align(T)][T; capacity]`
//
// For our element types (align <= 16), padding is always 0, so the header is
// always 16 bytes. These assertions are canaries — if metadata_size or
// required_size_for_capacity changes, deployed accounts break.

#[test]
fn metadata_size_u8() {
    assert_eq!(BoundedSliceMut::<u8>::metadata_size(), 16);
}

#[test]
fn metadata_size_u32() {
    assert_eq!(BoundedSliceMut::<u32>::metadata_size(), 16);
}

#[test]
fn metadata_size_u64() {
    assert_eq!(BoundedSliceMut::<u64>::metadata_size(), 16);
}

#[test]
fn metadata_size_u8_array_32() {
    assert_eq!(BoundedSliceMut::<[u8; 32]>::metadata_size(), 16);
}

#[test]
fn required_size_for_capacity_u8() {
    assert_eq!(
        BoundedSliceMut::<u8>::required_size_for_capacity(64),
        16 + 64
    );
    assert_eq!(BoundedSliceMut::<u8>::required_size_for_capacity(0), 16);
}

#[test]
fn required_size_for_capacity_u32() {
    assert_eq!(
        BoundedSliceMut::<u32>::required_size_for_capacity(64),
        16 + 64 * 4
    );
}

#[test]
fn required_size_for_capacity_u64() {
    assert_eq!(
        BoundedSliceMut::<u64>::required_size_for_capacity(64),
        16 + 64 * 8
    );
}

#[test]
fn required_size_for_capacity_array_32() {
    assert_eq!(
        BoundedSliceMut::<[u8; 32]>::required_size_for_capacity(64),
        16 + 64 * 32
    );
    assert_eq!(
        BoundedSliceMut::<[u8; 32]>::required_size_for_capacity(512),
        16 + 512 * 32
    );
}

#[test]
fn new_initializes_header_and_push_advances_length() {
    let capacity = 5u64;
    let mut buf = vec![0u8; BoundedSliceMut::<u64>::required_size_for_capacity(capacity)];
    let mut v = BoundedSliceMut::<u64>::new(capacity, &mut buf).unwrap();
    assert_eq!(v.len(), 0);
    assert_eq!(v.capacity(), capacity as usize);
    for i in 0..capacity {
        v.push(i).unwrap();
        assert_eq!(v.len() as u64, i + 1);
        assert_eq!(*v.last().unwrap(), i);
    }
    // Header bytes are exactly [length=5 LE][capacity=5 LE].
    let len_bytes: [u8; 8] = buf[0..8].try_into().unwrap();
    let cap_bytes: [u8; 8] = buf[8..16].try_into().unwrap();
    assert_eq!(u64::from_le_bytes(len_bytes), 5);
    assert_eq!(u64::from_le_bytes(cap_bytes), 5);
}

#[test]
fn push_full_errors() {
    let mut buf = vec![0u8; BoundedSliceMut::<u64>::required_size_for_capacity(2)];
    let mut v = BoundedSliceMut::<u64>::new(2, &mut buf).unwrap();
    v.push(10).unwrap();
    v.push(20).unwrap();
    assert_eq!(v.push(30).unwrap_err(), ZeroCopyError::Full);
}

#[test]
fn new_memory_not_zeroed() {
    let mut buf = vec![1u8; BoundedSliceMut::<u64>::required_size_for_capacity(5)];
    let r = BoundedSliceMut::<u64>::new(5, &mut buf);
    assert!(matches!(r, Err(ZeroCopyError::MemoryNotZeroed)));
}

#[test]
fn from_bytes_round_trip() {
    let capacity = 8u64;
    let mut buf = vec![0u8; BoundedSliceMut::<[u8; 32]>::required_size_for_capacity(capacity)];
    {
        let mut v = BoundedSliceMut::<[u8; 32]>::new(capacity, &mut buf).unwrap();
        v.push([7u8; 32]).unwrap();
        v.push([9u8; 32]).unwrap();
    }
    let v = BoundedSliceMut::<[u8; 32]>::from_bytes(&mut buf).unwrap();
    assert_eq!(v.len(), 2);
    assert_eq!(v.capacity(), capacity as usize);
    assert_eq!(*v.get(0).unwrap(), [7u8; 32]);
    assert_eq!(*v.get(1).unwrap(), [9u8; 32]);
}

#[test]
fn from_bytes_length_gt_capacity_rejected() {
    let mut buf = vec![0u8; BoundedSliceMut::<u64>::required_size_for_capacity(4)];
    // Write length=5, capacity=4 manually.
    buf[0..8].copy_from_slice(&5u64.to_le_bytes());
    buf[8..16].copy_from_slice(&4u64.to_le_bytes());
    let r = BoundedSliceMut::<u64>::from_bytes(&mut buf);
    assert!(matches!(r, Err(ZeroCopyError::LengthGreaterThanCapacity)));
}

#[test]
fn clear_resets_length_keeps_capacity() {
    let mut buf = vec![0u8; BoundedSliceMut::<u64>::required_size_for_capacity(4)];
    let mut v = BoundedSliceMut::<u64>::new(4, &mut buf).unwrap();
    v.push(1).unwrap();
    v.push(2).unwrap();
    v.clear();
    assert_eq!(v.len(), 0);
    assert_eq!(v.capacity(), 4);
}
