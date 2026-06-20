use light_zero_copy_vec::{cyclic_slice::CyclicSliceMut, errors::ZeroCopyError};

// Wire format pins:
//   `[current_index: u64 LE][length: u64 LE][capacity: u64 LE][padding][T; capacity]`
//
// Header is 24 bytes for all element types with align <= 8.

#[test]
fn metadata_size_u8() {
    assert_eq!(CyclicSliceMut::<u8>::metadata_size(), 24);
}

#[test]
fn metadata_size_u32() {
    assert_eq!(CyclicSliceMut::<u32>::metadata_size(), 24);
}

#[test]
fn metadata_size_u64() {
    assert_eq!(CyclicSliceMut::<u64>::metadata_size(), 24);
}

#[test]
fn metadata_size_u8_array_32() {
    assert_eq!(CyclicSliceMut::<[u8; 32]>::metadata_size(), 24);
}

#[test]
fn required_size_for_capacity_u8() {
    assert_eq!(
        CyclicSliceMut::<u8>::required_size_for_capacity(64),
        24 + 64
    );
}

#[test]
fn required_size_for_capacity_u64() {
    assert_eq!(
        CyclicSliceMut::<u64>::required_size_for_capacity(64),
        24 + 64 * 8
    );
}

#[test]
fn required_size_for_capacity_array_32() {
    assert_eq!(
        CyclicSliceMut::<[u8; 32]>::required_size_for_capacity(64),
        24 + 64 * 32
    );
    assert_eq!(
        CyclicSliceMut::<[u8; 32]>::required_size_for_capacity(512),
        24 + 512 * 32
    );
}

#[test]
fn zero_capacity_rejected() {
    let mut buf = vec![0u8; CyclicSliceMut::<u64>::metadata_size()];
    let r = CyclicSliceMut::<u64>::new(0, &mut buf);
    assert!(matches!(r, Err(ZeroCopyError::InvalidCapacity)));
}

#[test]
fn push_under_capacity_advances_length_and_current_index() {
    let capacity = 4u64;
    let mut buf = vec![0u8; CyclicSliceMut::<u64>::required_size_for_capacity(capacity)];
    let mut v = CyclicSliceMut::<u64>::new(capacity, &mut buf).unwrap();
    assert_eq!(v.len(), 0);
    assert_eq!(v.capacity(), capacity as usize);

    v.push(10);
    v.push(20);
    v.push(30);
    assert_eq!(v.len(), 3);
    assert_eq!(v.first_index(), 0);
    assert_eq!(v.last_index(), 2);
    assert_eq!(*v.first().unwrap(), 10);
    assert_eq!(*v.last().unwrap(), 30);
    let collected: Vec<_> = v.iter().copied().collect();
    assert_eq!(collected, vec![10, 20, 30]);
}

#[test]
fn push_wraps_at_capacity() {
    let capacity = 3u64;
    let mut buf = vec![0u8; CyclicSliceMut::<u64>::required_size_for_capacity(capacity)];
    let mut v = CyclicSliceMut::<u64>::new(capacity, &mut buf).unwrap();
    v.push(1);
    v.push(2);
    v.push(3);
    // Fully populated. current_index now wrapped back to 0.
    v.push(4); // overwrites index 0
    v.push(5); // overwrites index 1
    assert_eq!(v.len(), 3);
    assert_eq!(v.capacity(), 3);
    // first_index is the next slot to be overwritten (= current_index).
    assert_eq!(v.first_index(), 2);
    assert_eq!(v.last_index(), 1);
    assert_eq!(*v.first().unwrap(), 3);
    assert_eq!(*v.last().unwrap(), 5);
    let collected: Vec<_> = v.iter().copied().collect();
    assert_eq!(collected, vec![3, 4, 5]);
}

#[test]
fn from_bytes_round_trip() {
    let capacity = 4u64;
    let mut buf = vec![0u8; CyclicSliceMut::<[u8; 32]>::required_size_for_capacity(capacity)];
    {
        let mut v = CyclicSliceMut::<[u8; 32]>::new(capacity, &mut buf).unwrap();
        v.push([1u8; 32]);
        v.push([2u8; 32]);
    }
    let v = CyclicSliceMut::<[u8; 32]>::from_bytes(&mut buf).unwrap();
    assert_eq!(v.len(), 2);
    assert_eq!(v.capacity(), capacity as usize);
    assert_eq!(*v.get(0).unwrap(), [1u8; 32]);
    assert_eq!(*v.get(1).unwrap(), [2u8; 32]);
}

#[test]
fn from_bytes_length_gt_capacity_rejected() {
    let mut buf = vec![0u8; CyclicSliceMut::<u64>::required_size_for_capacity(4)];
    buf[0..8].copy_from_slice(&0u64.to_le_bytes());
    buf[8..16].copy_from_slice(&5u64.to_le_bytes());
    buf[16..24].copy_from_slice(&4u64.to_le_bytes());
    let r = CyclicSliceMut::<u64>::from_bytes(&mut buf);
    assert!(matches!(r, Err(ZeroCopyError::LengthGreaterThanCapacity)));
}

#[test]
fn from_bytes_current_gt_length_rejected() {
    let mut buf = vec![0u8; CyclicSliceMut::<u64>::required_size_for_capacity(4)];
    buf[0..8].copy_from_slice(&3u64.to_le_bytes());
    buf[8..16].copy_from_slice(&2u64.to_le_bytes());
    buf[16..24].copy_from_slice(&4u64.to_le_bytes());
    let r = CyclicSliceMut::<u64>::from_bytes(&mut buf);
    assert!(matches!(
        r,
        Err(ZeroCopyError::CurrentIndexGreaterThanLength)
    ));
}

#[test]
fn new_memory_not_zeroed() {
    let mut buf = vec![1u8; CyclicSliceMut::<u64>::required_size_for_capacity(4)];
    let r = CyclicSliceMut::<u64>::new(4, &mut buf);
    assert!(matches!(r, Err(ZeroCopyError::MemoryNotZeroed)));
}
