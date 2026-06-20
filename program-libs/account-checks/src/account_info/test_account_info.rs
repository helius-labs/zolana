#![cfg(feature = "test-only")]

extern crate std;
use std::vec::Vec;

use rand::{prelude::Rng, thread_rng};
use solana_account_view::{AccountView, RuntimeAccount};

pub fn get_account_view(
    address: [u8; 32],
    owner: [u8; 32],
    is_signer: bool,
    is_writable: bool,
    is_executable: bool,
    data: Vec<u8>,
) -> AccountView {
    // The RuntimeAccount struct has fields for flags, pubkeys, lamports, etc
    let account_size = core::mem::size_of::<RuntimeAccount>();

    // Allocate memory for RuntimeAccount + data
    let mut raw_data = vec![0u8; account_size + data.len()];

    // Set the boolean flags - use 1 for true as the AccountView implementation checks for non-zero
    // IMPORTANT: borrow_state needs to be 0xFF (all bits set) to indicate unborrowed state
    raw_data[0] = 0xFF; // borrow_state - all bits set means unborrowed
    raw_data[1] = if is_signer { 1 } else { 0 }; // is_signer
    raw_data[2] = if is_writable { 1 } else { 0 }; // is_writable
    raw_data[3] = if is_executable { 1 } else { 0 }; // executable

    // padding at offset 4
    raw_data[4..8].copy_from_slice(&0i32.to_le_bytes());

    // address at offset 8
    raw_data[8..40].copy_from_slice(&address);

    // owner at offset 40
    raw_data[40..72].copy_from_slice(&owner);

    // lamports at offset 72
    raw_data[72..80].copy_from_slice(&1000u64.to_le_bytes());

    // data_len at offset 80
    raw_data[80..88].copy_from_slice(&(data.len() as u64).to_le_bytes());

    // copy the actual data after the RuntimeAccount struct
    if !data.is_empty() {
        raw_data[account_size..account_size + data.len()].copy_from_slice(&data);
    }

    // Create the AccountView by pointing to our raw RuntimeAccount data
    let account_ptr = raw_data.as_mut_ptr() as *mut RuntimeAccount;

    // Need to leak the memory so it doesn't get dropped while the AccountView is still using it
    core::mem::forget(raw_data);

    unsafe { AccountView::new_unchecked(account_ptr) }
}

#[test]
fn test_get_account_view() {
    let mut rng = thread_rng();
    for _ in 0..1000 {
        let address = rng.gen::<[u8; 32]>();
        let owner = rng.gen::<[u8; 32]>();
        let is_signer = rng.gen();
        let is_writable = rng.gen();
        let is_executable = rng.gen();
        let data_len: u64 = rng.gen_range(0..3000);
        let data = (0..data_len).map(|_| rng.gen::<u8>()).collect::<Vec<u8>>();

        let account_view = get_account_view(
            address,
            owner,
            is_signer,
            is_writable,
            is_executable,
            data.clone(),
        );

        // Test the account matches the values we set
        assert_eq!(account_view.is_signer(), is_signer);
        assert_eq!(account_view.is_writable(), is_writable);
        assert_eq!(account_view.executable(), is_executable);
        assert_eq!(account_view.data_len(), data.len());

        // Test we can access the account data - this was the failing part originally
        unsafe {
            let account_data = account_view.borrow_unchecked();
            assert_eq!(account_data.len(), data.len());
            for (i, val) in data.iter().enumerate() {
                assert_eq!(account_data[i], *val);
            }
        }
    }
}
