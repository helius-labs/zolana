#![cfg(feature = "borsh")]

use zolana_interface::{NullifierPda, NULLIFIER_PDA_SIZE};

#[test]
fn write_to_matches_the_borsh_account_layout() {
    let record = NullifierPda {
        queue_index: 0x0102_0304_0506_0708,
        tree_id: 0xabcd,
    };
    let mut written = [0u8; NULLIFIER_PDA_SIZE];
    record.write_to(&mut written).expect("exact-size buffer");
    assert_eq!(written.to_vec(), borsh::to_vec(&record).unwrap());
    assert_eq!(
        written,
        [0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0xcd, 0xab]
    );
}

#[test]
fn read_from_reads_back_the_written_account_layout() {
    let record = NullifierPda {
        queue_index: 0x0102_0304_0506_0708,
        tree_id: 0xabcd,
    };
    let mut written = [0u8; NULLIFIER_PDA_SIZE];
    record.write_to(&mut written).expect("exact-size buffer");
    assert_eq!(NullifierPda::read_from(&written), Some(record));
    assert_eq!(
        NullifierPda::read_from(&[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0xcd, 0xab]),
        Some(record)
    );
}

#[test]
fn write_to_rejects_a_buffer_of_the_wrong_size() {
    let record = NullifierPda {
        queue_index: 1,
        tree_id: 1,
    };
    assert_eq!(record.write_to(&mut [0u8; NULLIFIER_PDA_SIZE - 1]), None);
    assert_eq!(record.write_to(&mut [0u8; NULLIFIER_PDA_SIZE + 1]), None);
}

#[test]
fn read_from_rejects_a_buffer_of_the_wrong_size() {
    assert_eq!(
        NullifierPda::read_from(&[0u8; NULLIFIER_PDA_SIZE - 1]),
        None
    );
    assert_eq!(
        NullifierPda::read_from(&[0u8; NULLIFIER_PDA_SIZE + 1]),
        None
    );
}
