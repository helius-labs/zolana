use zolana_interface::{state::discriminator::NULLIFIER_PDA, NullifierPda, NULLIFIER_PDA_SIZE};

const RECORD: NullifierPda = NullifierPda {
    queue_index: 0x0102_0304_0506_0708,
    tree_id: 0xabcd,
};
const RECORD_BYTES: [u8; NULLIFIER_PDA_SIZE] = [
    NULLIFIER_PDA,
    0x08,
    0x07,
    0x06,
    0x05,
    0x04,
    0x03,
    0x02,
    0x01,
    0xcd,
    0xab,
];

#[test]
fn write_to_writes_the_discriminated_account_layout() {
    let mut written = [0u8; NULLIFIER_PDA_SIZE];
    RECORD.write_to(&mut written).expect("exact-size buffer");
    assert_eq!(written, RECORD_BYTES);
    assert_eq!(RECORD.to_account_data(), RECORD_BYTES);
}

#[test]
fn read_from_reads_back_the_written_account_layout() {
    assert_eq!(NullifierPda::read_from(&RECORD_BYTES), Some(RECORD));
}

/// A program-owned account of the right length is a nullifier
/// PDA only if it starts with the nullifier PDA discriminator.
#[test]
fn read_from_rejects_a_record_without_the_discriminator() {
    for discriminator in [0u8, 1, 7, NULLIFIER_PDA + 1] {
        let mut bytes = RECORD_BYTES;
        *bytes.first_mut().unwrap() = discriminator;
        assert_eq!(NullifierPda::read_from(&bytes), None, "{discriminator}");
    }
}

#[test]
fn write_to_rejects_a_buffer_of_the_wrong_size() {
    assert_eq!(RECORD.write_to(&mut [0u8; NULLIFIER_PDA_SIZE - 1]), None);
    assert_eq!(RECORD.write_to(&mut [0u8; NULLIFIER_PDA_SIZE + 1]), None);
}

#[test]
fn read_from_rejects_a_buffer_of_the_wrong_size() {
    assert_eq!(
        NullifierPda::read_from(RECORD_BYTES.get(..NULLIFIER_PDA_SIZE - 1).unwrap()),
        None
    );
    let mut long = RECORD_BYTES.to_vec();
    long.push(0);
    assert_eq!(NullifierPda::read_from(&long), None);
}
