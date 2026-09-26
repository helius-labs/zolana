use zk_program_sdk::hasher::{state_discriminator, Hasher, Poseidon, Sha256, ToByteArray};
use zolana_hasher::primitives::right_align;

#[test]
fn integers_right_align_their_big_endian_bytes() {
    assert_eq!(
        0x0102u16.to_byte_array().expect("u16"),
        right_align(&[1u8, 2])
    );
    assert_eq!(
        7u32.to_byte_array().expect("u32"),
        right_align(&7u32.to_be_bytes())
    );
    assert_eq!(
        u64::MAX.to_byte_array().expect("u64"),
        right_align(&u64::MAX.to_be_bytes())
    );
}

#[test]
fn bools_are_zero_or_one() {
    assert_eq!(false.to_byte_array().expect("false"), [0u8; 32]);
    assert_eq!(true.to_byte_array().expect("true"), right_align(&[1u8]));
}

#[test]
fn a_32_byte_value_is_unchanged() {
    let value = [7u8; 32];
    assert_eq!(value.to_byte_array().expect("bytes"), value);
}

#[test]
fn an_array_hashes_its_elements() {
    let expected = Poseidon::hashv(&[
        &right_align(&1u64.to_be_bytes()),
        &right_align(&2u64.to_be_bytes()),
        &right_align(&3u64.to_be_bytes()),
    ])
    .expect("poseidon");
    assert_eq!([1u64, 2, 3].to_byte_array().expect("array"), expected);
}

#[test]
fn nested_arrays_hash_each_inner_array_first() {
    let inner = [4u16, 5].to_byte_array().expect("inner");
    let expected = Poseidon::hashv(&[&inner, &inner]).expect("poseidon");
    assert_eq!(
        [[4u16, 5], [4, 5]].to_byte_array().expect("outer"),
        expected
    );
}

#[test]
fn state_discriminator_is_the_sha256_prefix_of_the_state_name() {
    let digest = Sha256::hash(b"state:Counter").expect("sha256");
    assert_eq!(
        Some(
            state_discriminator("Counter")
                .expect("discriminator")
                .as_slice()
        ),
        digest.get(..8)
    );
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn byte_encodings_and_array_hashes_are_pinned() {
    assert_eq!(
        hex(&0x0102u16.to_byte_array().expect("u16")),
        "0000000000000000000000000000000000000000000000000000000000000102"
    );
    assert_eq!(
        hex(&[1u64, 2, 3].to_byte_array().expect("array")),
        "0e7732d89e6939c0ff03d5e58dab6302f3230e269dc5b968f725df34ab36d732"
    );
    assert_eq!(
        hex(&[[4u16, 5], [4, 5]].to_byte_array().expect("nested array")),
        "2ee841fb1aac75da271e3f7d47984423b3dac7ff6a48b916b406365201acc87f"
    );
}

#[test]
fn state_discriminators_are_pinned() {
    assert_eq!(
        hex(&state_discriminator("Counter").expect("discriminator")),
        "46269aa2dc998420"
    );
    assert_eq!(
        hex(&state_discriminator("Limits").expect("discriminator")),
        "b15b5ef11321b302"
    );
}
