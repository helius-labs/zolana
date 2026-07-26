use zolana_hasher::primitives::{pack_be, pack_be_chunks};

#[test]
fn packs_fixed_size_big_endian_chunks() {
    let bytes = core::array::from_fn::<_, 63, _>(|i| i as u8);
    let [first, second, third] = pack_be::<63, 3>(&bytes);
    assert_eq!(&first[1..], &bytes[..31]);
    assert_eq!(&second[1..], &bytes[31..62]);
    assert_eq!(third[31], bytes[62]);
    assert_eq!(pack_be_chunks(0), 0);
    assert_eq!(pack_be_chunks(31), 1);
    assert_eq!(pack_be_chunks(32), 2);
}
