//! Fixtures the vector tests share.

/// The `b` point of groth16-solana's own proof fixture, big-endian and uncompressed.
pub fn spp_b() -> [u8; 128] {
    let mut point = [0u8; 128];
    hex::decode_to_slice(
        "2839e9cdb42e236fd705175d0c4776e1072ef7932f826abdb85092678d34f21900cb7cb06e2297d442b4ee97ecbd85d11189cdb7a8c45c9f4bae51a81256b038101ad21412517a8e683efba9628d15fd3282b60f216de41f4fb75893ae6c04160e81a80650f6fe64da835e31f7d303f516c8b15b3c9093ae5a1113bd3e939812",
        &mut point,
    )
    .unwrap();
    point
}
