/// Encodes a bool as a big-endian field element (`0` or `1`).
pub fn bool_fe(b: bool) -> [u8; 32] {
    let mut fe = [0u8; 32];
    if b {
        fe[31] = 1;
    }
    fe
}
