/// Right-aligns a fixed-size big-endian byte value in a 32-byte field
/// representation.
pub fn right_align<const N: usize>(bytes: &[u8; N]) -> [u8; 32] {
    const { assert!(N <= 32) };
    let mut output = [0u8; 32];
    output[32 - N..].copy_from_slice(bytes);
    output
}
