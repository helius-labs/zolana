/// Packs a 32-byte value into two field elements, mirroring the circuit
/// `Pack32To2FECircuit`: `lo[1..32] = b[0..31]` (< 2^248) and `hi[31] = b[31]`,
/// so the packing is lossless and both limbs are below the field modulus.
pub fn pack32(b: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut lo = [0u8; 32];
    lo[1..32].copy_from_slice(&b[0..31]);
    let mut hi = [0u8; 32];
    hi[31] = b[31];
    (lo, hi)
}
