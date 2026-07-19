/// Packs a 33-byte value (e.g. a SEC1-compressed P256 key) into two BN254
/// field elements, mirroring the circuit `Pack33To2FECircuit`:
/// `lo[1..32] = b[0..31]` (< 2^248) and `hi[30..32] = b[31..33]` (16 bits),
/// so the packing is lossless and both limbs are below the field modulus.
pub fn pack33(b: &[u8; 33]) -> ([u8; 32], [u8; 32]) {
    let mut lo = [0u8; 32];
    lo[1..32].copy_from_slice(&b[0..31]);
    let mut hi = [0u8; 32];
    hi[30] = b[31];
    hi[31] = b[32];
    (lo, hi)
}
