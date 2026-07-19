use crate::errors::HasherError;

/// Packs a domain-separation `info` string of up to 62 bytes into two field
/// elements, mirroring the circuit `packInfoTo2FECircuit`: `lo[0] = len`,
/// `lo` holds `info[..min(len, 31)]` right-aligned, `hi` the remainder.
pub fn pack_info(info: &[u8]) -> Result<([u8; 32], [u8; 32]), HasherError> {
    let len = info.len();
    if len > 62 {
        return Err(HasherError::InvalidInputLength(62, len));
    }
    let split = len.min(31);
    let mut lo = [0u8; 32];
    lo[0] = len as u8;
    if let (Some(dst), Some(src)) = (lo.get_mut(32 - split..), info.get(..split)) {
        dst.copy_from_slice(src);
    }
    let mut hi = [0u8; 32];
    let rem = len - split;
    if let (Some(dst), Some(src)) = (hi.get_mut(32 - rem..), info.get(split..len)) {
        dst.copy_from_slice(src);
    }
    Ok((lo, hi))
}
