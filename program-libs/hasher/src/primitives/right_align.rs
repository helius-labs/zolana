use crate::errors::HasherError;

/// Right-aligns `N` bytes into a 32-byte big-endian field element.
pub fn right_align<const N: usize>(bytes: &[u8; N]) -> [u8; 32] {
    const { assert!(N <= 32) };
    let mut out = [0u8; 32];
    out[32 - N..].copy_from_slice(bytes);
    out
}

/// Right-aligns up to 32 bytes into a 32-byte big-endian field element.
pub fn right_align_slice(bytes: &[u8]) -> Result<[u8; 32], HasherError> {
    let len = bytes.len();
    if len > 32 {
        return Err(HasherError::InvalidInputLength(32, len));
    }
    let mut out = [0u8; 32];
    if let Some(dst) = out.get_mut(32 - len..) {
        dst.copy_from_slice(bytes);
    }
    Ok(out)
}
