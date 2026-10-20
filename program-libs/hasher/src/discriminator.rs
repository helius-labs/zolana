use crate::{Hasher, HasherError, Sha256};

pub fn state_discriminator(type_name: &str) -> Result<[u8; 8], HasherError> {
    let digest = Sha256::hashv(&[b"account:", type_name.as_bytes()])?;
    let mut discriminator = [0u8; 8];
    for (target, source) in discriminator.iter_mut().zip(digest.iter()) {
        *target = *source;
    }
    Ok(discriminator)
}
