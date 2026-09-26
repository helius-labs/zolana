use sha2::{Digest, Sha256};

pub(crate) fn state_discriminator(type_name: &str) -> [u8; 8] {
    let digest = Sha256::digest(format!("state:{type_name}"));
    let mut discriminator = [0u8; 8];
    for (target, source) in discriminator.iter_mut().zip(digest.iter()) {
        *target = *source;
    }
    discriminator
}
