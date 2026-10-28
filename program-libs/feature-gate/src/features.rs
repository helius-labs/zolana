use crate::CircuitFeature;

/// Default-ring transfers authorized by an Ed25519 signature in the proof.
pub const CONFIDENTIAL_EDDSA: &str = "confidential-eddsa";

pub const fn confidential_eddsa(proving_key_sha256s: &'static [[u8; 32]]) -> CircuitFeature {
    CircuitFeature {
        name: CONFIDENTIAL_EDDSA,
        enabled: cfg!(feature = "confidential-eddsa"),
        proving_key_sha256s,
    }
}
