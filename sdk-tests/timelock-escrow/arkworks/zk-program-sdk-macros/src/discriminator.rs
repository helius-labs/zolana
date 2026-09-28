use sha2::{Digest, Sha256};

pub(crate) fn state_discriminator(type_name: &str) -> [u8; 8] {
    let digest = Sha256::digest(format!("account:{type_name}"));
    let mut discriminator = [0u8; 8];
    for (target, source) in discriminator.iter_mut().zip(digest.iter()) {
        *target = *source;
    }
    discriminator
}

#[cfg(test)]
mod tests {
    use anchor_syn::codegen::program::common::sighash;

    use super::state_discriminator;

    #[test]
    fn matches_anchor_account_discriminators() {
        for name in ["NewAccount", "Escrow", "EscrowTerms", "Limits", "HTTPState"] {
            assert_eq!(
                state_discriminator(name),
                sighash("account", name),
                "{name}"
            );
        }
    }

    #[test]
    fn matches_anchors_documented_account_vector() {
        // https://www.anchor-lang.com/docs/basics/idl#discriminators
        assert_eq!(
            state_discriminator("NewAccount"),
            [176, 95, 4, 118, 91, 177, 125, 232]
        );
    }
}
