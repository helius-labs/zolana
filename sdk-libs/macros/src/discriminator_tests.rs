#[cfg(test)]
mod tests {
    use anchor_syn::codegen::program::common::sighash;

    use zolana_hasher::state_discriminator;

    #[test]
    fn matches_anchor_account_discriminators() {
        for name in ["NewAccount", "Escrow", "EscrowTerms", "Limits", "HTTPState"] {
            assert_eq!(
                state_discriminator(name).expect("discriminator"),
                sighash("account", name),
                "{name}"
            );
        }
    }

    #[test]
    fn matches_anchors_documented_account_vector() {
        // https://www.anchor-lang.com/docs/basics/idl#discriminators
        assert_eq!(
            state_discriminator("NewAccount").expect("discriminator"),
            [176, 95, 4, 118, 91, 177, 125, 232]
        );
    }
}
