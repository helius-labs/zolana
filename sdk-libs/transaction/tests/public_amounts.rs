use zolana_transaction::instructions::transact::{signed_to_field, PublicAmounts};

#[test]
fn zero_public_amounts_match_the_field_encoding_of_zero() {
    let default = PublicAmounts::default();
    for amount in default.amounts {
        assert_eq!(amount, signed_to_field(0));
    }
    for asset in default.assets {
        assert_eq!(asset, [0u8; 32]);
    }
}
