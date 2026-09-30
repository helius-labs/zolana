use proptest::prelude::*;

use super::{
    fixtures::{broken, spend, AS_GIVEN, BALANCE_FITS},
    vectors::{sol, usdc},
};
use crate::{harness::fixture::native, protocol::transaction::wallets::dummy};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn natively_a_spend_holds_the_real_total_exactly_when_it_fits_64_bits(
        first in any::<u64>(),
        second in any::<u64>(),
    ) {
        let expected = if first.checked_add(second).is_some() {
            Ok(())
        } else {
            Err(broken(BALANCE_FITS))
        };
        prop_assert_eq!(
            (
                native(&spend::<2, AS_GIVEN>([usdc(first, 0), usdc(second, 1)])),
                native(&spend::<3, AS_GIVEN>([sol(first, 0), dummy(), dummy()])),
            ),
            (expected, Ok(()))
        );
    }
}
