use proptest::prelude::*;
use zolana_program::TxContext;
use zolana_transaction::Mint;

use super::{
    fixtures::{Asserted, NoFields, Refresh},
    vectors::payment,
    wallets::{Spent, SENDER},
};
use crate::harness::fixture::native;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    #[test]
    fn every_random_payment_reproduces_the_native_hashes(
        first in 0..u64::MAX / 2,
        second in 0..u64::MAX / 2,
        share in any::<u64>(),
    ) {
        let amount = share % (first + second + 1);
        prop_assert_eq!(
            native(&Asserted::honest(payment(Mint::SOL, [first, second], amount))),
            Ok(())
        );
    }

    #[test]
    fn every_random_seed_and_output_tree_reproduces_the_native_hashes(
        seed in any::<[u8; 32]>(),
        tree in any::<u16>(),
        latest in proptest::option::of(any::<u16>()),
        sets_tree in any::<bool>(),
    ) {
        let mut seed = seed;
        seed[0] = 0;
        let output_tree_id = (sets_tree || latest.is_none()).then_some(tree);
        let program = Refresh {
            tx_context: TxContext::new()
                .with_blinding_seed(seed)
                .with_output_tree_id(output_tree_id),
            tokens: [Spent::token(SENDER, Mint::SOL, 5, 0)
                .with_latest_tree_id(latest)
                .wallet_utxo()],
            public: NoFields,
        };
        prop_assert_eq!(native(&Asserted::honest(program)), Ok(()));
    }
}
