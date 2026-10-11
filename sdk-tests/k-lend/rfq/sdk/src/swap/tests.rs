use super::*;
use zolana_keypair::ShieldedKeypair;

#[test]
fn fees_and_zero_inputs_fail_before_pricing() -> Result<()> {
    let rate = VaultState {
        token_available: 1_000_000,
        shares_issued: 1_000_000,
        pending_fees_sf: 0,
    };
    for fee_bps in [10_000, 10_001, u64::MAX] {
        assert_eq!(
            Quote::price(&rate, Direction::Deposit, 100, fee_bps)
                .err()
                .and_then(|error| error.downcast::<SwapError>().ok()),
            Some(SwapError::InvalidFee { fee_bps })
        );
    }
    assert_eq!(
        Quote::price(&rate, Direction::Deposit, 0, 30)
            .err()
            .and_then(|error| error.downcast::<SwapError>().ok()),
        Some(SwapError::AmountZero)
    );
    assert_eq!(
        crate::user::select_inputs(Vec::new(), Address::default(), 0, 4),
        Err(SwapError::AmountZero)
    );
    assert_eq!(validate_fee(0), Ok(()));
    assert_eq!(validate_fee(9999), Ok(()));
    Ok(())
}

#[test]
fn accepted_offer_verifies_against_its_quoted_fee() -> Result<()> {
    let rate = VaultState {
        token_available: 1_000_000,
        shares_issued: 1_000_000,
        pending_fees_sf: 0,
    };
    let maker = ShieldedKeypair::new_ed25519()?.shielded_address()?;
    let mut offer = Offer {
        pair: Pair::new(
            Address::new_from_array([1; 32]),
            Address::new_from_array([2; 32]),
        ),
        quote: Quote::price(&rate, Direction::Deposit, 100_000, 80)?,
        fee_bps: 80,
        maker,
        fee_payer: Address::default(),
        max_user_inputs: 4,
        user_outputs: 2,
    };
    offer.verify_price(&rate)?;
    offer.fee_bps = 30;
    assert!(offer.verify_price(&rate).is_err());
    Ok(())
}
