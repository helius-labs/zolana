use spr_circuit::protocol::{TokenUtxos, Utxo, UtxoTrait};
use spr_circuit::{Field, checked};
use spr_interface::ADDRESS_DOMAIN;

use crate::support::{SOL, USDC, assert_requirement, owner, utxo};

const TOKEN: &str = "protocol/utxo/token.rs";
const NEW_MUT: &str = "pub fn new_mut(inputs";

#[test]
fn real_inputs_share_the_first_real_inputs_owner_and_asset() {
    for (inputs, call) in [
        (
            [utxo(owner(1), SOL, 5), utxo(owner(2), SOL, 5)],
            "require_eq(input.owner, owner)",
        ),
        (
            [utxo(owner(1), SOL, 5), utxo(owner(1), USDC, 5)],
            "require_eq(input.asset, asset)",
        ),
    ] {
        assert_requirement(
            checked(|| TokenUtxos::new_mut(&inputs)),
            TOKEN,
            NEW_MUT,
            call,
        );
    }
    let tokens = TokenUtxos::new_mut(&[Utxo::dummy(), utxo(owner(1), USDC, 5)]).unwrap();
    assert_eq!(
        (tokens.owner(), tokens.asset(), tokens.amount()),
        (owner(1), USDC, Ok(5))
    );
}

#[test]
fn a_leading_dummy_takes_the_owner_and_asset_of_the_first_real_input() {
    let inputs = [
        Utxo::dummy(),
        utxo(owner(1), USDC, 5),
        utxo(owner(2), USDC, 5),
    ];
    assert_requirement(
        checked(|| TokenUtxos::new_mut(&inputs)),
        TOKEN,
        NEW_MUT,
        "require_eq(input.owner, owner)",
    );
}

#[test]
fn token_inputs_carry_no_data_and_the_utxo_domain() {
    let with_data = Utxo {
        data_hash: Field::one(),
        ..utxo(owner(1), SOL, 5)
    };
    let address = Utxo {
        domain: ADDRESS_DOMAIN,
        ..utxo(owner(1), SOL, 5)
    };
    assert_requirement(
        checked(|| TokenUtxos::new_mut(&[with_data])),
        TOKEN,
        NEW_MUT,
        "require_eq(input.data_hash, Field::zero())",
    );
    assert_requirement(
        checked(|| TokenUtxos::new_mut(&[address])),
        TOKEN,
        NEW_MUT,
        "require_eq(input.domain, UTXO_DOMAIN)",
    );
}

#[test]
fn a_dummy_input_amount_does_not_count() {
    let dummy = Utxo {
        amount: 99,
        ..Utxo::dummy()
    };
    let tokens = TokenUtxos::new_mut(&[utxo(owner(1), SOL, 5), dummy]).unwrap();
    assert_eq!(tokens.amount(), Ok(5));
}

#[test]
fn only_dummy_inputs_require_the_optional_builder() {
    assert_requirement(
        checked(|| TokenUtxos::new_mut(&[Utxo::dummy()])?.change()),
        TOKEN,
        "pub fn change(self)",
        "require(real)",
    );
    let change = TokenUtxos::new_mut(&[Utxo::dummy()])
        .unwrap()
        .with_optional(&owner(3), &USDC)
        .change()
        .unwrap()
        .unwrap();
    assert_eq!(
        (change.owner, change.asset, change.amount),
        (owner(3), USDC, 0)
    );
}

#[test]
fn optional_inputs_match_a_real_input_and_are_configured_before_balance_operations() {
    let inputs = [utxo(owner(1), SOL, 5)];
    let anchor = "pub fn with_optional";
    assert_requirement(
        checked(|| Ok(TokenUtxos::new_mut(&inputs)?.with_optional(&owner(2), &SOL))),
        TOKEN,
        anchor,
        "require_eq(self.owner(), *owner)",
    );
    assert_requirement(
        checked(|| Ok(TokenUtxos::new_mut(&inputs)?.with_optional(&owner(1), &USDC))),
        TOKEN,
        anchor,
        "require_eq(self.asset(), *asset)",
    );
    assert_requirement(
        checked(|| {
            let mut tokens = TokenUtxos::new_mut(&inputs)?;
            tokens.withdraw(&1, &[9; 32])?;
            Ok(tokens.with_optional(&owner(1), &SOL))
        }),
        TOKEN,
        anchor,
        "require(self.balance.is_untouched())",
    );
}

#[test]
fn a_closed_token_group_must_be_empty_and_has_no_output() {
    assert_requirement(
        checked(|| {
            TokenUtxos::new_mut(&[utxo(owner(1), SOL, 5)])?
                .close()
                .change()
        }),
        TOKEN,
        "pub fn change(self)",
        "require_eq(self.balance.amount, 0u128)",
    );
    let mut closed = TokenUtxos::new_mut(&[utxo(owner(1), SOL, 5)])
        .unwrap()
        .close();
    closed.withdraw_all(&[9; 32]).unwrap();
    assert!(closed.change().unwrap().is_none());
}
