use spr_circuit::protocol::{DataUtxo, PublicTransfer, TokenUtxos, UtxoTrait};
use spr_circuit::{CircuitError, Field, checked};

use crate::support::{SOL, USDC, assert_requirement, owner, utxo};

const BALANCE: &str = "protocol/utxo/balance.rs";
const DEBIT: (&str, &str) = ("fn debit(", "crate::require_eq(high, u64::from(borrow))");
const DESTINATION: &str = "fn check_destination(";

type Operation = fn() -> Result<(), CircuitError>;

fn source(amount: u64) -> TokenUtxos {
    TokenUtxos::new_mut(&[utxo(owner(1), SOL, amount)]).unwrap()
}

fn transfers(tokens: &TokenUtxos) -> Vec<(bool, u64, [u8; 32], [u8; 32])> {
    tokens
        .public_transfers()
        .iter()
        .map(
            |PublicTransfer {
                 asset,
                 is_deposit,
                 amount,
                 account,
             }| (*is_deposit, *amount, *asset, *account),
        )
        .collect()
}

#[test]
fn transfers_and_withdrawals_move_exactly_their_amounts() {
    let mut source = source(10);
    let mut destination = TokenUtxos::new_init(&owner(2), &SOL);
    source.transfer(&mut destination, &4).unwrap();
    source.withdraw(&5, &[9; 32]).unwrap();
    destination.deposit(&7, &[8; 32]).unwrap();
    let mut emptied = TokenUtxos::new_init(&owner(2), &SOL);
    destination.transfer_all(&mut emptied).unwrap();
    assert_eq!(
        (
            [source.amount(), destination.amount(), emptied.amount()],
            transfers(&source),
            transfers(&destination),
            [*source.transferred(), *emptied.transferred()],
        ),
        (
            [Ok(1), Ok(0), Ok(11)],
            vec![(false, 5, SOL, [9; 32])],
            vec![(true, 7, SOL, [8; 32])],
            [-Field::from(4u64), Field::from(11u64)],
        )
    );
    assert_eq!(source.withdraw_all(&[9; 32]), Ok(1));
    assert_eq!(source.amount(), Ok(0));
}

#[test]
fn a_debit_beyond_the_balance_is_refused() {
    let (anchor, call) = DEBIT;
    assert_requirement(
        checked(|| {
            let mut destination = TokenUtxos::new_init(&owner(2), &SOL);
            source(10).transfer(&mut destination, &11)
        }),
        BALANCE,
        anchor,
        call,
    );
    assert_requirement(
        checked(|| source(10).withdraw(&11, &[9; 32])),
        BALANCE,
        anchor,
        call,
    );
}

#[test]
fn a_transfer_into_a_closed_destination_is_refused() {
    let call = "require(!destination.is_closed())";
    assert_requirement(
        checked(|| {
            let mut closed = TokenUtxos::new_init(&owner(2), &SOL).close();
            source(10).transfer(&mut closed, &1)
        }),
        BALANCE,
        DESTINATION,
        call,
    );
    assert_requirement(
        checked(|| {
            let mut closed = DataUtxo::new_init_with_hash(&owner(2), &Field::one())
                .with_asset(&SOL)?
                .close();
            source(10).transfer_all(&mut closed)
        }),
        BALANCE,
        DESTINATION,
        call,
    );
}

#[test]
fn a_destination_holding_another_asset_is_refused() {
    let call = "crate::require_eq(*asset, destination.balance().asset)";
    assert_requirement(
        checked(|| source(10).transfer(&mut TokenUtxos::new_init(&owner(2), &USDC), &1)),
        BALANCE,
        DESTINATION,
        call,
    );
    assert_requirement(
        checked(|| source(10).transfer_all(&mut TokenUtxos::new_init(&owner(2), &USDC))),
        BALANCE,
        DESTINATION,
        call,
    );
}

#[test]
fn public_transfers_of_zero_are_refused() {
    let call = "require(*amount != 0)";
    let cases: [(&str, Operation); 2] = [
        ("fn deposit(", || source(10).deposit(&0, &[9; 32])),
        ("fn withdraw(", || source(10).withdraw(&0, &[9; 32])),
    ];
    for (anchor, operation) in cases {
        assert_requirement(checked(operation), BALANCE, anchor, call);
    }
    assert_requirement(
        checked(|| TokenUtxos::new_init(&owner(1), &SOL).withdraw_all(&[9; 32])),
        BALANCE,
        "fn withdraw_all(",
        "require(amount != 0)",
    );
}

#[test]
fn a_balance_of_at_least_2_pow_64_does_not_fit_an_amount() {
    assert_requirement(
        checked(|| {
            let mut wide = TokenUtxos::new_init(&owner(2), &SOL);
            TokenUtxos::new_mut(&[utxo(owner(1), SOL, u64::MAX), utxo(owner(1), SOL, 1)])?
                .transfer_all(&mut wide)?;
            wide.amount()
        }),
        BALANCE,
        "fn amount_u64(",
        "require(self.amount <= u128::from(u64::MAX))",
    );
}
