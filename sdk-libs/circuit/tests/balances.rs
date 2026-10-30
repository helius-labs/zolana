use spr_circuit::protocol::{TokenUtxos, Utxo, UtxoTrait};

fn source(amounts: &[u64]) -> TokenUtxos {
    let inputs: Vec<_> = amounts.iter().map(|amount| Utxo { amount: *amount, ..Utxo::default() }).collect();
    TokenUtxos::new_mut(&inputs).unwrap()
}

#[test]
fn wide_inputs_can_be_debited_down_to_a_u64_balance() {
    let mut source = source(&[u64::MAX, u64::MAX]);
    let mut destination = TokenUtxos::new_init(&source.owner(), &source.asset());
    source.transfer(&mut destination, &u64::MAX).unwrap();
    assert_eq!((source.amount().unwrap(), destination.amount().unwrap()), (u64::MAX, u64::MAX));
}

#[test]
fn debit_rejects_a_remaining_balance_above_u64_immediately() {
    let rejected = std::panic::catch_unwind(|| {
        let mut source = source(&[u64::MAX, u64::MAX]);
        let mut destination = TokenUtxos::new_init(&source.owner(), &source.asset());
        source.transfer(&mut destination, &1).unwrap();
    });
    assert!(rejected.is_err(), "a debit narrows its remaining balance before another operation");
}

#[test]
fn transfer_all_preserves_wide_intermediate_balances() {
    let mut source = source(&[u64::MAX, u64::MAX]);
    let mut wide = TokenUtxos::new_init(&source.owner(), &source.asset());
    source.transfer_all(&mut wide).unwrap();
    let mut destination = TokenUtxos::new_init(&wide.owner(), &wide.asset());
    wide.transfer(&mut destination, &u64::MAX).unwrap();
    assert_eq!((source.amount().unwrap(), wide.amount().unwrap(), destination.amount().unwrap()), (0, u64::MAX, u64::MAX));
}
