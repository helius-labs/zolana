use spr_circuit::protocol::{
    CheckedTransaction, ConfidentialTransaction, DataUtxo, NewAddress, TokenUtxos, TxContext, Utxo,
    UtxoMeta, UtxoTrait,
};
use spr_circuit::{CircuitError, Field, checked, to_bytes};

use crate::support::{Public, SOL, assert_requirement, context, owner, program_owner, utxo};

const TRANSACTION: &str = "protocol/transaction.rs";

fn empties(checked: &CheckedTransaction) -> Vec<(u64, bool)> {
    checked
        .outputs
        .iter()
        .map(|output| (output.output.amount, output.empty))
        .collect()
}

fn hashes(values: &[Field]) -> Vec<[u8; 32]> {
    values.iter().map(to_bytes).collect()
}

#[test]
fn a_transaction_spends_at_least_one_input_or_reserves_an_address() {
    let error = ConfidentialTransaction::new(&context(), &Public)
        .with(TokenUtxos::new_init(&owner(1), &SOL))
        .check()
        .unwrap_err();
    assert_eq!(
        error.broken_rule(),
        Some("a transaction spends at least one input")
    );
    assert!(
        ConfidentialTransaction::new(&context(), &Public)
            .with(NewAddress::new(&program_owner(1), &Field::one()).unwrap())
            .check()
            .is_ok()
    );
}

#[test]
fn the_output_tree_is_the_chosen_one_or_the_first_inputs_latest_tree() {
    let latest = |has_latest_tree_id| Utxo {
        meta: UtxoMeta {
            latest_tree_id: 9,
            has_latest_tree_id,
            ..utxo(owner(1), SOL, 5).meta
        },
        ..utxo(owner(1), SOL, 5)
    };
    let run = |context: TxContext, input: Utxo| {
        checked(|| {
            ConfidentialTransaction::new(&context, &Public)
                .with(TokenUtxos::new_mut(&[input])?)
                .check()
                .map(|checked| checked.output_tree_id)
        })
    };
    let unchosen = TxContext {
        uses_output_tree_id: false,
        ..context()
    };
    assert_eq!(
        [run(context(), latest(true)), run(unchosen, latest(true))],
        [Ok(17), Ok(9)]
    );
    assert_requirement(
        run(unchosen, latest(false)),
        TRANSACTION,
        "fn output_tree(",
        "require(self.uses_output_tree_id || first.meta.has_latest_tree_id)",
    );
}

#[test]
fn value_cannot_leave_the_transaction_through_an_unregistered_destination() {
    assert_requirement(
        checked(|| {
            let mut source = TokenUtxos::new_mut(&[utxo(owner(1), SOL, 5)])?;
            let mut destination = TokenUtxos::new_init(&owner(2), &SOL);
            source.transfer(&mut destination, &2)?;
            ConfidentialTransaction::new(&context(), &Public)
                .with(source)
                .check()
                .map(drop)
        }),
        TRANSACTION,
        "pub fn check(self)",
        "require_eq(self.transferred, Field::zero())",
    );
}

#[test]
fn only_a_trailing_run_of_zero_token_outputs_becomes_empty_slots() {
    let spend = |amount| TokenUtxos::new_mut(&[utxo(owner(1), SOL, amount)]).unwrap();
    let paid = |amount| {
        let mut source = spend(5);
        let mut destination = TokenUtxos::new_init(&owner(2), &SOL);
        source.transfer(&mut destination, &amount).unwrap();
        (source, destination)
    };
    let run = |build: &dyn Fn(
        ConfidentialTransaction<'_, Public>,
    ) -> ConfidentialTransaction<'_, Public>| {
        empties(
            &build(ConfidentialTransaction::new(&context(), &Public))
                .check()
                .unwrap(),
        )
    };
    let data = || DataUtxo::new_init_with_hash(&owner(3), &Field::one());
    assert_eq!(
        [
            run(&|tx| {
                let (source, destination) = paid(5);
                tx.with(source).with(destination)
            }),
            run(&|tx| {
                let (source, destination) = paid(0);
                tx.with(source).with(destination)
            }),
            run(&|tx| {
                let (source, destination) = paid(5);
                tx.with(destination).with(source)
            }),
            run(&|tx| tx.with(spend(0)).with(data())),
            run(&|tx| tx
                .with(spend(0))
                .with(TokenUtxos::new_init(&owner(2), &SOL).with_zero_output())),
            run(&|tx| tx
                .with(spend(0).with_zero_output())
                .with(TokenUtxos::new_init(&owner(2), &SOL))),
        ],
        [
            vec![(0, false), (5, false)],
            vec![(5, false), (0, true)],
            vec![(5, false), (0, true)],
            vec![(0, false), (0, false)],
            vec![(0, false), (0, false)],
            vec![(0, false), (0, true)],
        ]
    );
}

#[test]
fn a_closed_token_group_contributes_no_output() {
    let checked = ConfidentialTransaction::new(&context(), &Public)
        .with({
            let mut source = TokenUtxos::new_mut(&[utxo(owner(1), SOL, 5)])
                .unwrap()
                .close()
                .with_zero_output();
            source.withdraw_all(&[9; 32]).unwrap();
            source
        })
        .check()
        .unwrap();
    assert!(checked.outputs.is_empty());
}

#[test]
fn real_inputs_precede_dummies_and_address_slots_come_first() {
    let first = utxo(owner(1), SOL, 5);
    let second = utxo(owner(1), SOL, 6);
    let tokens = || TokenUtxos::new_mut(&[Utxo::dummy(), first, Utxo::dummy(), second]).unwrap();
    let expected = [
        first.hash().unwrap(),
        second.hash().unwrap(),
        Field::zero(),
        Field::zero(),
    ];

    let spent = ConfidentialTransaction::new(&context(), &Public)
        .with(tokens())
        .check()
        .unwrap();
    assert_eq!(
        (
            hashes(&spent.inputs),
            to_bytes(&spent.first_nullifier),
            spent.preserve_input_slots
        ),
        (hashes(&expected), to_bytes(&first.meta.nullifier), false)
    );

    let address = NewAddress::new(&program_owner(1), &Field::one()).unwrap();
    let reserved = address.address();
    let with_address = ConfidentialTransaction::new(&context(), &Public)
        .with_dummy_padding()
        .with(tokens())
        .with(address)
        .check()
        .unwrap();
    let mut slots = vec![Field::zero()];
    slots.extend(expected);
    assert_eq!(
        (
            hashes(&with_address.inputs),
            to_bytes(&with_address.first_nullifier),
            with_address.preserve_input_slots
        ),
        (hashes(&slots), to_bytes(&reserved), true)
    );
}

#[test]
fn a_failed_item_fails_the_transaction_with_its_first_requirement() {
    let result: Result<CheckedTransaction, CircuitError> = checked(|| {
        let mut state = DataUtxo::new_mut_with_hash(
            &Utxo {
                data_hash: Field::one(),
                ..utxo(owner(1), SOL, 5)
            },
            &Field::one(),
        )?;
        state.withdraw(&2, &[9; 32])?;
        ConfidentialTransaction::new(&context(), &Public)
            .with(state.close())
            .check()
    });
    assert_requirement(
        result,
        "protocol/utxo/data.rs",
        "OutputState::None =>",
        "require_eq(self.balance.amount, 0u128)",
    );
}
