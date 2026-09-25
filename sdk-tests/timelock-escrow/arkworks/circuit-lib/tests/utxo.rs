use ark_relations::r1cs::ConstraintSystem;
use circuit_lib::{
    constant,
    convert::{field_bytes, to_bytes, utxo},
    poseidon, zero, Allocator, CircuitVar, DataHash, DataUtxo, Field, ProofInput, RelationError,
    TokenUtxo, Utxo,
};
use zolana_client::ProofInputUtxo;
use zolana_hasher::primitives::hash_bytes;

const TREE_ID: u16 = 2;

fn bytes(value: u64) -> [u8; 32] {
    field_bytes(&Field::from(value))
}

fn plain_input(owner: u64, amount: u64, blinding: u64) -> ProofInputUtxo {
    ProofInputUtxo::new(
        bytes(owner),
        &[4u8; 32].into(),
        amount,
        &bytes(blinding),
        TREE_ID,
    )
    .unwrap()
}

#[derive(Clone, Debug)]
struct Counter {
    value: CircuitVar,
}

impl Default for Counter {
    fn default() -> Self {
        Self { value: zero() }
    }
}

impl DataHash for Counter {
    fn hash(&self) -> Result<CircuitVar, RelationError> {
        poseidon(&[self.value.hash()?])
    }
}

fn counter(value: u64) -> Counter {
    Counter {
        value: constant(value),
    }
}

fn error<T>(result: Result<T, RelationError>) -> String {
    result.err().map(|e| e.to_string()).unwrap_or_default()
}

#[test]
fn a_data_utxo_follows_its_lifecycle() {
    let counter_hash = to_bytes(&counter(9).hash().unwrap()).unwrap();
    let spent = utxo(&plain_input(12, 7, 17).with_data_hash(counter_hash)).unwrap();
    let mut tokens = TokenUtxo::new_mut([utxo(&plain_input(11, 50, 1)).unwrap()]).unwrap();
    let funded =
        DataUtxo::<Counter>::from_output_utxo(tokens.transfer(&constant(12u64), constant(30u64)))
            .unwrap();
    let valueless = DataUtxo::<Counter>::new_init(&constant(12u64)).unwrap();
    let mut mutated = DataUtxo::new_mut(&spent, counter(9)).unwrap();
    mutated.value = constant(10u64);
    let mut burned = DataUtxo::new_burn(&spent, counter(9)).unwrap();
    let payout = burned.transfer(&constant(40u64), constant(7u64)).unwrap();

    assert_eq!(
        (
            (
                to_bytes(funded.owner()).unwrap(),
                to_bytes(funded.amount()).unwrap(),
                to_bytes(funded.asset()).unwrap(),
            ),
            (
                to_bytes(valueless.amount()).unwrap(),
                to_bytes(valueless.asset()).unwrap(),
            ),
            to_bytes(&mutated.value).unwrap(),
            (
                to_bytes(payout.owner()).unwrap(),
                to_bytes(payout.amount()).unwrap(),
            ),
            error(mutated.transfer(&constant(40u64), constant(1u64))),
            error(DataUtxo::new_mut(&spent, counter(8))),
            error(DataUtxo::new_burn(
                &utxo(&plain_input(12, 7, 17)).unwrap(),
                counter(9)
            )),
        ),
        (
            (bytes(12), bytes(30), plain_input(0, 0, 0).asset),
            (
                [0u8; 32],
                hash_bytes(zolana_transaction::Mint::SOL.asset.as_array()).unwrap()
            ),
            bytes(10),
            (bytes(40), bytes(7)),
            "only a burned data utxo transfers its value".to_string(),
            "the input does not commit to its program state".to_string(),
            "the input does not commit to its program state".to_string(),
        )
    );
}

#[test]
fn a_token_utxo_balances_transfers_deposits_and_withdrawals() {
    let mut token = TokenUtxo::new_mut([
        utxo(&plain_input(11, 300, 1)).unwrap(),
        utxo(&plain_input(11, 200, 2)).unwrap(),
        Utxo::dummy(),
    ])
    .unwrap();
    let transfer = token.transfer(&constant(30u64), constant(350u64));
    token.deposit(&constant(10u64));
    token.withdraw(&constant(5u64));
    let mut deposit_only = TokenUtxo::new_init(&constant(11u64), &constant(4u64));
    deposit_only.deposit(&constant(25u64));

    assert_eq!(
        (
            to_bytes(token.balance()).unwrap(),
            to_bytes(token.owner()).unwrap(),
            to_bytes(transfer.amount()).unwrap(),
            to_bytes(deposit_only.balance()).unwrap(),
            error(TokenUtxo::new_mut([
                utxo(&plain_input(11, 300, 1)).unwrap(),
                utxo(&plain_input(12, 1, 3)).unwrap(),
            ])),
            error(TokenUtxo::new_burn([
                Utxo::dummy(),
                utxo(&plain_input(11, 300, 1)).unwrap(),
            ])),
            error(TokenUtxo::new_mut([])),
        ),
        (
            bytes(155),
            bytes(11),
            bytes(350),
            bytes(25),
            "the inputs belong to different owners".to_string(),
            "the first input of a token utxo is a dummy".to_string(),
            "a token utxo spends at least one input".to_string(),
        )
    );
}

#[test]
fn a_token_utxo_enforces_its_rules_in_r1cs() {
    let spend = |inputs: [ProofInputUtxo; 2]| {
        let cs = ConstraintSystem::<Field>::new_ref();
        let allocator = Allocator::R1cs(cs.clone());
        let inputs = inputs.map(|input| utxo(&input).unwrap().instantiate(&allocator).unwrap());
        let _token = TokenUtxo::new_mut(inputs).unwrap();
        cs.is_satisfied().unwrap()
    };
    let dummy_with_value = {
        let cs = ConstraintSystem::<Field>::new_ref();
        let allocator = Allocator::R1cs(cs.clone());
        let mut dummy = Utxo::dummy();
        dummy.amount = constant(1_000u64);
        let token = TokenUtxo::new_mut([
            utxo(&plain_input(11, 300, 1))
                .unwrap()
                .instantiate(&allocator)
                .unwrap(),
            dummy.instantiate(&allocator).unwrap(),
        ])
        .unwrap();
        (
            to_bytes(token.balance()).unwrap(),
            cs.is_satisfied().unwrap(),
        )
    };

    assert_eq!(
        (
            spend([plain_input(11, 300, 1), plain_input(11, 200, 2)]),
            spend([plain_input(11, 300, 1), plain_input(12, 200, 2)]),
            dummy_with_value,
        ),
        (true, false, (bytes(300), true))
    );
}
