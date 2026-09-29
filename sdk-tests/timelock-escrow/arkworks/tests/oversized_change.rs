//! The circuit's change/output paths wrap the balance in `Uint::trusted`
//! without the `narrow()` range check that `UtxoTrait::amount()` and
//! `withdraw_all()` use. As a result the circuit accepts change outputs whose
//! amount does not fit in 64 bits, while the native transaction code refuses
//! the same values with checked arithmetic.
use zk_program_sdk::circuit::{
    constant, Bool, CircuitVar, ConfidentialTransaction, ConstraintSystem, PublicInputs,
    TokenUtxo, TxContext, Uint,
};
use zk_program_sdk::conversion::{Allocator, ProofInput};
use zk_program_sdk::CircuitError;

mod shared;
use shared::{keypair, token_input};

struct NoPublicInputs;
impl PublicInputs for NoPublicInputs {
    fn hash(&self, transaction_hash: &CircuitVar) -> Result<CircuitVar, CircuitError> {
        Ok(transaction_hash.clone())
    }
}

#[test]
fn the_circuit_accepts_a_change_amount_above_u64() {
    let cs = ConstraintSystem::new_ref();
    let allocator = Allocator::R1cs(cs.clone());

    let creator = keypair(5);
    let first = token_input(&creator, u64::MAX, 0)
        .instantiate(&allocator)
        .expect("first input");
    let second = token_input(&creator, u64::MAX, 1)
        .instantiate(&allocator)
        .expect("second input");

    // Balance = 2 * (2^64 - 1) = 2^65 - 2, which does not fit in 64 bits.
    let token = TokenUtxo::new_mut(&[first, second]).expect("token utxo");

    let tx_context = TxContext {
        blinding_seed: constant(7u64),
        output_tree_id: Uint::constant(3).expect("tree id"),
        uses_output_tree_id: Bool::constant(true),
    };
    let checked = ConfidentialTransaction::new(&tx_context, &NoPublicInputs)
        .with_token_utxos(token)
        .check()
        .expect("transaction checks out");

    // The whole circuit is satisfied even though the change amount
    // (2^65 - 2) exceeds u64::MAX. A range check (`narrow`) would have made
    // the system unsatisfiable here.
    let _ = checked;
    assert!(
        cs.is_satisfied().expect("satisfied"),
        "the circuit accepted a change amount of 2^65 - 2"
    );
    println!(
        "circuit accepted a change output of 2*(u64::MAX) = 2^65 - 2: \
         no range check on the change path"
    );
}
