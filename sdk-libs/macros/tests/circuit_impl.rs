#![deny(unused_must_use, unused_variables, unused_assignments)]
#![forbid(unsafe_code)]
#![deny(clippy::let_underscore_must_use, clippy::disallowed_types)]

use zolana_program::{
    circuit::{
        value, CheckedTransaction, Circuit, ConfidentialTransaction, Field, PublicInputs, Uint,
    },
    conversion::{Allocator, ProofInput},
    CircuitError, TxContext, ZkProgram,
};

#[derive(Clone, ProofInput)]
struct Doubler {
    value: u64,
}

impl DoublerCircuit {
    fn doubled(&self) -> Uint<65> {
        self.value.add::<65>(&self.value)
    }
}

#[derive(Clone, ProofInput)]
pub struct Empty {
    private: EmptyPrivateInputs,
    public: EmptyPublicInputs,
}

#[derive(Clone, ProofInput)]
struct EmptyPrivateInputs {
    tx_context: TxContext,
}

#[derive(Clone, PublicInputs)]
struct EmptyPublicInputs;

impl Circuit for <Empty as ProofInput>::Circuit {
    fn circuit(&self) -> Result<CheckedTransaction, CircuitError> {
        ConfidentialTransaction::new(&self.private.tx_context, &self.public).check()
    }
}

fn run<P: ZkProgram>(inputs: &P) -> Result<CheckedTransaction, CircuitError> {
    inputs.instantiate(&Allocator::native())?.circuit()
}

#[test]
fn an_inherent_impl_uses_the_generated_type() {
    let doubler = Doubler { value: 4 }
        .instantiate(&Allocator::native())
        .expect("native instantiation");
    assert_eq!(
        value(&doubler.doubled().into()).expect("doubled"),
        Field::from(8u64)
    );
}

#[test]
fn a_qualified_impl_satisfies_the_programs_associated_type_bound() {
    let empty = Empty {
        private: EmptyPrivateInputs {
            tx_context: TxContext::new(),
        },
        public: EmptyPublicInputs,
    };
    assert!(matches!(
        run(&empty),
        Err(error) if error.broken_rule().is_some_and(|rule| rule.contains("input"))
    ));
}
