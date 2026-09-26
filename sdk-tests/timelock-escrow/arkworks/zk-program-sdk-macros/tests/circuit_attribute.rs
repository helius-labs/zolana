use zk_program_sdk::{
    circuit,
    circuit::{
        constant, value, CheckedTransaction, Circuit, CircuitMarker, CircuitVar,
        ConfidentialTransaction, Field, PublicInputs,
    },
    conversion::{Allocator, ProofInput},
    RelationError, TxContext,
};

#[derive(Clone, ProofInput)]
struct Doubler {
    value: u64,
}

#[circuit]
impl Doubler {
    fn doubled(&self) -> CircuitVar {
        self.value.clone() + &self.value
    }
}

#[derive(Clone, ProofInput)]
struct Empty {
    private: EmptyPrivateInputs,
    public: EmptyPublicInputs,
}

#[derive(Clone, ProofInput)]
struct EmptyPrivateInputs {
    tx_context: TxContext,
}

#[derive(Clone, ProofInput, PublicInputs)]
struct EmptyPublicInputs;

#[circuit]
impl Circuit for Empty {
    fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
        ConfidentialTransaction::new(&self.private.tx_context, &self.public).check()
    }
}

#[circuit]
fn shaped_sum<const N: usize>(values: &[CircuitVar; N]) -> Result<CircuitVar, RelationError> {
    let total = values.iter().fold(constant(0u64), |sum, value| sum + value);
    let scaled = if const { N > 2 } {
        total.clone() + &total
    } else if const { N > 1 } {
        total.clone()
    } else {
        constant(0u64)
    };
    let label = match const { N } {
        0 => 0u64,
        _ => 1u64,
    };
    let mut count = 0u64;
    for _ in values {
        count += 1;
    }
    Ok(scaled + constant(label + count))
}

#[test]
fn an_inherent_impl_is_written_against_the_circuit_twin() {
    let doubler = Doubler { value: 4 }
        .instantiate(&Allocator::native())
        .expect("native instantiation");
    assert_eq!(
        value(&doubler.doubled()).expect("doubled"),
        Field::from(8u64)
    );
}

#[test]
fn the_attribute_writes_the_circuit_marker_on_the_twin() {
    assert_eq!(<EmptyCircuit as Circuit>::MARKER, CircuitMarker);
    let empty = Empty {
        private: EmptyPrivateInputs {
            tx_context: TxContext::new(),
        },
        public: EmptyPublicInputs,
    }
    .instantiate(&Allocator::native())
    .expect("native instantiation");
    assert!(matches!(
        empty.circuit(),
        Err(RelationError::Violated(rule)) if rule.contains("input")
    ));
}

#[test]
fn compile_time_branches_loops_and_closures_run() {
    let values = [constant(1u64), constant(2u64), constant(3u64)];
    assert_eq!(
        value(&shaped_sum(&values).expect("sum")).expect("value"),
        Field::from(16u64)
    );
}
