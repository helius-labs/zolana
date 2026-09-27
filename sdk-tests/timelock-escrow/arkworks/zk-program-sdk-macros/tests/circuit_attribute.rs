use zk_program_sdk::{
    circuit,
    circuit::{
        value, CheckedTransaction, Circuit, ConfidentialTransaction, Field, PublicInputs, Uint,
        U16, U32,
    },
    conversion::{to_bytes, Allocator, ProofInput},
    CircuitError, TxContext,
};

#[derive(Clone, ProofInput)]
struct Doubler {
    value: u64,
}

#[circuit]
impl Doubler {
    fn doubled(&self) -> Uint<65> {
        self.value.add::<65>(&self.value)
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
    fn circuit(&self) -> Result<CheckedTransaction, CircuitError> {
        ConfidentialTransaction::new(&self.private.tx_context, &self.public).check()
    }
}

#[circuit]
fn shaped_sum<const N: usize>(values: &[U16; N]) -> Result<U32, CircuitError> {
    let total = values.iter().try_fold(U32::zero(), |total, value| {
        total.checked_add(&U32::from(value.clone()), "the sum fits in 32 bits")
    })?;
    let scaled = if const { N > 2 } {
        total.checked_add(&total, "the sum fits in 32 bits")?
    } else if const { N > 1 } {
        total
    } else {
        U32::zero()
    };
    let label = match const { N } {
        0 => 0u64,
        _ => 1u64,
    };
    let mut count = 0u64;
    for _ in values {
        count += 1;
    }
    scaled.checked_add(&U32::constant(label + count)?, "the sum fits in 32 bits")
}

#[derive(Clone, ProofInput)]
struct Keyed {
    key: [u8; 32],
}

#[circuit]
mod keyed {
    use zk_program_sdk::circuit::CircuitVar;

    use super::KeyedCircuit;

    pub struct Label(pub u64);

    pub fn label() -> Label {
        Label(7)
    }

    impl Keyed {
        pub fn key(&self) -> CircuitVar {
            self.key.clone()
        }
    }

    pub mod nested {
        use zk_program_sdk::circuit::CircuitVar;

        use super::super::KeyedCircuit;

        impl Keyed {
            pub fn key_again(&self) -> CircuitVar {
                self.key.clone()
            }
        }
    }
}

#[circuit]
mod whole {
    use zk_program_sdk::{
        circuit::{CheckedTransaction, Circuit, ConfidentialTransaction, PublicInputs},
        conversion::ProofInput,
        CircuitError, TxContext,
    };

    #[derive(Clone, ProofInput)]
    pub struct Solo {
        pub private: SoloPrivateInputs,
        pub public: SoloPublicInputs,
    }

    #[derive(Clone, ProofInput)]
    pub struct SoloPrivateInputs {
        pub tx_context: TxContext,
    }

    #[derive(Clone, ProofInput, PublicInputs)]
    pub struct SoloPublicInputs;

    impl Circuit for Solo {
        fn circuit(&self) -> Result<CheckedTransaction, CircuitError> {
            ConfidentialTransaction::new(&self.private.tx_context, &self.public).check()
        }
    }
}

#[test]
fn a_module_renames_its_impls_and_leaves_other_items_alone() {
    let keyed = Keyed { key: [3u8; 32] }
        .instantiate(&Allocator::native())
        .expect("native instantiation");
    assert_eq!(
        (
            keyed::label().0,
            to_bytes(&keyed.key()).expect("key"),
            to_bytes(&keyed.key_again()).expect("key again"),
        ),
        (7, [3u8; 32], [3u8; 32])
    );
}

#[test]
fn a_module_renames_a_circuit_impl_to_its_twin() {
    let solo = whole::Solo {
        private: whole::SoloPrivateInputs {
            tx_context: TxContext::new(),
        },
        public: whole::SoloPublicInputs,
    }
    .instantiate(&Allocator::native())
    .expect("native instantiation");
    assert!(matches!(
        solo.circuit(),
        Err(error) if error.broken_rule().is_some_and(|rule| rule.contains("input"))
    ));
}

#[test]
fn an_inherent_impl_is_written_against_the_circuit_twin() {
    let doubler = Doubler { value: 4 }
        .instantiate(&Allocator::native())
        .expect("native instantiation");
    assert_eq!(
        value(&doubler.doubled().var()).expect("doubled"),
        Field::from(8u64)
    );
}

#[test]
fn the_attribute_renames_a_circuit_impl_to_its_twin() {
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
        Err(error) if error.broken_rule().is_some_and(|rule| rule.contains("input"))
    ));
}

#[test]
fn compile_time_branches_loops_and_closures_run() {
    let values = [1, 2, 3].map(|value| Uint::<16>::constant(value).expect("constant"));
    assert_eq!(
        value(&shaped_sum(&values).expect("sum").var()).expect("value"),
        Field::from(16u64)
    );
}
