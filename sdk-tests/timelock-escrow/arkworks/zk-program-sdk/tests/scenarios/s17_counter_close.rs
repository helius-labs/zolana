use zk_program_sdk::{
    conversion::{Allocator, Placeholder, ProofInput},
    Groth16Prover, RelationError, TxContext, ZkProgram,
};
use zolana_keypair::ShieldedAddress;
use zolana_transaction::WalletUtxo;

use crate::{
    benchmark::prove,
    s13_counter_create::Counter,
    shared::{data_input, keypair},
};

#[derive(Clone)]
pub(crate) struct Close {
    pub(crate) private: ClosePrivateInputs,
    pub(crate) public: ClosePublicInputs,
}

#[derive(Clone)]
pub(crate) struct ClosePrivateInputs {
    pub(crate) tx_context: TxContext,
    pub(crate) counter: WalletUtxo,
    pub(crate) state: Counter,
}

#[derive(Clone)]
pub(crate) struct ClosePublicInputs {
    pub(crate) owner: ShieldedAddress,
}

impl ProofInput for Close {
    type Circuit = circuit::Close;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::Close, RelationError> {
        let private = &self.private;
        Ok(circuit::Close {
            private: circuit::ClosePrivateInputs {
                tx_context: private.tx_context.instantiate(allocator)?,
                counter: private.counter.instantiate(allocator)?,
                state: private.state.instantiate(allocator)?,
            },
            public: circuit::ClosePublicInputs {
                owner: self.public.owner.instantiate(allocator)?,
            },
        })
    }
}

impl Placeholder for Close {
    fn placeholder() -> Result<Self, RelationError> {
        Ok(Self {
            private: ClosePrivateInputs {
                tx_context: Placeholder::placeholder()?,
                counter: Placeholder::placeholder()?,
                state: Placeholder::placeholder()?,
            },
            public: ClosePublicInputs {
                owner: Placeholder::placeholder()?,
            },
        })
    }
}

mod circuit {
    use zk_program_sdk::{
        circuit::{
            poseidon, Assert, Balance, CheckedTransaction, Circuit, CircuitVar,
            ConfidentialTransaction, DataUtxo, Owner, PublicInputs, TxContext, Utxo,
        },
        RelationError,
    };

    use crate::s13_counter_create::circuit::Counter;

    pub struct Close {
        pub private: ClosePrivateInputs,
        pub public: ClosePublicInputs,
    }

    pub struct ClosePrivateInputs {
        pub tx_context: TxContext,
        pub counter: Utxo,
        pub state: Counter,
    }

    pub struct ClosePublicInputs {
        pub owner: Owner,
    }

    impl Circuit for Close {
        fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
            let private = &self.private;
            let counter = DataUtxo::new_burn(&private.counter, &private.state)?;
            counter
                .owner()
                .hash()?
                .assert_equal(&self.public.owner.hash()?, "the counter has another owner")?;

            ConfidentialTransaction::new(&private.tx_context, &self.public)
                .with_data_utxo(counter)
                .check()
        }
    }

    impl PublicInputs for ClosePublicInputs {
        fn hash(&self, transaction_hash: &CircuitVar) -> Result<CircuitVar, RelationError> {
            poseidon(&[self.owner.hash()?, transaction_hash.clone()])
        }
    }
}

#[test]
fn counter_close_prove_and_verify() {
    let owner = keypair(5);
    let address = owner.shielded_address().expect("owner address");
    let payer = address.solana_address().expect("payer");
    let state = Counter { count: 5 };
    let counter = data_input(&owner, 0, &state, 0);

    let close = Close {
        private: ClosePrivateInputs {
            tx_context: TxContext::new(),
            counter,
            state,
        },
        public: ClosePublicInputs { owner: address },
    };
    let spp_proof_inputs = close
        .create_proof_inputs_and_encrypt(&owner, payer, u64::MAX)
        .expect("close proof inputs");
    assert_eq!(
        spp_proof_inputs
            .output_utxos
            .iter()
            .map(|output| (output.owner_address, output.amount))
            .collect::<Vec<_>>(),
        vec![(None, 0)]
    );

    let prover = Groth16Prover::<Close>::new_with_test_setup().expect("close setup");
    let result = prove(&prover, &close, "close proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
