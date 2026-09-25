use borsh::{BorshDeserialize, BorshSerialize};
use zk_program_sdk::{
    conversion::{Allocator, FromCircuit, Placeholder, ProofInput},
    Groth16Prover, RelationError, TxContext, ZkProgram,
};
use zolana_keypair::ShieldedAddress;
use zolana_transaction::{Mint, WalletUtxo};

use crate::{
    benchmark::prove,
    shared::{keypair, token_input},
};

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Counter {
    pub count: u64,
}

impl ProofInput for Counter {
    type Circuit = circuit::Counter;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::Counter, RelationError> {
        Ok(circuit::Counter {
            count: self.count.instantiate(allocator)?,
        })
    }
}

impl FromCircuit for Counter {
    fn from_circuit(circuit: &circuit::Counter) -> Result<Self, RelationError> {
        Ok(Self {
            count: u64::from_circuit(&circuit.count)?,
        })
    }
}

impl Placeholder for Counter {
    fn placeholder() -> Result<Self, RelationError> {
        Ok(Self {
            count: Placeholder::placeholder()?,
        })
    }
}

#[derive(Clone)]
pub(crate) struct CounterCreate {
    pub(crate) private: CounterCreatePrivateInputs,
    pub(crate) public: CounterCreatePublicInputs,
}

#[derive(Clone)]
pub(crate) struct CounterCreatePrivateInputs {
    pub(crate) tx_context: TxContext,
    pub(crate) token_utxos_asset_a: [WalletUtxo; 1],
}

#[derive(Clone)]
pub(crate) struct CounterCreatePublicInputs {
    pub(crate) owner: ShieldedAddress,
}

impl ProofInput for CounterCreate {
    type Circuit = circuit::CounterCreate;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::CounterCreate, RelationError> {
        let private = &self.private;
        Ok(circuit::CounterCreate {
            private: circuit::CounterCreatePrivateInputs {
                tx_context: private.tx_context.instantiate(allocator)?,
                token_utxos_asset_a: private.token_utxos_asset_a.instantiate(allocator)?,
            },
            public: circuit::CounterCreatePublicInputs {
                owner: self.public.owner.instantiate(allocator)?,
            },
        })
    }
}

impl Placeholder for CounterCreate {
    fn placeholder() -> Result<Self, RelationError> {
        Ok(Self {
            private: CounterCreatePrivateInputs {
                tx_context: Placeholder::placeholder()?,
                token_utxos_asset_a: Placeholder::placeholder()?,
            },
            public: CounterCreatePublicInputs {
                owner: Placeholder::placeholder()?,
            },
        })
    }
}

pub(crate) mod circuit {
    use zk_program_sdk::{
        circuit::{
            poseidon, zero, CheckedTransaction, Circuit, CircuitVar, ConfidentialTransaction,
            DataHash, DataUtxo, Owner, PublicInputs, TokenUtxo, TxContext, Utxo, UtxoData,
        },
        RelationError,
    };

    #[derive(Clone, Debug)]
    pub struct Counter {
        pub count: CircuitVar,
    }

    impl Default for Counter {
        fn default() -> Self {
            Self { count: zero() }
        }
    }

    impl DataHash for Counter {
        fn hash(&self) -> Result<CircuitVar, RelationError> {
            poseidon(std::slice::from_ref(&self.count))
        }
    }

    impl UtxoData for Counter {
        type Client = super::Counter;
    }

    pub struct CounterCreate {
        pub private: CounterCreatePrivateInputs,
        pub public: CounterCreatePublicInputs,
    }

    pub struct CounterCreatePrivateInputs {
        pub tx_context: TxContext,
        pub token_utxos_asset_a: [Utxo; 1],
    }

    pub struct CounterCreatePublicInputs {
        pub owner: Owner,
    }

    impl Circuit for CounterCreate {
        fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
            let private = &self.private;
            let tokens = TokenUtxo::new_mut(&private.token_utxos_asset_a)?;
            let counter = DataUtxo::<Counter>::new_init(&self.public.owner);

            ConfidentialTransaction::new(&private.tx_context, &self.public)
                .with_token_utxos(tokens)
                .with_data_utxo(counter)
                .check()
        }
    }

    impl PublicInputs for CounterCreatePublicInputs {
        fn hash(&self, transaction_hash: &CircuitVar) -> Result<CircuitVar, RelationError> {
            poseidon(&[self.owner.hash()?, transaction_hash.clone()])
        }
    }
}

#[test]
fn counter_create_prove_and_verify() {
    let sender = keypair(5);
    let address = sender.shielded_address().expect("sender address");
    let payer = address.solana_address().expect("payer");
    let input = token_input(&sender, Mint::SOL, 300, 0);

    let create = CounterCreate {
        private: CounterCreatePrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: [input],
        },
        public: CounterCreatePublicInputs { owner: address },
    };
    let spp_proof_inputs = create
        .create_proof_inputs_and_encrypt(&sender, payer, u64::MAX)
        .expect("counter create proof inputs");
    assert_eq!(
        spp_proof_inputs
            .output_utxos
            .iter()
            .map(|output| (
                output.owner_address,
                output.asset,
                output.amount,
                output.data.utxo_data().map(<[u8]>::to_vec),
            ))
            .collect::<Vec<_>>(),
        vec![
            (Some(address), Mint::SOL, 300, None),
            (
                Some(address),
                Mint::SOL,
                0,
                Some(borsh::to_vec(&Counter { count: 0 }).expect("counter bytes")),
            ),
        ]
    );

    let prover =
        Groth16Prover::<CounterCreate>::new_with_test_setup().expect("counter create setup");
    let result = prove(&prover, &create, "counter create proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
