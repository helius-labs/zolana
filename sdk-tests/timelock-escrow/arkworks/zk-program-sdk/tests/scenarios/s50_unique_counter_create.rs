use borsh::{BorshDeserialize, BorshSerialize};
use solana_address::Address;
use zk_program_sdk::{
    circuit::Circuit,
    conversion::{to_bytes, Allocator, FromCircuit, Placeholder, ProofInput},
    hasher::unique_data_hash,
    CircuitError, Groth16Prover, ProgramOwner, TxContext, ZkProgram,
};
use zolana_keypair::ShieldedAddress;
use zolana_program::{
    compression::{AddressSeed, DataUtxo, NewAddress, PdaOwner},
    derive_output_blinding_seed, derive_private_tx_blinding, derive_transact_output_blinding,
};

use crate::{
    benchmark::prove,
    shared::{keypair, poseidon_bytes},
};

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Counter {
    pub count: u64,
}

impl zk_program_sdk::circuit::CircuitType for circuit::Counter {}

impl ProofInput for Counter {
    type Circuit = circuit::Counter;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::Counter, CircuitError> {
        Ok(circuit::Counter {
            count: self.count.instantiate(allocator)?,
        })
    }
}

impl FromCircuit for Counter {
    fn from_circuit(circuit: &circuit::Counter) -> Result<Self, CircuitError> {
        Ok(Self {
            count: u64::from_circuit(&circuit.count)?,
        })
    }
}

#[derive(Clone)]
struct UniqueCounterCreate {
    private: UniqueCounterCreatePrivateInputs,
    public: UniqueCounterCreatePublicInputs,
}

#[derive(Clone)]
struct UniqueCounterCreatePrivateInputs {
    tx_context: TxContext,
}

#[derive(Clone)]
struct UniqueCounterCreatePublicInputs {
    owner: ShieldedAddress,
}

impl zk_program_sdk::circuit::CircuitType for circuit::UniqueCounterCreate {}

impl ProofInput for UniqueCounterCreate {
    type Circuit = circuit::UniqueCounterCreate;

    fn instantiate(
        &self,
        allocator: &Allocator,
    ) -> Result<circuit::UniqueCounterCreate, CircuitError> {
        Ok(circuit::UniqueCounterCreate {
            private: circuit::UniqueCounterCreatePrivateInputs {
                tx_context: self.private.tx_context.instantiate(allocator)?,
            },
            public: circuit::UniqueCounterCreatePublicInputs {
                owner: self.public.owner.instantiate(allocator)?,
            },
        })
    }
}

impl Placeholder for UniqueCounterCreate {
    fn placeholder() -> Result<Self, CircuitError> {
        Ok(Self {
            private: UniqueCounterCreatePrivateInputs {
                tx_context: Placeholder::placeholder()?,
            },
            public: UniqueCounterCreatePublicInputs {
                owner: Placeholder::placeholder()?,
            },
        })
    }
}

mod circuit {
    use zk_program_sdk::{
        circuit::{
            poseidon, CheckedTransaction, Circuit, CircuitVar, ConfidentialTransaction, DataHash,
            Owner, PublicInputs, TxContext, Uint, UniqueDataUtxo, UtxoData,
        },
        CircuitError,
    };

    #[derive(Clone, Debug)]
    pub struct Counter {
        pub count: Uint<64>,
    }

    impl Default for Counter {
        fn default() -> Self {
            Self {
                count: Uint::zero(),
            }
        }
    }

    impl DataHash for Counter {
        fn hash(&self) -> Result<CircuitVar, CircuitError> {
            poseidon(&[self.count.clone().into()])
        }
    }

    impl UtxoData for Counter {
        type Client = super::Counter;
    }

    pub struct UniqueCounterCreate {
        pub private: UniqueCounterCreatePrivateInputs,
        pub public: UniqueCounterCreatePublicInputs,
    }

    pub struct UniqueCounterCreatePrivateInputs {
        pub tx_context: TxContext,
    }

    pub struct UniqueCounterCreatePublicInputs {
        pub owner: Owner,
    }

    impl Circuit for UniqueCounterCreate {
        fn circuit(&self) -> Result<CheckedTransaction, CircuitError> {
            let public = &self.public;
            let counter = UniqueDataUtxo::<Counter>::new_init(&public.owner)?;

            ConfidentialTransaction::new(&self.private.tx_context, public)
                .with_unique_data_utxo(counter)
                .check()
        }
    }

    impl PublicInputs for UniqueCounterCreatePublicInputs {
        fn hash(&self, transaction_hash: &CircuitVar) -> Result<CircuitVar, CircuitError> {
            poseidon(&[self.owner.hash()?, transaction_hash.clone()])
        }
    }
}

#[test]
fn unique_counter_create_prove_and_verify() {
    let viewer = keypair(5).shielded_address().expect("viewer address");
    let payer = viewer.solana_address().expect("payer");
    let program = ProgramOwner::new(Address::new_from_array([9u8; 32]));
    let owner = program
        .address(viewer.viewing_pubkey)
        .expect("program address");
    let tx_context = TxContext::new();

    let create = UniqueCounterCreate {
        private: UniqueCounterCreatePrivateInputs { tx_context },
        public: UniqueCounterCreatePublicInputs { owner },
    };

    let pda_owner = PdaOwner::new(program.pda()).expect("pda owner");
    let address = *NewAddress::derive(&pda_owner, AddressSeed::owner(&pda_owner))
        .expect("address")
        .address();
    let output_blinding = derive_transact_output_blinding(
        &address,
        &derive_output_blinding_seed(&address, &tx_context.blinding_seed)
            .expect("output blinding seed"),
        0,
    )
    .expect("output blinding");
    let output_hash = DataUtxo {
        owner: &pda_owner,
        data_hash: unique_data_hash(&address, &poseidon_bytes(&[[0u8; 32]])).expect("data hash"),
        blinding: output_blinding,
    }
    .hash(0)
    .expect("output hash");
    let private_tx_hash = poseidon_bytes(&[
        [0u8; 32],
        poseidon_bytes(&[[0u8; 32], output_hash]),
        poseidon_bytes(&[[0u8; 32], address]),
        derive_private_tx_blinding(&address, &tx_context.blinding_seed)
            .expect("private tx blinding"),
    ]);
    let public_hash = poseidon_bytes(&[owner.owner_hash().expect("owner hash"), private_tx_hash]);

    let checked = create
        .instantiate(&Allocator::native())
        .expect("native unique counter create")
        .circuit()
        .expect("unique counter create circuit");

    let prover = Groth16Prover::<UniqueCounterCreate>::new_with_test_setup()
        .expect("unique counter create setup");
    let result = prove(&prover, &create, "unique counter create proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");

    assert_eq!(
        (
            to_bytes(checked.private_tx_hash()).expect("private tx hash"),
            to_bytes(checked.public_hash()).expect("public hash"),
            result.public_hash,
            create
                .create_finalized_transaction(&viewer, payer)
                .map(|_| ())
                .map_err(|error| error.name()),
        ),
        (
            private_tx_hash,
            public_hash,
            public_hash,
            Err("ClientError.UnsupportedAddressCreation"),
        )
    );
}
