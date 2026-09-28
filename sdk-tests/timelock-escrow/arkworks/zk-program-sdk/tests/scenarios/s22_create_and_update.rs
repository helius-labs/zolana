use borsh::{BorshDeserialize, BorshSerialize};
use zk_program_sdk::{
    conversion::{Allocator, FromCircuit, Placeholder, ProofInput},
    CircuitError, Groth16Prover, TxContext, ZkProgram,
};
use zolana_keypair::ShieldedAddress;
use zolana_transaction::{Mint, WalletUtxo};

use crate::{
    benchmark::prove,
    shared::{data_input, keypair},
};

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Profile {
    pub score: u64,
}

impl zk_program_sdk::circuit::CircuitType for circuit::Profile {}

impl ProofInput for Profile {
    type Circuit = circuit::Profile;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::Profile, CircuitError> {
        Ok(circuit::Profile {
            score: self.score.instantiate(allocator)?,
        })
    }
}

impl FromCircuit for Profile {
    fn from_circuit(circuit: &circuit::Profile) -> Result<Self, CircuitError> {
        Ok(Self {
            score: u64::from_circuit(&circuit.score)?,
        })
    }
}

impl Placeholder for Profile {
    fn placeholder() -> Result<Self, CircuitError> {
        Ok(Self {
            score: Placeholder::placeholder()?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Badge {
    pub level: u16,
}

impl zk_program_sdk::circuit::CircuitType for circuit::Badge {}

impl ProofInput for Badge {
    type Circuit = circuit::Badge;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::Badge, CircuitError> {
        Ok(circuit::Badge {
            level: self.level.instantiate(allocator)?,
        })
    }
}

impl FromCircuit for Badge {
    fn from_circuit(circuit: &circuit::Badge) -> Result<Self, CircuitError> {
        Ok(Self {
            level: u16::from_circuit(&circuit.level)?,
        })
    }
}

impl Placeholder for Badge {
    fn placeholder() -> Result<Self, CircuitError> {
        Ok(Self {
            level: Placeholder::placeholder()?,
        })
    }
}

#[derive(Clone)]
struct CreateAndUpdate {
    private: CreateAndUpdatePrivateInputs,
    public: CreateAndUpdatePublicInputs,
}

#[derive(Clone)]
struct CreateAndUpdatePrivateInputs {
    tx_context: TxContext,
    profile_utxo: WalletUtxo,
    profile: Profile,
    level: u16,
}

#[derive(Clone)]
struct CreateAndUpdatePublicInputs {
    badge_owner: ShieldedAddress,
}

impl zk_program_sdk::circuit::CircuitType for circuit::CreateAndUpdate {}

impl ProofInput for CreateAndUpdate {
    type Circuit = circuit::CreateAndUpdate;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::CreateAndUpdate, CircuitError> {
        let private = &self.private;
        Ok(circuit::CreateAndUpdate {
            private: circuit::CreateAndUpdatePrivateInputs {
                tx_context: private.tx_context.instantiate(allocator)?,
                profile_utxo: private.profile_utxo.instantiate(allocator)?,
                profile: private.profile.instantiate(allocator)?,
                level: private.level.instantiate(allocator)?,
            },
            public: circuit::CreateAndUpdatePublicInputs {
                badge_owner: self.public.badge_owner.instantiate(allocator)?,
            },
        })
    }
}

impl Placeholder for CreateAndUpdate {
    fn placeholder() -> Result<Self, CircuitError> {
        Ok(Self {
            private: CreateAndUpdatePrivateInputs {
                tx_context: Placeholder::placeholder()?,
                profile_utxo: Placeholder::placeholder()?,
                profile: Placeholder::placeholder()?,
                level: Placeholder::placeholder()?,
            },
            public: CreateAndUpdatePublicInputs {
                badge_owner: Placeholder::placeholder()?,
            },
        })
    }
}

pub(crate) mod circuit {
    use zk_program_sdk::{
        circuit::{
            constant, poseidon, Asset, CheckedTransaction, Circuit, CircuitVar,
            ConfidentialTransaction, DataHash, DataUtxo, Owner, PublicInputs, TxContext, Uint,
            Utxo, UtxoData,
        },
        CircuitError,
    };

    #[derive(Clone, Debug)]
    pub struct Profile {
        pub score: Uint<64>,
    }

    impl Default for Profile {
        fn default() -> Self {
            Self {
                score: Uint::zero(),
            }
        }
    }

    impl DataHash for Profile {
        fn hash(&self) -> Result<CircuitVar, CircuitError> {
            poseidon(&[self.score.clone().into()])
        }
    }

    impl UtxoData for Profile {
        type Client = super::Profile;
    }

    #[derive(Clone, Debug)]
    pub struct Badge {
        pub level: Uint<16>,
    }

    impl Default for Badge {
        fn default() -> Self {
            Self {
                level: Uint::zero(),
            }
        }
    }

    impl DataHash for Badge {
        fn hash(&self) -> Result<CircuitVar, CircuitError> {
            poseidon(&[constant(1u64), self.level.clone().into()])
        }
    }

    impl UtxoData for Badge {
        type Client = super::Badge;
    }

    pub struct CreateAndUpdate {
        pub private: CreateAndUpdatePrivateInputs,
        pub public: CreateAndUpdatePublicInputs,
    }

    pub struct CreateAndUpdatePrivateInputs {
        pub tx_context: TxContext,
        pub profile_utxo: Utxo,
        pub profile: Profile,
        pub level: Uint<16>,
    }

    pub struct CreateAndUpdatePublicInputs {
        pub badge_owner: Owner,
    }

    impl Circuit for CreateAndUpdate {
        fn circuit(&self) -> Result<CheckedTransaction, CircuitError> {
            let private = &self.private;
            let mut profile = DataUtxo::new_mut(&private.profile_utxo, &private.profile)?;
            profile.score = profile
                .score
                .checked_add(&Uint::<64>::constant(1)?, "the score overflows")?;
            let mut badge = DataUtxo::<Badge>::new_init(&self.public.badge_owner, &Asset::sol());
            badge.level = private.level.clone();

            ConfidentialTransaction::new(&private.tx_context, &self.public)
                .with_data_utxo(profile)
                .with_data_utxo(badge)
                .check()
        }
    }

    impl PublicInputs for CreateAndUpdatePublicInputs {
        fn hash(&self, transaction_hash: &CircuitVar) -> Result<CircuitVar, CircuitError> {
            poseidon(&[self.badge_owner.hash()?, transaction_hash.clone()])
        }
    }
}

#[test]
fn create_and_update_prove_and_verify() {
    let owner = keypair(5);
    let address = owner.shielded_address().expect("owner address");
    let payer = address.solana_address().expect("payer");
    let badge_owner = keypair(6).shielded_address().expect("badge owner address");
    let profile = Profile { score: 41 };
    let profile_utxo = data_input(&owner, 0, &profile, 0);

    let create_and_update = CreateAndUpdate {
        private: CreateAndUpdatePrivateInputs {
            tx_context: TxContext::new(),
            profile_utxo,
            profile,
            level: 2,
        },
        public: CreateAndUpdatePublicInputs { badge_owner },
    };
    let spp_proof_inputs = create_and_update
        .create_and_encrypt(&address, payer)
        .expect("create and update proof inputs");
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
            (
                Some(address),
                Mint::SOL,
                0,
                Some(borsh::to_vec(&Profile { score: 42 }).expect("profile bytes")),
            ),
            (
                Some(badge_owner),
                Mint::SOL,
                0,
                Some(borsh::to_vec(&Badge { level: 2 }).expect("badge bytes")),
            ),
        ]
    );

    let prover =
        Groth16Prover::<CreateAndUpdate>::new_with_test_setup().expect("create and update setup");
    let result = prove(&prover, &create_and_update, "create and update proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
