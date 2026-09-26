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
pub struct Issuer {
    pub issuer_hash: [u8; 32],
    pub issued: u64,
}

impl zk_program_sdk::circuit::CircuitType for circuit::Issuer {}

impl ProofInput for Issuer {
    type Circuit = circuit::Issuer;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::Issuer, RelationError> {
        Ok(circuit::Issuer {
            issuer_hash: self.issuer_hash.instantiate(allocator)?,
            issued: self.issued.instantiate(allocator)?,
        })
    }
}

impl FromCircuit for Issuer {
    fn from_circuit(circuit: &circuit::Issuer) -> Result<Self, RelationError> {
        Ok(Self {
            issuer_hash: <[u8; 32]>::from_circuit(&circuit.issuer_hash)?,
            issued: u64::from_circuit(&circuit.issued)?,
        })
    }
}

impl Placeholder for Issuer {
    fn placeholder() -> Result<Self, RelationError> {
        Ok(Self {
            issuer_hash: Placeholder::placeholder()?,
            issued: Placeholder::placeholder()?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Credential {
    pub issuer_hash: [u8; 32],
    pub attribute_commitment: [u8; 32],
}

impl zk_program_sdk::circuit::CircuitType for circuit::Credential {}

impl ProofInput for Credential {
    type Circuit = circuit::Credential;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::Credential, RelationError> {
        Ok(circuit::Credential {
            issuer_hash: self.issuer_hash.instantiate(allocator)?,
            attribute_commitment: self.attribute_commitment.instantiate(allocator)?,
        })
    }
}

impl FromCircuit for Credential {
    fn from_circuit(circuit: &circuit::Credential) -> Result<Self, RelationError> {
        Ok(Self {
            issuer_hash: <[u8; 32]>::from_circuit(&circuit.issuer_hash)?,
            attribute_commitment: <[u8; 32]>::from_circuit(&circuit.attribute_commitment)?,
        })
    }
}

impl Placeholder for Credential {
    fn placeholder() -> Result<Self, RelationError> {
        Ok(Self {
            issuer_hash: Placeholder::placeholder()?,
            attribute_commitment: Placeholder::placeholder()?,
        })
    }
}

#[derive(Clone)]
struct CreateIssuer {
    private: CreateIssuerPrivateInputs,
    public: CreateIssuerPublicInputs,
}

#[derive(Clone)]
struct CreateIssuerPrivateInputs {
    tx_context: TxContext,
    token_utxos_asset_a: [WalletUtxo; 1],
}

#[derive(Clone)]
struct CreateIssuerPublicInputs {
    issuer: ShieldedAddress,
}

impl zk_program_sdk::circuit::CircuitType for circuit::CreateIssuer {}

impl ProofInput for CreateIssuer {
    type Circuit = circuit::CreateIssuer;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::CreateIssuer, RelationError> {
        let private = &self.private;
        Ok(circuit::CreateIssuer {
            private: circuit::CreateIssuerPrivateInputs {
                tx_context: private.tx_context.instantiate(allocator)?,
                token_utxos_asset_a: private.token_utxos_asset_a.instantiate(allocator)?,
            },
            public: circuit::CreateIssuerPublicInputs {
                issuer: self.public.issuer.instantiate(allocator)?,
            },
        })
    }
}

impl Placeholder for CreateIssuer {
    fn placeholder() -> Result<Self, RelationError> {
        Ok(Self {
            private: CreateIssuerPrivateInputs {
                tx_context: Placeholder::placeholder()?,
                token_utxos_asset_a: Placeholder::placeholder()?,
            },
            public: CreateIssuerPublicInputs {
                issuer: Placeholder::placeholder()?,
            },
        })
    }
}

pub(crate) mod circuit {
    use zk_program_sdk::{
        circuit::{
            constant, poseidon, zero, Asset, CheckedTransaction, Circuit, CircuitMarker,
            CircuitVar, ConfidentialTransaction, DataHash, DataUtxo, Owner, PublicInputs,
            TokenUtxo, TxContext, Utxo, UtxoData,
        },
        RelationError,
    };

    #[derive(Clone, Debug)]
    pub struct Issuer {
        pub issuer_hash: CircuitVar,
        pub issued: CircuitVar,
    }

    impl Default for Issuer {
        fn default() -> Self {
            Self {
                issuer_hash: zero(),
                issued: zero(),
            }
        }
    }

    impl DataHash for Issuer {
        fn hash(&self) -> Result<CircuitVar, RelationError> {
            poseidon(&[
                constant(1u64),
                self.issuer_hash.clone(),
                self.issued.clone(),
            ])
        }
    }

    impl UtxoData for Issuer {
        type Client = super::Issuer;
    }

    #[derive(Clone, Debug)]
    pub struct Credential {
        pub issuer_hash: CircuitVar,
        pub attribute_commitment: CircuitVar,
    }

    impl Default for Credential {
        fn default() -> Self {
            Self {
                issuer_hash: zero(),
                attribute_commitment: zero(),
            }
        }
    }

    impl DataHash for Credential {
        fn hash(&self) -> Result<CircuitVar, RelationError> {
            poseidon(&[
                constant(2u64),
                self.issuer_hash.clone(),
                self.attribute_commitment.clone(),
            ])
        }
    }

    impl UtxoData for Credential {
        type Client = super::Credential;
    }

    pub struct CreateIssuer {
        pub private: CreateIssuerPrivateInputs,
        pub public: CreateIssuerPublicInputs,
    }

    pub struct CreateIssuerPrivateInputs {
        pub tx_context: TxContext,
        pub token_utxos_asset_a: [Utxo; 1],
    }

    pub struct CreateIssuerPublicInputs {
        pub issuer: Owner,
    }

    impl Circuit for CreateIssuer {
        const MARKER: CircuitMarker = CircuitMarker;

        fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
            let private = &self.private;
            let tokens = TokenUtxo::new_mut(&private.token_utxos_asset_a)?;
            let mut issuer = DataUtxo::<Issuer>::new_init(&self.public.issuer, &Asset::sol());
            issuer.issuer_hash = self.public.issuer.hash()?;

            ConfidentialTransaction::new(&private.tx_context, &self.public)
                .with_token_utxos(tokens)
                .with_data_utxo(issuer)
                .check()
        }
    }

    impl PublicInputs for CreateIssuerPublicInputs {
        fn hash(&self, transaction_hash: &CircuitVar) -> Result<CircuitVar, RelationError> {
            poseidon(&[self.issuer.hash()?, transaction_hash.clone()])
        }
    }
}

#[test]
fn create_issuer_prove_and_verify() {
    let issuer = keypair(5);
    let address = issuer.shielded_address().expect("issuer address");
    let payer = address.solana_address().expect("payer");
    let input = token_input(&issuer, Mint::SOL, 300, 0);

    let create = CreateIssuer {
        private: CreateIssuerPrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: [input],
        },
        public: CreateIssuerPublicInputs { issuer: address },
    };
    let spp_proof_inputs = create
        .create_proof_inputs_and_encrypt(&issuer, payer, u64::MAX)
        .expect("create issuer proof inputs");
    let state = Issuer {
        issuer_hash: address.owner_hash().expect("issuer hash"),
        issued: 0,
    };
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
                Some(borsh::to_vec(&state).expect("issuer bytes")),
            ),
        ]
    );

    let prover = Groth16Prover::<CreateIssuer>::new_with_test_setup().expect("create issuer setup");
    let result = prove(&prover, &create, "create issuer proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
