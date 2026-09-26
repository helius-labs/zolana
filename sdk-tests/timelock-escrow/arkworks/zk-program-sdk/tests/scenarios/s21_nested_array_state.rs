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
pub struct Limits {
    pub daily: u64,
    pub weekly: u64,
    pub per_transfer: u64,
    pub frozen: bool,
    pub tier: u16,
}

impl zk_program_sdk::circuit::CircuitType for circuit::Limits {}

impl ProofInput for Limits {
    type Circuit = circuit::Limits;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::Limits, RelationError> {
        Ok(circuit::Limits {
            daily: self.daily.instantiate(allocator)?,
            weekly: self.weekly.instantiate(allocator)?,
            per_transfer: self.per_transfer.instantiate(allocator)?,
            frozen: self.frozen.instantiate(allocator)?,
            tier: self.tier.instantiate(allocator)?,
        })
    }
}

impl FromCircuit for Limits {
    fn from_circuit(circuit: &circuit::Limits) -> Result<Self, RelationError> {
        Ok(Self {
            daily: u64::from_circuit(&circuit.daily)?,
            weekly: u64::from_circuit(&circuit.weekly)?,
            per_transfer: u64::from_circuit(&circuit.per_transfer)?,
            frozen: bool::from_circuit(&circuit.frozen)?,
            tier: u16::from_circuit(&circuit.tier)?,
        })
    }
}

impl Placeholder for Limits {
    fn placeholder() -> Result<Self, RelationError> {
        Ok(Self {
            daily: Placeholder::placeholder()?,
            weekly: Placeholder::placeholder()?,
            per_transfer: Placeholder::placeholder()?,
            frozen: Placeholder::placeholder()?,
            tier: Placeholder::placeholder()?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Portfolio {
    pub owner_hash: [u8; 32],
    pub nonce: u32,
    pub limits: Limits,
    pub balances: [u64; 4],
    pub labels: [u16; 2],
}

impl zk_program_sdk::circuit::CircuitType for circuit::Portfolio {}

impl ProofInput for Portfolio {
    type Circuit = circuit::Portfolio;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::Portfolio, RelationError> {
        Ok(circuit::Portfolio {
            owner_hash: self.owner_hash.instantiate(allocator)?,
            nonce: self.nonce.instantiate(allocator)?,
            limits: self.limits.instantiate(allocator)?,
            balances: self.balances.instantiate(allocator)?,
            labels: self.labels.instantiate(allocator)?,
        })
    }
}

impl FromCircuit for Portfolio {
    fn from_circuit(circuit: &circuit::Portfolio) -> Result<Self, RelationError> {
        Ok(Self {
            owner_hash: <[u8; 32]>::from_circuit(&circuit.owner_hash)?,
            nonce: u32::from_circuit(&circuit.nonce)?,
            limits: Limits::from_circuit(&circuit.limits)?,
            balances: <[u64; 4]>::from_circuit(&circuit.balances)?,
            labels: <[u16; 2]>::from_circuit(&circuit.labels)?,
        })
    }
}

impl Placeholder for Portfolio {
    fn placeholder() -> Result<Self, RelationError> {
        Ok(Self {
            owner_hash: Placeholder::placeholder()?,
            nonce: Placeholder::placeholder()?,
            limits: Placeholder::placeholder()?,
            balances: Placeholder::placeholder()?,
            labels: Placeholder::placeholder()?,
        })
    }
}

#[derive(Clone)]
struct PortfolioCreate {
    private: PortfolioCreatePrivateInputs,
    public: PortfolioCreatePublicInputs,
}

#[derive(Clone)]
struct PortfolioCreatePrivateInputs {
    tx_context: TxContext,
    token_utxos_asset_a: [WalletUtxo; 1],
    nonce: u32,
    limits: Limits,
    balances: [u64; 4],
    labels: [u16; 2],
}

#[derive(Clone)]
struct PortfolioCreatePublicInputs {
    owner: ShieldedAddress,
}

impl zk_program_sdk::circuit::CircuitType for circuit::PortfolioCreate {}

impl ProofInput for PortfolioCreate {
    type Circuit = circuit::PortfolioCreate;

    fn instantiate(
        &self,
        allocator: &Allocator,
    ) -> Result<circuit::PortfolioCreate, RelationError> {
        let private = &self.private;
        Ok(circuit::PortfolioCreate {
            private: circuit::PortfolioCreatePrivateInputs {
                tx_context: private.tx_context.instantiate(allocator)?,
                token_utxos_asset_a: private.token_utxos_asset_a.instantiate(allocator)?,
                nonce: private.nonce.instantiate(allocator)?,
                limits: private.limits.instantiate(allocator)?,
                balances: private.balances.instantiate(allocator)?,
                labels: private.labels.instantiate(allocator)?,
            },
            public: circuit::PortfolioCreatePublicInputs {
                owner: self.public.owner.instantiate(allocator)?,
            },
        })
    }
}

impl Placeholder for PortfolioCreate {
    fn placeholder() -> Result<Self, RelationError> {
        Ok(Self {
            private: PortfolioCreatePrivateInputs {
                tx_context: Placeholder::placeholder()?,
                token_utxos_asset_a: Placeholder::placeholder()?,
                nonce: Placeholder::placeholder()?,
                limits: Placeholder::placeholder()?,
                balances: Placeholder::placeholder()?,
                labels: Placeholder::placeholder()?,
            },
            public: PortfolioCreatePublicInputs {
                owner: Placeholder::placeholder()?,
            },
        })
    }
}

mod circuit {
    use zk_program_sdk::{
        circuit::{
            poseidon, zero, Asset, Bool, CheckedTransaction, Circuit, CircuitMarker, CircuitVar,
            ConfidentialTransaction, DataHash, DataUtxo, Owner, PublicInputs, TokenUtxo, TxContext,
            Utxo, UtxoData,
        },
        RelationError,
    };

    #[derive(Clone, Debug)]
    pub struct Limits {
        pub daily: CircuitVar,
        pub weekly: CircuitVar,
        pub per_transfer: CircuitVar,
        pub frozen: Bool,
        pub tier: CircuitVar,
    }

    impl Default for Limits {
        fn default() -> Self {
            Self {
                daily: zero(),
                weekly: zero(),
                per_transfer: zero(),
                frozen: Bool::constant(false),
                tier: zero(),
            }
        }
    }

    impl DataHash for Limits {
        fn hash(&self) -> Result<CircuitVar, RelationError> {
            poseidon(&[
                self.daily.clone(),
                self.weekly.clone(),
                self.per_transfer.clone(),
                self.frozen.var(),
                self.tier.clone(),
            ])
        }
    }

    #[derive(Clone, Debug)]
    pub struct Portfolio {
        pub owner_hash: CircuitVar,
        pub nonce: CircuitVar,
        pub limits: Limits,
        pub balances: [CircuitVar; 4],
        pub labels: [CircuitVar; 2],
    }

    impl Default for Portfolio {
        fn default() -> Self {
            Self {
                owner_hash: zero(),
                nonce: zero(),
                limits: Limits::default(),
                balances: core::array::from_fn(|_| zero()),
                labels: core::array::from_fn(|_| zero()),
            }
        }
    }

    impl DataHash for Portfolio {
        fn hash(&self) -> Result<CircuitVar, RelationError> {
            poseidon(&[
                self.owner_hash.clone(),
                self.nonce.clone(),
                self.limits.hash()?,
                poseidon(&self.balances)?,
                poseidon(&self.labels)?,
            ])
        }
    }

    impl UtxoData for Portfolio {
        type Client = super::Portfolio;
    }

    pub struct PortfolioCreate {
        pub private: PortfolioCreatePrivateInputs,
        pub public: PortfolioCreatePublicInputs,
    }

    pub struct PortfolioCreatePrivateInputs {
        pub tx_context: TxContext,
        pub token_utxos_asset_a: [Utxo; 1],
        pub nonce: CircuitVar,
        pub limits: Limits,
        pub balances: [CircuitVar; 4],
        pub labels: [CircuitVar; 2],
    }

    pub struct PortfolioCreatePublicInputs {
        pub owner: Owner,
    }

    impl Circuit for PortfolioCreate {
        const MARKER: CircuitMarker = CircuitMarker;

        fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
            let private = &self.private;
            let tokens = TokenUtxo::new_mut(&private.token_utxos_asset_a)?;
            let mut portfolio = DataUtxo::<Portfolio>::new_init(&self.public.owner, &Asset::sol());
            portfolio.owner_hash = self.public.owner.hash()?;
            portfolio.nonce = private.nonce.clone();
            portfolio.limits = private.limits.clone();
            portfolio.balances = private.balances.clone();
            portfolio.labels = private.labels.clone();

            ConfidentialTransaction::new(&private.tx_context, &self.public)
                .with_token_utxos(tokens)
                .with_data_utxo(portfolio)
                .check()
        }
    }

    impl PublicInputs for PortfolioCreatePublicInputs {
        fn hash(&self, transaction_hash: &CircuitVar) -> Result<CircuitVar, RelationError> {
            poseidon(&[self.owner.hash()?, transaction_hash.clone()])
        }
    }
}

#[test]
fn nested_array_state_prove_and_verify() {
    let sender = keypair(5);
    let address = sender.shielded_address().expect("sender address");
    let payer = address.solana_address().expect("payer");
    let owner = keypair(6).shielded_address().expect("owner address");
    let input = token_input(&sender, Mint::SOL, 300, 0);
    let limits = Limits {
        daily: 1_000,
        weekly: 5_000,
        per_transfer: 250,
        frozen: false,
        tier: 3,
    };

    let create = PortfolioCreate {
        private: PortfolioCreatePrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: [input],
            nonce: 1,
            limits: limits.clone(),
            balances: [10, 20, 30, 40],
            labels: [7, 8],
        },
        public: PortfolioCreatePublicInputs { owner },
    };
    let spp_proof_inputs = create
        .create_proof_inputs_and_encrypt(&sender, payer, u64::MAX)
        .expect("portfolio create proof inputs");
    let portfolio = Portfolio {
        owner_hash: owner.owner_hash().expect("owner hash"),
        nonce: 1,
        limits,
        balances: [10, 20, 30, 40],
        labels: [7, 8],
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
                Some(owner),
                Mint::SOL,
                0,
                Some(borsh::to_vec(&portfolio).expect("portfolio bytes")),
            ),
        ]
    );

    let prover =
        Groth16Prover::<PortfolioCreate>::new_with_test_setup().expect("portfolio create setup");
    let result = prove(&prover, &create, "portfolio create proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
