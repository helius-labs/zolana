use borsh::{BorshDeserialize, BorshSerialize};
use zk_program_sdk::{
    conversion::{Allocator, FromCircuit, Placeholder, ProofInput},
    Groth16Prover, RelationError, TxContext, ZkProgram,
};
use zolana_keypair::{ShieldedAddress, ShieldedKeypair};
use zolana_transaction::{Mint, WalletUtxo};

use crate::{
    benchmark::prove,
    shared::{keypair, token_input, ProgramOwner},
};

pub(crate) const POOL_SLOT: usize = 1;

pub(crate) fn airdrop_authority() -> ProgramOwner {
    ProgramOwner::new(42)
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Pool {
    pub root: [u8; 32],
    pub airdrop_id: u64,
}

impl ProofInput for Pool {
    type Circuit = circuit::Pool;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::Pool, RelationError> {
        Ok(circuit::Pool {
            root: self.root.instantiate(allocator)?,
            airdrop_id: self.airdrop_id.instantiate(allocator)?,
        })
    }
}

impl FromCircuit for Pool {
    fn from_circuit(circuit: &circuit::Pool) -> Result<Self, RelationError> {
        Ok(Self {
            root: <[u8; 32]>::from_circuit(&circuit.root)?,
            airdrop_id: u64::from_circuit(&circuit.airdrop_id)?,
        })
    }
}

impl Placeholder for Pool {
    fn placeholder() -> Result<Self, RelationError> {
        Ok(Self {
            root: Placeholder::placeholder()?,
            airdrop_id: Placeholder::placeholder()?,
        })
    }
}

#[derive(Clone)]
struct CreatePool {
    private: CreatePoolPrivateInputs,
    public: CreatePoolPublicInputs,
}

#[derive(Clone)]
struct CreatePoolPrivateInputs {
    tx_context: TxContext,
    token_utxos_asset_a: [WalletUtxo; 1],
    amount: u64,
    pool_owner: ShieldedAddress,
}

#[derive(Clone)]
struct CreatePoolPublicInputs {
    root: [u8; 32],
    airdrop_id: u64,
}

impl ProofInput for CreatePool {
    type Circuit = circuit::CreatePool;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::CreatePool, RelationError> {
        let private = &self.private;
        Ok(circuit::CreatePool {
            private: circuit::CreatePoolPrivateInputs {
                tx_context: private.tx_context.instantiate(allocator)?,
                token_utxos_asset_a: private.token_utxos_asset_a.instantiate(allocator)?,
                amount: private.amount.instantiate(allocator)?,
                pool_owner: private.pool_owner.instantiate(allocator)?,
            },
            public: circuit::CreatePoolPublicInputs {
                root: self.public.root.instantiate(allocator)?,
                airdrop_id: self.public.airdrop_id.instantiate(allocator)?,
            },
        })
    }
}

impl Placeholder for CreatePool {
    fn placeholder() -> Result<Self, RelationError> {
        Ok(Self {
            private: CreatePoolPrivateInputs {
                tx_context: Placeholder::placeholder()?,
                token_utxos_asset_a: Placeholder::placeholder()?,
                amount: Placeholder::placeholder()?,
                pool_owner: Placeholder::placeholder()?,
            },
            public: CreatePoolPublicInputs {
                root: Placeholder::placeholder()?,
                airdrop_id: Placeholder::placeholder()?,
            },
        })
    }
}

pub(crate) mod circuit {
    use zk_program_sdk::{
        circuit::{
            poseidon, zero, Balance, CheckedTransaction, Circuit, CircuitVar,
            ConfidentialTransaction, DataHash, DataUtxo, Owner, PublicInputs, TokenUtxo, TxContext,
            Utxo, UtxoData,
        },
        RelationError,
    };

    #[derive(Clone, Debug)]
    pub struct Pool {
        pub root: CircuitVar,
        pub airdrop_id: CircuitVar,
    }

    impl Default for Pool {
        fn default() -> Self {
            Self {
                root: zero(),
                airdrop_id: zero(),
            }
        }
    }

    impl DataHash for Pool {
        fn hash(&self) -> Result<CircuitVar, RelationError> {
            poseidon(&[self.root.clone(), self.airdrop_id.clone()])
        }
    }

    impl UtxoData for Pool {
        type Client = super::Pool;
    }

    pub struct CreatePool {
        pub private: CreatePoolPrivateInputs,
        pub public: CreatePoolPublicInputs,
    }

    pub struct CreatePoolPrivateInputs {
        pub tx_context: TxContext,
        pub token_utxos_asset_a: [Utxo; 1],
        pub amount: CircuitVar,
        pub pool_owner: Owner,
    }

    pub struct CreatePoolPublicInputs {
        pub root: CircuitVar,
        pub airdrop_id: CircuitVar,
    }

    impl Circuit for CreatePool {
        fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
            let private = &self.private;
            let mut tokens = TokenUtxo::new_mut(&private.token_utxos_asset_a)?;
            let funded = tokens.transfer(&private.pool_owner, &private.amount)?;
            let mut pool = DataUtxo::<Pool>::from_output_utxo(funded);
            pool.root = self.public.root.clone();
            pool.airdrop_id = self.public.airdrop_id.clone();

            ConfidentialTransaction::new(&private.tx_context, &self.public)
                .with_token_utxos(tokens)
                .with_data_utxo(pool)
                .check()
        }
    }

    impl PublicInputs for CreatePoolPublicInputs {
        fn hash(&self, transaction_hash: &CircuitVar) -> Result<CircuitVar, RelationError> {
            poseidon(&[
                self.root.clone(),
                self.airdrop_id.clone(),
                transaction_hash.clone(),
            ])
        }
    }
}

pub(crate) fn pool_utxo(
    funder: &ShieldedKeypair,
    amount: u64,
    root: [u8; 32],
    airdrop_id: u64,
) -> (WalletUtxo, Pool) {
    let address = funder.shielded_address().expect("funder address");
    let input = token_input(funder, Mint::SOL, amount + 100, 0);
    let spp_proof_inputs = CreatePool {
        private: CreatePoolPrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: [input],
            amount,
            pool_owner: airdrop_authority().address(&address),
        },
        public: CreatePoolPublicInputs { root, airdrop_id },
    }
    .create_proof_inputs_and_encrypt(funder, address.solana_address().expect("payer"), u64::MAX)
    .expect("pool proof inputs");
    let output = spp_proof_inputs
        .output_utxos
        .get(POOL_SLOT)
        .expect("pool output");
    let pool =
        Pool::try_from_slice(output.data.utxo_data().expect("pool data")).expect("pool state");
    (
        airdrop_authority().input(output, spp_proof_inputs.output_tree_id, 2),
        pool,
    )
}

#[test]
fn airdrop_pool_prove_and_verify() {
    let funder = keypair(5);
    let address = funder.shielded_address().expect("funder address");
    let payer = address.solana_address().expect("payer");
    let pool_owner = airdrop_authority().address(&address);
    let input = token_input(&funder, Mint::SOL, 1_000, 0);
    let root = [2u8; 32];

    let create = CreatePool {
        private: CreatePoolPrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: [input],
            amount: 600,
            pool_owner,
        },
        public: CreatePoolPublicInputs {
            root,
            airdrop_id: 12,
        },
    };
    let spp_proof_inputs = create
        .create_proof_inputs_and_encrypt(&funder, payer, u64::MAX)
        .expect("pool proof inputs");
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
            (Some(address), Mint::SOL, 400, None),
            (
                Some(pool_owner),
                Mint::SOL,
                600,
                Some(
                    borsh::to_vec(&Pool {
                        root,
                        airdrop_id: 12
                    })
                    .expect("pool bytes")
                ),
            ),
        ]
    );

    let prover = Groth16Prover::<CreatePool>::new_with_test_setup().expect("pool setup");
    let result = prove(&prover, &create, "pool proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
