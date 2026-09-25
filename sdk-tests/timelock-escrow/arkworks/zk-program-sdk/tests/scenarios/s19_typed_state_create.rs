use borsh::{BorshDeserialize, BorshSerialize};
use zk_program_sdk::{
    conversion::{Allocator, FromCircuit, Placeholder, ProofInput},
    Groth16Prover, RelationError, TxContext, ZkProgram,
};
use zolana_hasher::primitives::hash_bytes;
use zolana_keypair::ShieldedAddress;
use zolana_transaction::{Mint, WalletUtxo};

use crate::{
    benchmark::prove,
    shared::{keypair, token_input, USDC},
};

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct TypedState {
    pub amount: u64,
    pub count: u32,
    pub kind: u16,
    pub active: bool,
    pub tag: [u8; 32],
    pub owner_hash: [u8; 32],
    pub asset_hash: [u8; 32],
}

impl ProofInput for TypedState {
    type Circuit = circuit::TypedState;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::TypedState, RelationError> {
        Ok(circuit::TypedState {
            amount: self.amount.instantiate(allocator)?,
            count: self.count.instantiate(allocator)?,
            kind: self.kind.instantiate(allocator)?,
            active: self.active.instantiate(allocator)?,
            tag: self.tag.instantiate(allocator)?,
            owner_hash: self.owner_hash.instantiate(allocator)?,
            asset_hash: self.asset_hash.instantiate(allocator)?,
        })
    }
}

impl FromCircuit for TypedState {
    fn from_circuit(circuit: &circuit::TypedState) -> Result<Self, RelationError> {
        Ok(Self {
            amount: u64::from_circuit(&circuit.amount)?,
            count: u32::from_circuit(&circuit.count)?,
            kind: u16::from_circuit(&circuit.kind)?,
            active: bool::from_circuit(&circuit.active)?,
            tag: <[u8; 32]>::from_circuit(&circuit.tag)?,
            owner_hash: <[u8; 32]>::from_circuit(&circuit.owner_hash)?,
            asset_hash: <[u8; 32]>::from_circuit(&circuit.asset_hash)?,
        })
    }
}

impl Placeholder for TypedState {
    fn placeholder() -> Result<Self, RelationError> {
        Ok(Self {
            amount: Placeholder::placeholder()?,
            count: Placeholder::placeholder()?,
            kind: Placeholder::placeholder()?,
            active: Placeholder::placeholder()?,
            tag: Placeholder::placeholder()?,
            owner_hash: Placeholder::placeholder()?,
            asset_hash: Placeholder::placeholder()?,
        })
    }
}

#[derive(Clone)]
struct TypedCreate {
    private: TypedCreatePrivateInputs,
    public: TypedCreatePublicInputs,
}

#[derive(Clone)]
struct TypedCreatePrivateInputs {
    tx_context: TxContext,
    token_utxos_asset_a: [WalletUtxo; 1],
    owner: ShieldedAddress,
    mint: Mint,
    count: u32,
    kind: u16,
    active: bool,
    tag: [u8; 32],
}

#[derive(Clone)]
struct TypedCreatePublicInputs {
    amount: u64,
}

impl ProofInput for TypedCreate {
    type Circuit = circuit::TypedCreate;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::TypedCreate, RelationError> {
        let private = &self.private;
        Ok(circuit::TypedCreate {
            private: circuit::TypedCreatePrivateInputs {
                tx_context: private.tx_context.instantiate(allocator)?,
                token_utxos_asset_a: private.token_utxos_asset_a.instantiate(allocator)?,
                owner: private.owner.instantiate(allocator)?,
                mint: private.mint.instantiate(allocator)?,
                count: private.count.instantiate(allocator)?,
                kind: private.kind.instantiate(allocator)?,
                active: private.active.instantiate(allocator)?,
                tag: private.tag.instantiate(allocator)?,
            },
            public: circuit::TypedCreatePublicInputs {
                amount: self.public.amount.instantiate(allocator)?,
            },
        })
    }
}

impl Placeholder for TypedCreate {
    fn placeholder() -> Result<Self, RelationError> {
        Ok(Self {
            private: TypedCreatePrivateInputs {
                tx_context: Placeholder::placeholder()?,
                token_utxos_asset_a: Placeholder::placeholder()?,
                owner: Placeholder::placeholder()?,
                mint: Placeholder::placeholder()?,
                count: Placeholder::placeholder()?,
                kind: Placeholder::placeholder()?,
                active: Placeholder::placeholder()?,
                tag: Placeholder::placeholder()?,
            },
            public: TypedCreatePublicInputs {
                amount: Placeholder::placeholder()?,
            },
        })
    }
}

pub(crate) mod circuit {
    use zk_program_sdk::{
        circuit::{
            poseidon, zero, Asset, Bool, CheckedTransaction, Circuit, CircuitVar,
            ConfidentialTransaction, DataHash, DataUtxo, Owner, PublicInputs, TokenUtxo, TxContext,
            Utxo, UtxoData,
        },
        RelationError,
    };

    #[derive(Clone, Debug)]
    pub struct TypedState {
        pub amount: CircuitVar,
        pub count: CircuitVar,
        pub kind: CircuitVar,
        pub active: Bool,
        pub tag: CircuitVar,
        pub owner_hash: CircuitVar,
        pub asset_hash: CircuitVar,
    }

    impl Default for TypedState {
        fn default() -> Self {
            Self {
                amount: zero(),
                count: zero(),
                kind: zero(),
                active: Bool::constant(false),
                tag: zero(),
                owner_hash: zero(),
                asset_hash: zero(),
            }
        }
    }

    impl DataHash for TypedState {
        fn hash(&self) -> Result<CircuitVar, RelationError> {
            poseidon(&[
                self.amount.clone(),
                self.count.clone(),
                self.kind.clone(),
                self.active.var(),
                self.tag.clone(),
                self.owner_hash.clone(),
                self.asset_hash.clone(),
            ])
        }
    }

    impl UtxoData for TypedState {
        type Client = super::TypedState;
    }

    pub struct TypedCreate {
        pub private: TypedCreatePrivateInputs,
        pub public: TypedCreatePublicInputs,
    }

    pub struct TypedCreatePrivateInputs {
        pub tx_context: TxContext,
        pub token_utxos_asset_a: [Utxo; 1],
        pub owner: Owner,
        pub mint: Asset,
        pub count: CircuitVar,
        pub kind: CircuitVar,
        pub active: Bool,
        pub tag: CircuitVar,
    }

    pub struct TypedCreatePublicInputs {
        pub amount: CircuitVar,
    }

    impl Circuit for TypedCreate {
        fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
            let private = &self.private;
            let tokens = TokenUtxo::new_mut(&private.token_utxos_asset_a)?;
            let mut state = DataUtxo::<TypedState>::new_init(&private.owner);
            state.amount = self.public.amount.clone();
            state.count = private.count.clone();
            state.kind = private.kind.clone();
            state.active = private.active.clone();
            state.tag = private.tag.clone();
            state.owner_hash = private.owner.hash()?;
            state.asset_hash = private.mint.hash()?;

            ConfidentialTransaction::new(&private.tx_context, &self.public)
                .with_token_utxos(tokens)
                .with_data_utxo(state)
                .check()
        }
    }

    impl PublicInputs for TypedCreatePublicInputs {
        fn hash(&self, transaction_hash: &CircuitVar) -> Result<CircuitVar, RelationError> {
            poseidon(&[self.amount.clone(), transaction_hash.clone()])
        }
    }
}

#[test]
fn typed_state_create_prove_and_verify() {
    let sender = keypair(5);
    let address = sender.shielded_address().expect("sender address");
    let payer = address.solana_address().expect("payer");
    let input = token_input(&sender, Mint::SOL, 300, 0);

    let create = TypedCreate {
        private: TypedCreatePrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: [input],
            owner: address,
            mint: USDC,
            count: 7,
            kind: 2,
            active: true,
            tag: [7u8; 32],
        },
        public: TypedCreatePublicInputs { amount: 1_000 },
    };
    let spp_proof_inputs = create
        .create_proof_inputs_and_encrypt(&sender, payer, u64::MAX)
        .expect("typed create proof inputs");
    let state = TypedState {
        amount: 1_000,
        count: 7,
        kind: 2,
        active: true,
        tag: [7u8; 32],
        owner_hash: address.owner_hash().expect("owner hash"),
        asset_hash: hash_bytes(USDC.asset.as_array()).expect("asset hash"),
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
                Some(borsh::to_vec(&state).expect("state bytes")),
            ),
        ]
    );

    let prover = Groth16Prover::<TypedCreate>::new_with_test_setup().expect("typed create setup");
    let result = prove(&prover, &create, "typed create proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
