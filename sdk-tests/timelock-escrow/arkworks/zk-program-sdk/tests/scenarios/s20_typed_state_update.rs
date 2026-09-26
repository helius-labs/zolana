use zk_program_sdk::{
    conversion::{Allocator, Placeholder, ProofInput},
    Groth16Prover, RelationError, TxContext, ZkProgram,
};
use zolana_hasher::primitives::hash_bytes;
use zolana_keypair::ShieldedAddress;
use zolana_transaction::{Mint, WalletUtxo};

use crate::{
    benchmark::prove,
    s19_typed_state_create::TypedState,
    shared::{data_input, keypair, poseidon_bytes, BONK, USDC},
};

#[derive(Clone)]
struct TypedUpdate {
    private: TypedUpdatePrivateInputs,
    public: TypedUpdatePublicInputs,
}

#[derive(Clone)]
struct TypedUpdatePrivateInputs {
    tx_context: TxContext,
    state_utxo: WalletUtxo,
    state: TypedState,
    delta: u64,
    new_owner: ShieldedAddress,
    new_mint: Mint,
}

#[derive(Clone)]
struct TypedUpdatePublicInputs {
    count: u32,
}

impl zk_program_sdk::circuit::CircuitType for circuit::TypedUpdate {}

impl ProofInput for TypedUpdate {
    type Circuit = circuit::TypedUpdate;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::TypedUpdate, RelationError> {
        let private = &self.private;
        Ok(circuit::TypedUpdate {
            private: circuit::TypedUpdatePrivateInputs {
                tx_context: private.tx_context.instantiate(allocator)?,
                state_utxo: private.state_utxo.instantiate(allocator)?,
                state: private.state.instantiate(allocator)?,
                delta: private.delta.instantiate(allocator)?,
                new_owner: private.new_owner.instantiate(allocator)?,
                new_mint: private.new_mint.instantiate(allocator)?,
            },
            public: circuit::TypedUpdatePublicInputs {
                count: self.public.count.instantiate(allocator)?,
            },
        })
    }
}

impl Placeholder for TypedUpdate {
    fn placeholder() -> Result<Self, RelationError> {
        Ok(Self {
            private: TypedUpdatePrivateInputs {
                tx_context: Placeholder::placeholder()?,
                state_utxo: Placeholder::placeholder()?,
                state: Placeholder::placeholder()?,
                delta: Placeholder::placeholder()?,
                new_owner: Placeholder::placeholder()?,
                new_mint: Placeholder::placeholder()?,
            },
            public: TypedUpdatePublicInputs {
                count: Placeholder::placeholder()?,
            },
        })
    }
}

mod circuit {
    use zk_program_sdk::{
        circuit::{
            constant, poseidon, Asset, Bits, CheckedTransaction, Circuit, CircuitMarker,
            CircuitVar, ConfidentialTransaction, DataUtxo, Owner, PublicInputs, TxContext, Utxo,
        },
        RelationError,
    };

    use crate::s19_typed_state_create::circuit::TypedState;

    pub struct TypedUpdate {
        pub private: TypedUpdatePrivateInputs,
        pub public: TypedUpdatePublicInputs,
    }

    pub struct TypedUpdatePrivateInputs {
        pub tx_context: TxContext,
        pub state_utxo: Utxo,
        pub state: TypedState,
        pub delta: CircuitVar,
        pub new_owner: Owner,
        pub new_mint: Asset,
    }

    pub struct TypedUpdatePublicInputs {
        pub count: CircuitVar,
    }

    impl Circuit for TypedUpdate {
        const MARKER: CircuitMarker = CircuitMarker;

        fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
            let private = &self.private;
            let mut state = DataUtxo::new_mut(&private.state_utxo, &private.state)?;
            state.amount = state.amount.clone() + &private.delta;
            state.amount.check_bits(64)?;
            state.count = self.public.count.clone();
            state.count.check_bits(32)?;
            state.kind = state.kind.clone() + constant(1u64);
            state.kind.check_bits(16)?;
            state.active = state.active.not();
            state.tag = poseidon(&[state.tag.clone()])?;
            state.owner_hash = private.new_owner.hash()?;
            state.asset_hash = private.new_mint.hash()?;

            ConfidentialTransaction::new(&private.tx_context, &self.public)
                .with_data_utxo(state)
                .check()
        }
    }

    impl PublicInputs for TypedUpdatePublicInputs {
        fn hash(&self, transaction_hash: &CircuitVar) -> Result<CircuitVar, RelationError> {
            poseidon(&[self.count.clone(), transaction_hash.clone()])
        }
    }
}

#[test]
fn typed_state_update_prove_and_verify() {
    let owner = keypair(5);
    let address = owner.shielded_address().expect("owner address");
    let payer = address.solana_address().expect("payer");
    let new_owner = keypair(6).shielded_address().expect("new owner address");
    let state = TypedState {
        amount: 1_000,
        count: 7,
        kind: 2,
        active: true,
        tag: [7u8; 32],
        owner_hash: address.owner_hash().expect("owner hash"),
        asset_hash: hash_bytes(USDC.asset.as_array()).expect("asset hash"),
    };
    let state_utxo = data_input(&owner, 0, &state, 0);

    let update = TypedUpdate {
        private: TypedUpdatePrivateInputs {
            tx_context: TxContext::new(),
            state_utxo,
            state,
            delta: 250,
            new_owner,
            new_mint: BONK,
        },
        public: TypedUpdatePublicInputs { count: 9 },
    };
    let spp_proof_inputs = update
        .create_proof_inputs_and_encrypt(&owner, payer, u64::MAX)
        .expect("typed update proof inputs");
    let updated = TypedState {
        amount: 1_250,
        count: 9,
        kind: 3,
        active: false,
        tag: poseidon_bytes(&[[7u8; 32]]),
        owner_hash: new_owner.owner_hash().expect("new owner hash"),
        asset_hash: hash_bytes(BONK.asset.as_array()).expect("new asset hash"),
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
        vec![(
            Some(address),
            Mint::SOL,
            0,
            Some(borsh::to_vec(&updated).expect("state bytes")),
        )]
    );

    let prover = Groth16Prover::<TypedUpdate>::new_with_test_setup().expect("typed update setup");
    let result = prove(&prover, &update, "typed update proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
