use zk_program_sdk::{
    conversion::{Allocator, Placeholder, ProofInput},
    Groth16Prover, RelationError, TxContext, ZkProgram,
};
use zolana_interface::shape::Shape;
use zolana_keypair::ShieldedAddress;
use zolana_transaction::{Mint, WalletUtxo};

use crate::{
    benchmark::prove,
    s22_create_and_update::{Badge, Profile},
    shared::{dummy, keypair, token_input},
};

#[derive(Clone)]
struct CreateTwo {
    private: CreateTwoPrivateInputs,
    public: CreateTwoPublicInputs,
}

#[derive(Clone)]
struct CreateTwoPrivateInputs {
    tx_context: TxContext,
    token_utxos_asset_a: [WalletUtxo; 2],
    score: u64,
    level: u16,
}

#[derive(Clone)]
struct CreateTwoPublicInputs {
    owner: ShieldedAddress,
}

impl zk_program_sdk::circuit::CircuitType for circuit::CreateTwo {}

impl ProofInput for CreateTwo {
    type Circuit = circuit::CreateTwo;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::CreateTwo, RelationError> {
        let private = &self.private;
        Ok(circuit::CreateTwo {
            private: circuit::CreateTwoPrivateInputs {
                tx_context: private.tx_context.instantiate(allocator)?,
                token_utxos_asset_a: private.token_utxos_asset_a.instantiate(allocator)?,
                score: private.score.instantiate(allocator)?,
                level: private.level.instantiate(allocator)?,
            },
            public: circuit::CreateTwoPublicInputs {
                owner: self.public.owner.instantiate(allocator)?,
            },
        })
    }
}

impl Placeholder for CreateTwo {
    fn placeholder() -> Result<Self, RelationError> {
        Ok(Self {
            private: CreateTwoPrivateInputs {
                tx_context: Placeholder::placeholder()?,
                token_utxos_asset_a: Placeholder::placeholder()?,
                score: Placeholder::placeholder()?,
                level: Placeholder::placeholder()?,
            },
            public: CreateTwoPublicInputs {
                owner: Placeholder::placeholder()?,
            },
        })
    }
}

mod circuit {
    use zk_program_sdk::{
        circuit::{
            poseidon, Asset, CheckedTransaction, Circuit, CircuitMarker, CircuitVar,
            ConfidentialTransaction, DataUtxo, Owner, PublicInputs, TokenUtxo, TxContext, Utxo,
        },
        RelationError,
    };

    use crate::s22_create_and_update::circuit::{Badge, Profile};

    pub struct CreateTwo {
        pub private: CreateTwoPrivateInputs,
        pub public: CreateTwoPublicInputs,
    }

    pub struct CreateTwoPrivateInputs {
        pub tx_context: TxContext,
        pub token_utxos_asset_a: [Utxo; 2],
        pub score: CircuitVar,
        pub level: CircuitVar,
    }

    pub struct CreateTwoPublicInputs {
        pub owner: Owner,
    }

    impl Circuit for CreateTwo {
        const MARKER: CircuitMarker = CircuitMarker;

        fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
            let private = &self.private;
            let tokens = TokenUtxo::new_mut(&private.token_utxos_asset_a)?;
            let mut profile = DataUtxo::<Profile>::new_init(&self.public.owner, &Asset::sol());
            profile.score = private.score.clone();
            let mut badge = DataUtxo::<Badge>::new_init(&self.public.owner, &Asset::sol());
            badge.level = private.level.clone();

            ConfidentialTransaction::new(&private.tx_context, &self.public)
                .with_token_utxos(tokens)
                .with_data_utxo(profile)
                .with_data_utxo(badge)
                .check()
        }
    }

    impl PublicInputs for CreateTwoPublicInputs {
        fn hash(&self, transaction_hash: &CircuitVar) -> Result<CircuitVar, RelationError> {
            poseidon(&[self.owner.hash()?, transaction_hash.clone()])
        }
    }
}

#[test]
fn create_two_prove_and_verify() {
    let sender = keypair(5);
    let address = sender.shielded_address().expect("sender address");
    let payer = address.solana_address().expect("payer");
    let input = token_input(&sender, Mint::SOL, 300, 0);

    let create_two = CreateTwo {
        private: CreateTwoPrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: [input, dummy()],
            score: 5,
            level: 1,
        },
        public: CreateTwoPublicInputs { owner: address },
    };
    let spp_proof_inputs = create_two
        .create_proof_inputs_and_encrypt(&sender, payer, u64::MAX)
        .expect("create two proof inputs");
    assert_eq!(
        (
            spp_proof_inputs.check_shape().expect("create two shape"),
            spp_proof_inputs
                .input_utxos
                .iter()
                .map(|input| input.is_dummy())
                .collect::<Vec<_>>(),
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
        ),
        (
            Shape::IN2_OUT3,
            vec![false, true],
            vec![
                (Some(address), Mint::SOL, 300, None),
                (
                    Some(address),
                    Mint::SOL,
                    0,
                    Some(borsh::to_vec(&Profile { score: 5 }).expect("profile bytes")),
                ),
                (
                    Some(address),
                    Mint::SOL,
                    0,
                    Some(borsh::to_vec(&Badge { level: 1 }).expect("badge bytes")),
                ),
            ],
        )
    );

    let prover = Groth16Prover::<CreateTwo>::new_with_test_setup().expect("create two setup");
    let result = prove(&prover, &create_two, "create two proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
