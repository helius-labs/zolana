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

pub(crate) const POLL_SLOT: usize = 1;

pub(crate) fn poll_authority() -> ProgramOwner {
    ProgramOwner::new(44)
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Poll {
    pub poll_id: u64,
    pub root: [u8; 32],
    pub tally: [u64; 3],
}

impl zk_program_sdk::circuit::CircuitType for circuit::Poll {}

impl ProofInput for Poll {
    type Circuit = circuit::Poll;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::Poll, RelationError> {
        Ok(circuit::Poll {
            poll_id: self.poll_id.instantiate(allocator)?,
            root: self.root.instantiate(allocator)?,
            tally: self.tally.instantiate(allocator)?,
        })
    }
}

impl FromCircuit for Poll {
    fn from_circuit(circuit: &circuit::Poll) -> Result<Self, RelationError> {
        Ok(Self {
            poll_id: u64::from_circuit(&circuit.poll_id)?,
            root: <[u8; 32]>::from_circuit(&circuit.root)?,
            tally: <[u64; 3]>::from_circuit(&circuit.tally)?,
        })
    }
}

impl Placeholder for Poll {
    fn placeholder() -> Result<Self, RelationError> {
        Ok(Self {
            poll_id: Placeholder::placeholder()?,
            root: Placeholder::placeholder()?,
            tally: Placeholder::placeholder()?,
        })
    }
}

#[derive(Clone)]
struct CreatePoll {
    private: CreatePollPrivateInputs,
    public: CreatePollPublicInputs,
}

#[derive(Clone)]
struct CreatePollPrivateInputs {
    tx_context: TxContext,
    token_utxos_asset_a: [WalletUtxo; 1],
    poll_owner: ShieldedAddress,
}

#[derive(Clone)]
struct CreatePollPublicInputs {
    poll_id: u64,
    root: [u8; 32],
}

impl zk_program_sdk::circuit::CircuitType for circuit::CreatePoll {}

impl ProofInput for CreatePoll {
    type Circuit = circuit::CreatePoll;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::CreatePoll, RelationError> {
        let private = &self.private;
        Ok(circuit::CreatePoll {
            private: circuit::CreatePollPrivateInputs {
                tx_context: private.tx_context.instantiate(allocator)?,
                token_utxos_asset_a: private.token_utxos_asset_a.instantiate(allocator)?,
                poll_owner: private.poll_owner.instantiate(allocator)?,
            },
            public: circuit::CreatePollPublicInputs {
                poll_id: self.public.poll_id.instantiate(allocator)?,
                root: self.public.root.instantiate(allocator)?,
            },
        })
    }
}

impl Placeholder for CreatePoll {
    fn placeholder() -> Result<Self, RelationError> {
        Ok(Self {
            private: CreatePollPrivateInputs {
                tx_context: Placeholder::placeholder()?,
                token_utxos_asset_a: Placeholder::placeholder()?,
                poll_owner: Placeholder::placeholder()?,
            },
            public: CreatePollPublicInputs {
                poll_id: Placeholder::placeholder()?,
                root: Placeholder::placeholder()?,
            },
        })
    }
}

pub(crate) mod circuit {
    use zk_program_sdk::{
        circuit::{
            poseidon, zero, Asset, CheckedTransaction, Circuit, CircuitMarker, CircuitVar,
            ConfidentialTransaction, DataHash, DataUtxo, Owner, PublicInputs, TokenUtxo, TxContext,
            Utxo, UtxoData,
        },
        RelationError,
    };

    #[derive(Clone, Debug)]
    pub struct Poll {
        pub poll_id: CircuitVar,
        pub root: CircuitVar,
        pub tally: [CircuitVar; 3],
    }

    impl Default for Poll {
        fn default() -> Self {
            Self {
                poll_id: zero(),
                root: zero(),
                tally: core::array::from_fn(|_| zero()),
            }
        }
    }

    impl DataHash for Poll {
        fn hash(&self) -> Result<CircuitVar, RelationError> {
            poseidon(&[
                self.poll_id.clone(),
                self.root.clone(),
                poseidon(&self.tally)?,
            ])
        }
    }

    impl UtxoData for Poll {
        type Client = super::Poll;
    }

    pub struct CreatePoll {
        pub private: CreatePollPrivateInputs,
        pub public: CreatePollPublicInputs,
    }

    pub struct CreatePollPrivateInputs {
        pub tx_context: TxContext,
        pub token_utxos_asset_a: [Utxo; 1],
        pub poll_owner: Owner,
    }

    pub struct CreatePollPublicInputs {
        pub poll_id: CircuitVar,
        pub root: CircuitVar,
    }

    impl Circuit for CreatePoll {
        const MARKER: CircuitMarker = CircuitMarker;

        fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
            let private = &self.private;
            let tokens = TokenUtxo::new_mut(&private.token_utxos_asset_a)?;
            let mut poll = DataUtxo::<Poll>::new_init(&private.poll_owner, &Asset::sol());
            poll.poll_id = self.public.poll_id.clone();
            poll.root = self.public.root.clone();

            ConfidentialTransaction::new(&private.tx_context, &self.public)
                .with_token_utxos(tokens)
                .with_data_utxo(poll)
                .check()
        }
    }

    impl PublicInputs for CreatePollPublicInputs {
        fn hash(&self, transaction_hash: &CircuitVar) -> Result<CircuitVar, RelationError> {
            poseidon(&[
                self.poll_id.clone(),
                self.root.clone(),
                transaction_hash.clone(),
            ])
        }
    }
}

pub(crate) fn poll_utxo(
    creator: &ShieldedKeypair,
    poll_id: u64,
    root: [u8; 32],
) -> (WalletUtxo, Poll) {
    let address = creator.shielded_address().expect("creator address");
    let input = token_input(creator, Mint::SOL, 300, 0);
    let spp_proof_inputs = CreatePoll {
        private: CreatePollPrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: [input],
            poll_owner: poll_authority().address(&address),
        },
        public: CreatePollPublicInputs { poll_id, root },
    }
    .create_proof_inputs_and_encrypt(creator, address.solana_address().expect("payer"), u64::MAX)
    .expect("create poll proof inputs");
    let output = spp_proof_inputs
        .output_utxos
        .get(POLL_SLOT)
        .expect("poll output");
    let poll =
        Poll::try_from_slice(output.data.utxo_data().expect("poll data")).expect("poll state");
    (
        poll_authority().input(output, spp_proof_inputs.output_tree_id, 2),
        poll,
    )
}

#[test]
fn create_poll_prove_and_verify() {
    let creator = keypair(5);
    let address = creator.shielded_address().expect("creator address");
    let payer = address.solana_address().expect("payer");
    let poll_owner = poll_authority().address(&address);
    let input = token_input(&creator, Mint::SOL, 300, 0);
    let root = [2u8; 32];

    let create = CreatePoll {
        private: CreatePollPrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: [input],
            poll_owner,
        },
        public: CreatePollPublicInputs { poll_id: 3, root },
    };
    let spp_proof_inputs = create
        .create_proof_inputs_and_encrypt(&creator, payer, u64::MAX)
        .expect("create poll proof inputs");
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
                Some(poll_owner),
                Mint::SOL,
                0,
                Some(
                    borsh::to_vec(&Poll {
                        poll_id: 3,
                        root,
                        tally: [0; 3],
                    })
                    .expect("poll bytes")
                ),
            ),
        ]
    );

    let prover = Groth16Prover::<CreatePoll>::new_with_test_setup().expect("create poll setup");
    let result = prove(&prover, &create, "create poll proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
