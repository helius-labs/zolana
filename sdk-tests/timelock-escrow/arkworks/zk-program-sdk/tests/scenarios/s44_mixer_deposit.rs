use borsh::{BorshDeserialize, BorshSerialize};
use zk_program_sdk::{
    conversion::{Allocator, FromCircuit, Placeholder, ProofInput},
    Groth16Prover, RelationError, TxContext, ZkProgram,
};
use zolana_keypair::{ShieldedAddress, ShieldedKeypair};
use zolana_transaction::{Mint, WalletUtxo};

use crate::{
    benchmark::prove,
    shared::{keypair, poseidon_bytes, token_input, ProgramOwner},
};

pub(crate) const NOTE_SLOT: usize = 1;
pub(crate) const DENOMINATION: u64 = 100;

pub(crate) fn mixer_authority() -> ProgramOwner {
    ProgramOwner::new(45)
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct MixerCommitment {
    pub commitment: [u8; 32],
}

impl ProofInput for MixerCommitment {
    type Circuit = circuit::MixerCommitment;

    fn instantiate(
        &self,
        allocator: &Allocator,
    ) -> Result<circuit::MixerCommitment, RelationError> {
        Ok(circuit::MixerCommitment {
            commitment: self.commitment.instantiate(allocator)?,
        })
    }
}

impl FromCircuit for MixerCommitment {
    fn from_circuit(circuit: &circuit::MixerCommitment) -> Result<Self, RelationError> {
        Ok(Self {
            commitment: <[u8; 32]>::from_circuit(&circuit.commitment)?,
        })
    }
}

impl Placeholder for MixerCommitment {
    fn placeholder() -> Result<Self, RelationError> {
        Ok(Self {
            commitment: Placeholder::placeholder()?,
        })
    }
}

#[derive(Clone)]
struct MixerDeposit {
    private: MixerDepositPrivateInputs,
    public: MixerDepositPublicInputs,
}

#[derive(Clone)]
struct MixerDepositPrivateInputs {
    tx_context: TxContext,
    token_utxos_asset_a: [WalletUtxo; 1],
    mixer: ShieldedAddress,
    nullifier_secret: [u8; 32],
    secret: [u8; 32],
}

#[derive(Clone)]
struct MixerDepositPublicInputs {
    denomination: u64,
}

impl ProofInput for MixerDeposit {
    type Circuit = circuit::MixerDeposit;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::MixerDeposit, RelationError> {
        let private = &self.private;
        Ok(circuit::MixerDeposit {
            private: circuit::MixerDepositPrivateInputs {
                tx_context: private.tx_context.instantiate(allocator)?,
                token_utxos_asset_a: private.token_utxos_asset_a.instantiate(allocator)?,
                mixer: private.mixer.instantiate(allocator)?,
                nullifier_secret: private.nullifier_secret.instantiate(allocator)?,
                secret: private.secret.instantiate(allocator)?,
            },
            public: circuit::MixerDepositPublicInputs {
                denomination: self.public.denomination.instantiate(allocator)?,
            },
        })
    }
}

impl Placeholder for MixerDeposit {
    fn placeholder() -> Result<Self, RelationError> {
        Ok(Self {
            private: MixerDepositPrivateInputs {
                tx_context: Placeholder::placeholder()?,
                token_utxos_asset_a: Placeholder::placeholder()?,
                mixer: Placeholder::placeholder()?,
                nullifier_secret: Placeholder::placeholder()?,
                secret: Placeholder::placeholder()?,
            },
            public: MixerDepositPublicInputs {
                denomination: Placeholder::placeholder()?,
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
    pub struct MixerCommitment {
        pub commitment: CircuitVar,
    }

    impl Default for MixerCommitment {
        fn default() -> Self {
            Self { commitment: zero() }
        }
    }

    impl DataHash for MixerCommitment {
        fn hash(&self) -> Result<CircuitVar, RelationError> {
            poseidon(std::slice::from_ref(&self.commitment))
        }
    }

    impl UtxoData for MixerCommitment {
        type Client = super::MixerCommitment;
    }

    pub struct MixerDeposit {
        pub private: MixerDepositPrivateInputs,
        pub public: MixerDepositPublicInputs,
    }

    pub struct MixerDepositPrivateInputs {
        pub tx_context: TxContext,
        pub token_utxos_asset_a: [Utxo; 1],
        pub mixer: Owner,
        pub nullifier_secret: CircuitVar,
        pub secret: CircuitVar,
    }

    pub struct MixerDepositPublicInputs {
        pub denomination: CircuitVar,
    }

    impl Circuit for MixerDeposit {
        fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
            let private = &self.private;
            let mut tokens = TokenUtxo::new_mut(&private.token_utxos_asset_a)?;
            let deposit = tokens.transfer(&private.mixer, &self.public.denomination)?;
            let mut note = DataUtxo::<MixerCommitment>::from_output_utxo(deposit);
            note.commitment =
                poseidon(&[private.nullifier_secret.clone(), private.secret.clone()])?;

            ConfidentialTransaction::new(&private.tx_context, &self.public)
                .with_token_utxos(tokens)
                .with_data_utxo(note)
                .check()
        }
    }

    impl PublicInputs for MixerDepositPublicInputs {
        fn hash(&self, transaction_hash: &CircuitVar) -> Result<CircuitVar, RelationError> {
            poseidon(&[self.denomination.clone(), transaction_hash.clone()])
        }
    }
}

pub(crate) fn commitment_utxo(
    depositor: &ShieldedKeypair,
    nullifier_secret: [u8; 32],
    secret: [u8; 32],
) -> (WalletUtxo, MixerCommitment) {
    let address = depositor.shielded_address().expect("depositor address");
    let input = token_input(depositor, Mint::SOL, 300, 0);
    let spp_proof_inputs = MixerDeposit {
        private: MixerDepositPrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: [input],
            mixer: mixer_authority().address(&address),
            nullifier_secret,
            secret,
        },
        public: MixerDepositPublicInputs {
            denomination: DENOMINATION,
        },
    }
    .create_proof_inputs_and_encrypt(
        depositor,
        address.solana_address().expect("payer"),
        u64::MAX,
    )
    .expect("mixer deposit proof inputs");
    let output = spp_proof_inputs
        .output_utxos
        .get(NOTE_SLOT)
        .expect("commitment output");
    let commitment =
        MixerCommitment::try_from_slice(output.data.utxo_data().expect("commitment data"))
            .expect("commitment state");
    (
        mixer_authority().input(output, spp_proof_inputs.output_tree_id, 2),
        commitment,
    )
}

#[test]
fn mixer_deposit_prove_and_verify() {
    let depositor = keypair(5);
    let address = depositor.shielded_address().expect("depositor address");
    let payer = address.solana_address().expect("payer");
    let mixer = mixer_authority().address(&address);
    let input = token_input(&depositor, Mint::SOL, 300, 0);
    let (nullifier_secret, secret) = ([3u8; 32], [4u8; 32]);

    let deposit = MixerDeposit {
        private: MixerDepositPrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: [input],
            mixer,
            nullifier_secret,
            secret,
        },
        public: MixerDepositPublicInputs {
            denomination: DENOMINATION,
        },
    };
    let spp_proof_inputs = deposit
        .create_proof_inputs_and_encrypt(&depositor, payer, u64::MAX)
        .expect("mixer deposit proof inputs");
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
            (Some(address), Mint::SOL, 200, None),
            (
                Some(mixer),
                Mint::SOL,
                DENOMINATION,
                Some(
                    borsh::to_vec(&MixerCommitment {
                        commitment: poseidon_bytes(&[nullifier_secret, secret]),
                    })
                    .expect("commitment bytes")
                ),
            ),
        ]
    );

    let prover = Groth16Prover::<MixerDeposit>::new_with_test_setup().expect("mixer deposit setup");
    let result = prove(&prover, &deposit, "mixer deposit proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
