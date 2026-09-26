use borsh::{BorshDeserialize, BorshSerialize};
use zk_program_sdk::{
    conversion::{Allocator, FromCircuit, Placeholder, ProofInput},
    Groth16Prover, Owner, RelationError, TxContext, ZkProgram,
};
use zolana_keypair::{ShieldedAddress, ShieldedKeypair};
use zolana_transaction::{Mint, WalletUtxo};

use crate::{
    benchmark::prove,
    shared::{keypair, token_input, ProgramOwner},
};

pub(crate) const ESCROW_SLOT: usize = 1;

pub(crate) fn escrow_authority() -> ProgramOwner {
    ProgramOwner::new(40)
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct EscrowTerms {
    pub creator: Owner,
    pub unlock: u64,
}

impl zk_program_sdk::circuit::CircuitType for circuit::EscrowTerms {}

impl ProofInput for EscrowTerms {
    type Circuit = circuit::EscrowTerms;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::EscrowTerms, RelationError> {
        Ok(circuit::EscrowTerms {
            creator: self.creator.instantiate(allocator)?,
            unlock: self.unlock.instantiate(allocator)?,
        })
    }
}

impl FromCircuit for EscrowTerms {
    fn from_circuit(circuit: &circuit::EscrowTerms) -> Result<Self, RelationError> {
        Ok(Self {
            creator: Owner::from_circuit(&circuit.creator)?,
            unlock: u64::from_circuit(&circuit.unlock)?,
        })
    }
}

impl Placeholder for EscrowTerms {
    fn placeholder() -> Result<Self, RelationError> {
        Ok(Self {
            creator: Placeholder::placeholder()?,
            unlock: Placeholder::placeholder()?,
        })
    }
}

#[derive(Clone)]
pub(crate) struct Escrow {
    pub(crate) private: EscrowPrivateInputs,
    pub(crate) public: EscrowPublicInputs,
}

#[derive(Clone)]
pub(crate) struct EscrowPrivateInputs {
    pub(crate) tx_context: TxContext,
    pub(crate) token_utxos_asset_a: [WalletUtxo; 2],
    pub(crate) unlock: u64,
    pub(crate) amount: u64,
}

#[derive(Clone)]
pub(crate) struct EscrowPublicInputs {
    pub(crate) escrow_owner: ShieldedAddress,
}

impl zk_program_sdk::circuit::CircuitType for circuit::Escrow {}

impl ProofInput for Escrow {
    type Circuit = circuit::Escrow;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::Escrow, RelationError> {
        let private = &self.private;
        Ok(circuit::Escrow {
            private: circuit::EscrowPrivateInputs {
                tx_context: private.tx_context.instantiate(allocator)?,
                token_utxos_asset_a: private.token_utxos_asset_a.instantiate(allocator)?,
                unlock: private.unlock.instantiate(allocator)?,
                amount: private.amount.instantiate(allocator)?,
            },
            public: circuit::EscrowPublicInputs {
                escrow_owner: self.public.escrow_owner.instantiate(allocator)?,
            },
        })
    }
}

impl Placeholder for Escrow {
    fn placeholder() -> Result<Self, RelationError> {
        Ok(Self {
            private: EscrowPrivateInputs {
                tx_context: Placeholder::placeholder()?,
                token_utxos_asset_a: Placeholder::placeholder()?,
                unlock: Placeholder::placeholder()?,
                amount: Placeholder::placeholder()?,
            },
            public: EscrowPublicInputs {
                escrow_owner: Placeholder::placeholder()?,
            },
        })
    }
}

pub(crate) mod circuit {
    use zk_program_sdk::{
        circuit::{
            poseidon, zero, Assert, Balance, CheckedTransaction, Circuit, CircuitMarker,
            CircuitVar, ConfidentialTransaction, DataHash, DataUtxo, Owner, PublicInputs,
            TokenUtxo, TxContext, Utxo, UtxoData,
        },
        RelationError,
    };

    #[derive(Clone, Debug)]
    pub struct EscrowTerms {
        pub creator: Owner,
        pub unlock: CircuitVar,
    }

    impl Default for EscrowTerms {
        fn default() -> Self {
            Self {
                creator: Owner::default(),
                unlock: zero(),
            }
        }
    }

    impl DataHash for EscrowTerms {
        fn hash(&self) -> Result<CircuitVar, RelationError> {
            poseidon(&[self.creator.hash()?, self.unlock.hash()?])
        }
    }

    impl UtxoData for EscrowTerms {
        type Client = super::EscrowTerms;
    }

    pub struct Escrow {
        pub private: EscrowPrivateInputs,
        pub public: EscrowPublicInputs,
    }

    pub struct EscrowPrivateInputs {
        pub tx_context: TxContext,
        pub token_utxos_asset_a: [Utxo; 2],
        pub unlock: CircuitVar,
        pub amount: CircuitVar,
    }

    pub struct EscrowPublicInputs {
        pub escrow_owner: Owner,
    }

    impl Circuit for Escrow {
        const MARKER: CircuitMarker = CircuitMarker;

        fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
            let private = &self.private;
            private
                .amount
                .assert_not_equal(&zero(), "the escrow locks nothing")?;
            let mut tokens = TokenUtxo::new_mut(&private.token_utxos_asset_a)?;
            let mut escrow =
                DataUtxo::<EscrowTerms>::new_init(&self.public.escrow_owner, &tokens.asset());
            tokens.transfer(&mut escrow, &private.amount)?;
            escrow.creator = tokens.owner();
            escrow.unlock = private.unlock.clone();

            ConfidentialTransaction::new(&private.tx_context, &self.public)
                .with_token_utxos(tokens)
                .with_data_utxo(escrow)
                .check()
        }
    }

    impl PublicInputs for EscrowPublicInputs {
        fn hash(&self, transaction_hash: &CircuitVar) -> Result<CircuitVar, RelationError> {
            poseidon(&[self.escrow_owner.hash()?, transaction_hash.clone()])
        }
    }
}

pub(crate) fn escrow_utxo(
    creator: &ShieldedKeypair,
    mint: Mint,
    amount: u64,
    unlock: u64,
) -> (WalletUtxo, EscrowTerms) {
    let address = creator.shielded_address().expect("creator address");
    let first = token_input(creator, mint, amount, 0);
    let spp_proof_inputs = Escrow {
        private: EscrowPrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: [first, token_input(creator, mint, 100, 1)],
            unlock,
            amount,
        },
        public: EscrowPublicInputs {
            escrow_owner: escrow_authority().address(&address),
        },
    }
    .create_proof_inputs_and_encrypt(creator, address.solana_address().expect("payer"), u64::MAX)
    .expect("escrow proof inputs");
    let output = spp_proof_inputs
        .output_utxos
        .get(ESCROW_SLOT)
        .expect("escrow output");
    let terms = EscrowTerms::try_from_slice(output.data.utxo_data().expect("escrow data"))
        .expect("escrow terms");
    (
        escrow_authority().input(output, spp_proof_inputs.output_tree_id, 2),
        terms,
    )
}

#[test]
fn escrow_prove_and_verify() {
    let creator = keypair(5);
    let address = creator.shielded_address().expect("creator address");
    let payer = address.solana_address().expect("payer");
    let escrow_owner = escrow_authority().address(&address);
    let first = token_input(&creator, Mint::SOL, 600, 0);
    let second = token_input(&creator, Mint::SOL, 400, 1);

    let escrow = Escrow {
        private: EscrowPrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: [first, second],
            unlock: 1_700_000_000,
            amount: 250,
        },
        public: EscrowPublicInputs { escrow_owner },
    };
    let spp_proof_inputs = escrow
        .create_proof_inputs_and_encrypt(&creator, payer, u64::MAX)
        .expect("escrow proof inputs");
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
            (Some(address), Mint::SOL, 750, None),
            (
                Some(escrow_owner),
                Mint::SOL,
                250,
                Some(
                    borsh::to_vec(&EscrowTerms {
                        creator: Owner::try_from(&address).expect("creator owner"),
                        unlock: 1_700_000_000,
                    })
                    .expect("escrow terms bytes")
                ),
            ),
        ]
    );

    let prover = Groth16Prover::<Escrow>::new_with_test_setup().expect("escrow setup");
    let result = prove(&prover, &escrow, "escrow proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
