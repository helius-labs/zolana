use zk_program_sdk::{
    conversion::{Allocator, Placeholder, ProofInput},
    CircuitError, Groth16Prover, TxContext, ZkProgram,
};
use zolana_keypair::ShieldedAddress;
use zolana_transaction::{Mint, WalletUtxo};

use crate::{
    benchmark::prove,
    shared::{dummy, keypair, token_input},
};

#[derive(Clone)]
struct Sweep {
    private: SweepPrivateInputs,
    public: SweepPublicInputs,
}

#[derive(Clone)]
struct SweepPrivateInputs {
    tx_context: TxContext,
    token_utxos_asset_a: [WalletUtxo; 2],
}

#[derive(Clone)]
struct SweepPublicInputs {
    recipient: ShieldedAddress,
}

impl zk_program_sdk::circuit::CircuitType for circuit::Sweep {}

impl ProofInput for Sweep {
    type Circuit = circuit::Sweep;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::Sweep, CircuitError> {
        let private = &self.private;
        Ok(circuit::Sweep {
            private: circuit::SweepPrivateInputs {
                tx_context: private.tx_context.instantiate(allocator)?,
                token_utxos_asset_a: private.token_utxos_asset_a.instantiate(allocator)?,
            },
            public: circuit::SweepPublicInputs {
                recipient: self.public.recipient.instantiate(allocator)?,
            },
        })
    }
}

impl Placeholder for Sweep {
    fn placeholder() -> Result<Self, CircuitError> {
        Ok(Self {
            private: SweepPrivateInputs {
                tx_context: Placeholder::placeholder()?,
                token_utxos_asset_a: Placeholder::placeholder()?,
            },
            public: SweepPublicInputs {
                recipient: Placeholder::placeholder()?,
            },
        })
    }
}

mod circuit {
    use zk_program_sdk::{
        circuit::{
            poseidon, Balance, CheckedTransaction, Circuit, CircuitVar, ConfidentialTransaction,
            Owner, PublicInputs, TokenUtxo, TxContext, Utxo,
        },
        CircuitError,
    };

    pub struct Sweep {
        pub private: SweepPrivateInputs,
        pub public: SweepPublicInputs,
    }

    pub struct SweepPrivateInputs {
        pub tx_context: TxContext,
        pub token_utxos_asset_a: [Utxo; 2],
    }

    pub struct SweepPublicInputs {
        pub recipient: Owner,
    }

    impl Circuit for Sweep {
        fn circuit(&self) -> Result<CheckedTransaction, CircuitError> {
            let private = &self.private;
            let mut tokens = TokenUtxo::new_burn(&private.token_utxos_asset_a)?;
            let mut sweep = TokenUtxo::new_init(&self.public.recipient, &tokens.asset());
            tokens.transfer_all(&mut sweep)?;

            ConfidentialTransaction::new(&private.tx_context, &self.public)
                .with_token_utxos(tokens)
                .with_token_utxos(sweep)
                .check()
        }
    }

    impl PublicInputs for SweepPublicInputs {
        fn hash(&self, transaction_hash: &CircuitVar) -> Result<CircuitVar, CircuitError> {
            poseidon(&[self.recipient.hash()?, transaction_hash.clone()])
        }
    }
}

#[test]
fn sweep_prove_and_verify() {
    let sender = keypair(5);
    let address = sender.shielded_address().expect("sender address");
    let payer = address.solana_address().expect("payer");
    let recipient = keypair(6).shielded_address().expect("recipient address");
    let input = token_input(&sender, Mint::SOL, 500, 0);

    let sweep = Sweep {
        private: SweepPrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: [input, dummy()],
        },
        public: SweepPublicInputs { recipient },
    };
    let spp_proof_inputs = sweep
        .create_and_encrypt(&address, payer)
        .expect("sweep proof inputs");
    assert_eq!(
        (
            spp_proof_inputs
                .input_utxos
                .iter()
                .map(|input| input.is_dummy())
                .collect::<Vec<_>>(),
            spp_proof_inputs
                .output_utxos
                .iter()
                .map(|output| (output.owner_address, output.asset, output.amount))
                .collect::<Vec<_>>(),
        ),
        (vec![false], vec![(Some(recipient), Mint::SOL, 500)])
    );

    let prover = Groth16Prover::<Sweep>::new_with_test_setup().expect("sweep setup");
    let result = prove(&prover, &sweep, "sweep proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
