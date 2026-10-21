use zolana_keypair::ShieldedAddress;
use zolana_program::{
    conversion::{Allocator, Placeholder, ProofInput},
    CircuitError, Groth16Prover, TxContext, ZkCircuit, ZkProgramCircuit,
};
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

impl zolana_program::circuit::CircuitType for circuit::Sweep {}

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
                recipient: self
                    .public
                    .recipient
                    .instantiate(allocator)?
                    .owner()
                    .clone(),
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
    use zolana_program::{
        circuit::{
            poseidon, CheckedTransaction, Circuit, CircuitVar, ConfidentialTransaction,
            PublicInputs, TokenUtxos, TxContext, Utxo, UtxoOwner, UtxoTrait,
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
        pub recipient: UtxoOwner,
    }

    impl Circuit for Sweep {
        type Output = CheckedTransaction;

        fn circuit(&self) -> Result<Self::Output, CircuitError> {
            let private = &self.private;
            let mut tokens = TokenUtxos::new_mut(&private.token_utxos_asset_a)?.close();
            let mut sweep = TokenUtxos::new_init(&self.public.recipient, &tokens.asset());
            tokens.transfer_all(&mut sweep)?;

            ConfidentialTransaction::new(&private.tx_context, &self.public)
                .with(tokens)
                .with(sweep)
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
        .create_proof_inputs_and_encrypt(&address, payer)
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
        (
            vec![false],
            vec![(Some(recipient), Mint::SOL, 500), (None, Mint::SOL, 0)]
        )
    );

    let prover = Groth16Prover::<Sweep>::new_with_test_setup().expect("sweep setup");
    let result = prove(&prover, &sweep, "sweep proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}

#[test]
fn sweep_cannot_prove_an_output_above_u64_max() {
    let sender = keypair(5);
    let sweep = Sweep {
        private: SweepPrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: [
                token_input(&sender, Mint::SOL, u64::MAX, 0),
                token_input(&sender, Mint::SOL, 1, 1),
            ],
        },
        public: SweepPublicInputs {
            recipient: keypair(6).shielded_address().unwrap(),
        },
    };
    let error = sweep
        .check_constraints()
        .expect_err("an output must fit in u64");
    assert_eq!(error.name(), "CircuitError.RuleBroken");
    assert_eq!(
        error.broken_rule(),
        Some("the balance does not fit in 64 bits")
    );
}
