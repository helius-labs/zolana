use zk_program_sdk::{
    conversion::{Allocator, Placeholder, ProofInput},
    Groth16Prover, RelationError, TxContext, ZkProgram,
};
use zolana_keypair::ShieldedAddress;
use zolana_transaction::{Mint, WalletUtxo};

use crate::shared::{keypair, token_input};

#[derive(Clone)]
pub(crate) struct Payment {
    pub(crate) private: PaymentPrivateInputs,
    pub(crate) public: PaymentPublicInputs,
}

#[derive(Clone)]
pub(crate) struct PaymentPrivateInputs {
    pub(crate) tx_context: TxContext,
    pub(crate) token_utxos_asset_a: [WalletUtxo; 2],
    pub(crate) amount: u64,
}

#[derive(Clone)]
pub(crate) struct PaymentPublicInputs {
    pub(crate) recipient: ShieldedAddress,
}

impl ProofInput for Payment {
    type Circuit = circuit::Payment;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::Payment, RelationError> {
        let private = &self.private;
        Ok(circuit::Payment {
            private: circuit::PaymentPrivateInputs {
                tx_context: private.tx_context.instantiate(allocator)?,
                token_utxos_asset_a: private.token_utxos_asset_a.instantiate(allocator)?,
                amount: private.amount.instantiate(allocator)?,
            },
            public: circuit::PaymentPublicInputs {
                recipient: self.public.recipient.instantiate(allocator)?,
            },
        })
    }
}

impl Placeholder for Payment {
    fn placeholder() -> Result<Self, RelationError> {
        Ok(Self {
            private: PaymentPrivateInputs {
                tx_context: Placeholder::placeholder()?,
                token_utxos_asset_a: Placeholder::placeholder()?,
                amount: Placeholder::placeholder()?,
            },
            public: PaymentPublicInputs {
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
        RelationError,
    };

    pub struct Payment {
        pub private: PaymentPrivateInputs,
        pub public: PaymentPublicInputs,
    }

    pub struct PaymentPrivateInputs {
        pub tx_context: TxContext,
        pub token_utxos_asset_a: [Utxo; 2],
        pub amount: CircuitVar,
    }

    pub struct PaymentPublicInputs {
        pub recipient: Owner,
    }

    impl Circuit for Payment {
        fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
            let private = &self.private;
            let mut tokens = TokenUtxo::new_mut(&private.token_utxos_asset_a)?;
            let payment = tokens.transfer(&self.public.recipient, &private.amount)?;

            ConfidentialTransaction::new(&private.tx_context, &self.public)
                .with_token_utxos(tokens)
                .with_output_token_utxo(payment)
                .check()
        }
    }

    impl PublicInputs for PaymentPublicInputs {
        fn hash(&self, transaction_hash: &CircuitVar) -> Result<CircuitVar, RelationError> {
            poseidon(&[self.recipient.hash()?, transaction_hash.clone()])
        }
    }
}

#[test]
fn sol_payment_prove_and_verify() {
    let sender = keypair(5);
    let address = sender.shielded_address().expect("sender address");
    let payer = address.solana_address().expect("payer");
    let recipient = keypair(6).shielded_address().expect("recipient address");
    let first = token_input(&sender, Mint::SOL, 300, 0);
    let second = token_input(&sender, Mint::SOL, 200, 1);

    let payment = Payment {
        private: PaymentPrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: [first, second],
            amount: 400,
        },
        public: PaymentPublicInputs { recipient },
    };
    let spp_proof_inputs = payment
        .create_proof_inputs_and_encrypt(&sender, payer, u64::MAX)
        .expect("payment proof inputs");
    assert_eq!(
        spp_proof_inputs
            .output_utxos
            .iter()
            .map(|output| (output.owner_address, output.asset, output.amount))
            .collect::<Vec<_>>(),
        vec![
            (Some(address), Mint::SOL, 100),
            (Some(recipient), Mint::SOL, 400),
        ]
    );

    let prover = Groth16Prover::<Payment>::new_with_test_setup().expect("payment setup");
    let result = prover.prove(&payment).expect("payment proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
