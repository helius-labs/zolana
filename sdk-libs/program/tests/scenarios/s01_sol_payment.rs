use spr_keypair::{ShieldedAddress, ViewingKey};
use spr_program::{
    conversion::{Allocator, Placeholder, ProofInput},
    CircuitError, Groth16Prover, TxContext, ZkProgramCircuit,
};
use spr_transaction::{Mint, WalletUtxo};

use crate::{
    benchmark::prove,
    shared::{keypair, token_input},
};

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

impl spr_program::circuit::CircuitType for circuit::Payment {}

impl ProofInput for Payment {
    type Circuit = circuit::Payment;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::Payment, CircuitError> {
        let private = &self.private;
        Ok(circuit::Payment {
            private: circuit::PaymentPrivateInputs {
                tx_context: private.tx_context.instantiate(allocator)?,
                token_utxos_asset_a: private.token_utxos_asset_a.instantiate(allocator)?,
                amount: private.amount.instantiate(allocator)?,
            },
            public: circuit::PaymentPublicInputs {
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

impl Placeholder for Payment {
    fn placeholder() -> Result<Self, CircuitError> {
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
    use spr_program::{
        circuit::{
            poseidon, CheckedTransaction, Circuit, CircuitVar, ConfidentialTransaction,
            PublicInputs, TokenUtxos, TxContext, Uint, Utxo, UtxoOwner, UtxoTrait,
        },
        CircuitError,
    };

    pub struct Payment {
        pub private: PaymentPrivateInputs,
        pub public: PaymentPublicInputs,
    }

    pub struct PaymentPrivateInputs {
        pub tx_context: TxContext,
        pub token_utxos_asset_a: [Utxo; 2],
        pub amount: Uint<64>,
    }

    pub struct PaymentPublicInputs {
        pub recipient: UtxoOwner,
    }

    impl Circuit for Payment {
        type Output = CheckedTransaction;

        fn circuit(&self) -> Result<Self::Output, CircuitError> {
            let private = &self.private;
            let mut tokens = TokenUtxos::new_mut(&private.token_utxos_asset_a)?;
            let mut payment = TokenUtxos::new_init(&self.public.recipient, &tokens.asset());
            tokens.transfer(&mut payment, &private.amount)?;

            ConfidentialTransaction::new(&private.tx_context, &self.public)
                .with(tokens)
                .with(payment)
                .check()
        }
    }

    impl PublicInputs for PaymentPublicInputs {
        fn hash(&self, transaction_hash: &CircuitVar) -> Result<CircuitVar, CircuitError> {
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
    let transaction_key =
        ViewingKey::from_canonical_bytes(&first.tx_viewing_key.expect("synced transaction key"))
            .expect("valid transaction key");
    drop(sender);

    let payment = Payment {
        private: PaymentPrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: [first, second],
            amount: 400,
        },
        public: PaymentPublicInputs { recipient },
    };
    let spp_proof_inputs = payment
        .create_proof_inputs_and_encrypt(&address, payer)
        .expect("payment proof inputs");
    assert_eq!(
        spp_proof_inputs.external_data.tx_viewing_pk,
        *transaction_key.pubkey().as_bytes()
    );
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
    let result = prove(&prover, &payment, "payment proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
