use zk_program_sdk::{
    conversion::{Allocator, Placeholder, ProofInput},
    Groth16Prover, RelationError, TxContext, ZkProgram,
};
use zolana_interface::shape::Shape;
use zolana_keypair::ShieldedAddress;
use zolana_transaction::{Mint, WalletUtxo};

use crate::{
    benchmark::prove,
    shared::{keypair, token_input, USDC},
};

#[derive(Clone)]
struct TwoAssetPayment {
    private: TwoAssetPaymentPrivateInputs,
    public: TwoAssetPaymentPublicInputs,
}

#[derive(Clone)]
struct TwoAssetPaymentPrivateInputs {
    tx_context: TxContext,
    token_utxos_asset_a: [WalletUtxo; 2],
    token_utxos_asset_b: [WalletUtxo; 2],
    amount_a: u64,
    amount_b: u64,
}

#[derive(Clone)]
struct TwoAssetPaymentPublicInputs {
    recipient: ShieldedAddress,
}

impl ProofInput for TwoAssetPayment {
    type Circuit = circuit::TwoAssetPayment;

    fn instantiate(
        &self,
        allocator: &Allocator,
    ) -> Result<circuit::TwoAssetPayment, RelationError> {
        let private = &self.private;
        Ok(circuit::TwoAssetPayment {
            private: circuit::TwoAssetPaymentPrivateInputs {
                tx_context: private.tx_context.instantiate(allocator)?,
                token_utxos_asset_a: private.token_utxos_asset_a.instantiate(allocator)?,
                token_utxos_asset_b: private.token_utxos_asset_b.instantiate(allocator)?,
                amount_a: private.amount_a.instantiate(allocator)?,
                amount_b: private.amount_b.instantiate(allocator)?,
            },
            public: circuit::TwoAssetPaymentPublicInputs {
                recipient: self.public.recipient.instantiate(allocator)?,
            },
        })
    }
}

impl Placeholder for TwoAssetPayment {
    fn placeholder() -> Result<Self, RelationError> {
        Ok(Self {
            private: TwoAssetPaymentPrivateInputs {
                tx_context: Placeholder::placeholder()?,
                token_utxos_asset_a: Placeholder::placeholder()?,
                token_utxos_asset_b: Placeholder::placeholder()?,
                amount_a: Placeholder::placeholder()?,
                amount_b: Placeholder::placeholder()?,
            },
            public: TwoAssetPaymentPublicInputs {
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

    pub struct TwoAssetPayment {
        pub private: TwoAssetPaymentPrivateInputs,
        pub public: TwoAssetPaymentPublicInputs,
    }

    pub struct TwoAssetPaymentPrivateInputs {
        pub tx_context: TxContext,
        pub token_utxos_asset_a: [Utxo; 2],
        pub token_utxos_asset_b: [Utxo; 2],
        pub amount_a: CircuitVar,
        pub amount_b: CircuitVar,
    }

    pub struct TwoAssetPaymentPublicInputs {
        pub recipient: Owner,
    }

    impl Circuit for TwoAssetPayment {
        fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
            let private = &self.private;
            let recipient = &self.public.recipient;
            let mut tokens_a = TokenUtxo::new_mut(&private.token_utxos_asset_a)?;
            let mut payment_a = TokenUtxo::new_init(recipient, &tokens_a.asset());
            tokens_a.transfer(&mut payment_a, &private.amount_a)?;
            let mut tokens_b = TokenUtxo::new_mut(&private.token_utxos_asset_b)?;
            let mut payment_b = TokenUtxo::new_init(recipient, &tokens_b.asset());
            tokens_b.transfer(&mut payment_b, &private.amount_b)?;

            ConfidentialTransaction::new(&private.tx_context, &self.public)
                .with_token_utxos(tokens_a)
                .with_token_utxos(payment_a)
                .with_token_utxos(tokens_b)
                .with_token_utxos(payment_b)
                .check()
        }
    }

    impl PublicInputs for TwoAssetPaymentPublicInputs {
        fn hash(&self, transaction_hash: &CircuitVar) -> Result<CircuitVar, RelationError> {
            poseidon(&[self.recipient.hash()?, transaction_hash.clone()])
        }
    }
}

#[test]
fn two_asset_payment_prove_and_verify() {
    let sender = keypair(5);
    let address = sender.shielded_address().expect("sender address");
    let payer = address.solana_address().expect("payer");
    let recipient = keypair(6).shielded_address().expect("recipient address");
    let first = token_input(&sender, Mint::SOL, 300, 0);

    let payment = TwoAssetPayment {
        private: TwoAssetPaymentPrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: [first, token_input(&sender, Mint::SOL, 200, 1)],
            token_utxos_asset_b: [
                token_input(&sender, USDC, 70, 2),
                token_input(&sender, USDC, 30, 3),
            ],
            amount_a: 450,
            amount_b: 80,
        },
        public: TwoAssetPaymentPublicInputs { recipient },
    };
    let spp_proof_inputs = payment
        .create_proof_inputs_and_encrypt(&sender, payer, u64::MAX)
        .expect("two-asset payment proof inputs");
    assert_eq!(
        (
            spp_proof_inputs.check_shape().expect("payment shape"),
            spp_proof_inputs
                .output_utxos
                .iter()
                .map(|output| (output.owner_address, output.asset, output.amount))
                .collect::<Vec<_>>(),
        ),
        (
            Shape::IN4_OUT4,
            vec![
                (Some(address), Mint::SOL, 50),
                (Some(recipient), Mint::SOL, 450),
                (Some(address), USDC, 20),
                (Some(recipient), USDC, 80),
            ]
        )
    );

    let prover =
        Groth16Prover::<TwoAssetPayment>::new_with_test_setup().expect("two-asset payment setup");
    let result = prove(&prover, &payment, "two-asset payment proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
