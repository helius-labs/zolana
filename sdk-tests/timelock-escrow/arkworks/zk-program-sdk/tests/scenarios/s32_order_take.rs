use zk_program_sdk::{
    conversion::{Allocator, Placeholder, ProofInput},
    Groth16Prover, RelationError, TxContext, ZkProgram,
};
use zolana_interface::shape::Shape;
use zolana_keypair::ShieldedAddress;
use zolana_transaction::{Mint, WalletUtxo};

use crate::{
    benchmark::prove,
    s31_order_make::{order_utxo, OrderTerms},
    shared::{keypair, token_input, USDC},
};

#[derive(Clone)]
pub(crate) struct Take {
    pub(crate) private: TakePrivateInputs,
    pub(crate) public: TakePublicInputs,
}

#[derive(Clone)]
pub(crate) struct TakePrivateInputs {
    pub(crate) tx_context: TxContext,
    pub(crate) order: WalletUtxo,
    pub(crate) terms: OrderTerms,
    pub(crate) maker: ShieldedAddress,
    pub(crate) token_utxos_asset_b: [WalletUtxo; 1],
}

#[derive(Clone)]
pub(crate) struct TakePublicInputs {
    pub(crate) ask_asset: Mint,
    pub(crate) ask_amount: u64,
}

impl ProofInput for Take {
    type Circuit = circuit::Take;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::Take, RelationError> {
        let private = &self.private;
        Ok(circuit::Take {
            private: circuit::TakePrivateInputs {
                tx_context: private.tx_context.instantiate(allocator)?,
                order: private.order.instantiate(allocator)?,
                terms: private.terms.instantiate(allocator)?,
                maker: private.maker.instantiate(allocator)?,
                token_utxos_asset_b: private.token_utxos_asset_b.instantiate(allocator)?,
            },
            public: circuit::TakePublicInputs {
                ask_asset: self.public.ask_asset.instantiate(allocator)?,
                ask_amount: self.public.ask_amount.instantiate(allocator)?,
            },
        })
    }
}

impl Placeholder for Take {
    fn placeholder() -> Result<Self, RelationError> {
        Ok(Self {
            private: TakePrivateInputs {
                tx_context: Placeholder::placeholder()?,
                order: Placeholder::placeholder()?,
                terms: Placeholder::placeholder()?,
                maker: Placeholder::placeholder()?,
                token_utxos_asset_b: Placeholder::placeholder()?,
            },
            public: TakePublicInputs {
                ask_asset: Placeholder::placeholder()?,
                ask_amount: Placeholder::placeholder()?,
            },
        })
    }
}

mod circuit {
    use zk_program_sdk::{
        circuit::{
            poseidon, Assert, Asset, Balance, CheckedTransaction, Circuit, CircuitVar,
            ConfidentialTransaction, DataUtxo, Owner, PublicInputs, TokenUtxo, TxContext, Utxo,
        },
        RelationError,
    };

    use crate::s31_order_make::circuit::OrderTerms;

    pub struct Take {
        pub private: TakePrivateInputs,
        pub public: TakePublicInputs,
    }

    pub struct TakePrivateInputs {
        pub tx_context: TxContext,
        pub order: Utxo,
        pub terms: OrderTerms,
        pub maker: Owner,
        pub token_utxos_asset_b: [Utxo; 1],
    }

    pub struct TakePublicInputs {
        pub ask_asset: Asset,
        pub ask_amount: CircuitVar,
    }

    impl Circuit for Take {
        fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
            let private = &self.private;
            let public = &self.public;
            let mut order = DataUtxo::new_burn(&private.order, &private.terms)?;
            private
                .maker
                .hash()?
                .assert_equal(&order.maker_hash, "the maker is not the order's")?;
            public
                .ask_asset
                .hash()?
                .assert_equal(&order.ask_asset_hash, "the ask asset is not the order's")?;
            public
                .ask_amount
                .assert_equal(&order.ask_amount, "the ask amount is not the order's")?;
            let mut tokens = TokenUtxo::new_mut(&private.token_utxos_asset_b)?;
            let mut payment = TokenUtxo::new_init(&private.maker, &public.ask_asset);
            tokens.transfer(&mut payment, &public.ask_amount)?;
            let mut payout = TokenUtxo::new_init(&tokens.owner(), &order.asset());
            order.transfer_all(&mut payout)?;

            ConfidentialTransaction::new(&private.tx_context, public)
                .with_data_utxo(order)
                .with_token_utxos(tokens)
                .with_token_utxos(payment)
                .with_token_utxos(payout)
                .check()
        }
    }

    impl PublicInputs for TakePublicInputs {
        fn hash(&self, transaction_hash: &CircuitVar) -> Result<CircuitVar, RelationError> {
            poseidon(&[
                self.ask_asset.hash()?,
                self.ask_amount.clone(),
                transaction_hash.clone(),
            ])
        }
    }
}

#[test]
fn order_take_prove_and_verify() {
    let maker = keypair(5);
    let maker_address = maker.shielded_address().expect("maker address");
    let taker = keypair(6);
    let taker_address = taker.shielded_address().expect("taker address");
    let payer = taker_address.solana_address().expect("payer");
    let (order, terms) = order_utxo(&maker, 500, 60, 1_800_000_000);

    let take = Take {
        private: TakePrivateInputs {
            tx_context: TxContext::new(),
            order,
            terms,
            maker: maker_address,
            token_utxos_asset_b: [token_input(&taker, USDC, 100, 3)],
        },
        public: TakePublicInputs {
            ask_asset: USDC,
            ask_amount: 60,
        },
    };
    let spp_proof_inputs = take
        .create_proof_inputs_and_encrypt(&taker, payer, u64::MAX)
        .expect("take proof inputs");
    assert_eq!(
        (
            spp_proof_inputs.check_shape().expect("take shape"),
            spp_proof_inputs
                .output_utxos
                .iter()
                .map(|output| (output.owner_address, output.asset, output.amount))
                .collect::<Vec<_>>(),
        ),
        (
            Shape::IN2_OUT3,
            vec![
                (Some(taker_address), USDC, 40),
                (Some(maker_address), USDC, 60),
                (Some(taker_address), Mint::SOL, 500),
            ]
        )
    );

    let prover = Groth16Prover::<Take>::new_with_test_setup().expect("take setup");
    let result = prove(&prover, &take, "take proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
