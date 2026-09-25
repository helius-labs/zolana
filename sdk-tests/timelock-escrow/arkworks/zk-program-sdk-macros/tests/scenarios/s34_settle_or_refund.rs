use borsh::{BorshDeserialize, BorshSerialize};
use zk_program_sdk::{
    circuit,
    circuit::{
        constant, zero, Assert, Balance, CheckedTransaction, Circuit, CircuitType,
        ConfidentialTransaction, DataUtxo, PublicInputs, TokenUtxo,
    },
    conversion::ProofInput,
    Groth16Prover, RelationError, TxContext, ZkProgram,
};
use zolana_interface::shape::Shape;
use zolana_keypair::ShieldedAddress;
use zolana_transaction::{Mint, WalletUtxo};

use crate::{
    benchmark::prove,
    s31_order_make::{order_utxo, OrderTerms},
    shared::{data_input, keypair},
};

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, CircuitType)]
pub struct Reservation {
    pub limit_price: u64,
    pub fill_price: u64,
}

#[derive(Clone, ProofInput)]
struct Settle {
    private: SettlePrivateInputs,
    public: SettlePublicInputs,
}

#[derive(Clone, ProofInput)]
struct SettlePrivateInputs {
    tx_context: TxContext,
    order: WalletUtxo,
    terms: OrderTerms,
    maker: ShieldedAddress,
    reservation_utxo: WalletUtxo,
    reservation: Reservation,
    settles: bool,
}

#[derive(Clone, ProofInput, PublicInputs)]
struct SettlePublicInputs {
    execution_price: u64,
}

#[circuit]
impl Circuit for Settle {
    fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
        let private = &self.private;
        let price = &self.public.execution_price;
        let mut order = DataUtxo::new_burn(&private.order, &private.terms)?;
        private
            .maker
            .hash()?
            .assert_equal(&order.maker_hash, "the maker is not the order's")?;
        let mut reservation = DataUtxo::new_mut(&private.reservation_utxo, &private.reservation)?;
        let settles = &private.settles;
        settles
            .select(
                &(reservation.limit_price.clone() - price),
                &(price.clone() - &reservation.limit_price - constant(1u64)),
            )
            .check_bits(64)?;
        let value = order.balance();
        let taker_amount = settles.select(&value, &zero());
        let maker_amount = value - &taker_amount;
        reservation.fill_price = settles.select(price, &zero());
        let taker = reservation.owner();
        let mut to_taker = TokenUtxo::new_init(&taker, &order.asset());
        order.transfer(&mut to_taker, &taker_amount)?;
        let mut to_maker = TokenUtxo::new_init(&private.maker, &order.asset());
        order.transfer(&mut to_maker, &maker_amount)?;

        ConfidentialTransaction::new(&private.tx_context, &self.public)
            .with_data_utxo(order)
            .with_data_utxo(reservation)
            .with_token_utxos(to_taker)
            .with_token_utxos(to_maker)
            .check()
    }
}

#[test]
fn settle_or_refund_prove_and_verify() {
    let maker = keypair(5);
    let maker_address = maker.shielded_address().expect("maker address");
    let taker = keypair(6);
    let taker_address = taker.shielded_address().expect("taker address");
    let payer = taker_address.solana_address().expect("payer");
    let reservation = Reservation {
        limit_price: 100,
        fill_price: 0,
    };
    let settle = |execution_price: u64, settles: bool| {
        let (order, terms) = order_utxo(&maker, 500, 60, 1_800_000_000);
        let reservation_utxo = data_input(&taker, 0, &reservation, 3);
        Settle {
            private: SettlePrivateInputs {
                tx_context: TxContext::new(),
                order,
                terms,
                maker: maker_address,
                reservation_utxo,
                reservation: reservation.clone(),
                settles,
            },
            public: SettlePublicInputs { execution_price },
        }
    };
    let prover = Groth16Prover::<Settle>::new_with_test_setup().expect("settle setup");

    let settled = settle(95, true);
    let settled_spp_proof_inputs = settled
        .create_proof_inputs_and_encrypt(&taker, payer, u64::MAX)
        .expect("settle proof inputs");
    let settled_result = prove(&prover, &settled, "settle proof");
    prover
        .verify(&settled_result)
        .expect("the settle proof verifies");

    let refunded = settle(105, false);
    let refunded_spp_proof_inputs = refunded
        .create_proof_inputs_and_encrypt(&taker, payer, u64::MAX)
        .expect("refund proof inputs");
    let refunded_result = prove(&prover, &refunded, "refund proof");
    prover
        .verify(&refunded_result)
        .expect("the refund proof verifies");

    let outputs =
        |spp_proof_inputs: &zolana_transaction::instructions::transact::SppProofInputs| {
            spp_proof_inputs
                .output_utxos
                .iter()
                .map(|output| {
                    (
                        output.owner_address,
                        output.asset,
                        output.amount,
                        output.data.utxo_data().map(<[u8]>::to_vec),
                    )
                })
                .collect::<Vec<_>>()
        };
    let reservation_bytes = |fill_price| {
        Some(
            borsh::to_vec(&Reservation {
                limit_price: 100,
                fill_price,
            })
            .expect("reservation bytes"),
        )
    };
    assert_eq!(
        (
            settled_spp_proof_inputs
                .check_shape()
                .expect("settle shape"),
            outputs(&settled_spp_proof_inputs),
            outputs(&refunded_spp_proof_inputs),
        ),
        (
            Shape::IN2_OUT3,
            vec![
                (Some(taker_address), Mint::SOL, 0, reservation_bytes(95)),
                (Some(taker_address), Mint::SOL, 500, None),
                (Some(maker_address), Mint::SOL, 0, None),
            ],
            vec![
                (Some(taker_address), Mint::SOL, 0, reservation_bytes(0)),
                (Some(taker_address), Mint::SOL, 0, None),
                (Some(maker_address), Mint::SOL, 500, None),
            ],
        )
    );
}
