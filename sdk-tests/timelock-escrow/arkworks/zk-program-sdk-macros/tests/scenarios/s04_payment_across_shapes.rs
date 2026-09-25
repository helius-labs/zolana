use zk_program_sdk::{
    circuit,
    circuit::{
        Balance, CheckedTransaction, Circuit, ConfidentialTransaction, PublicInputs, TokenUtxo,
    },
    conversion::ProofInput,
    Groth16Prover, RelationError, TxContext, ZkProgram,
};
use zolana_interface::shape::Shape;
use zolana_keypair::ShieldedAddress;
use zolana_transaction::{Mint, WalletUtxo};

use crate::{
    benchmark::prove,
    shared::{keypair, token_input},
};

#[derive(Clone, ProofInput)]
pub(crate) struct Payment<const N: usize, const R: usize> {
    pub(crate) private: PaymentPrivateInputs<N, R>,
    pub(crate) public: PaymentPublicInputs<R>,
}

#[derive(Clone, ProofInput)]
pub(crate) struct PaymentPrivateInputs<const N: usize, const R: usize> {
    pub(crate) tx_context: TxContext,
    pub(crate) token_utxos_asset_a: [WalletUtxo; N],
    pub(crate) amounts: [u64; R],
}

#[derive(Clone, ProofInput, PublicInputs)]
pub(crate) struct PaymentPublicInputs<const R: usize> {
    pub(crate) recipients: [ShieldedAddress; R],
}

fn recipients<const R: usize>() -> [ShieldedAddress; R] {
    std::array::from_fn(|index| {
        keypair(6 + u8::try_from(index).expect("recipient seed"))
            .shielded_address()
            .expect("recipient address")
    })
}

fn payment_prove_and_verify<const N: usize, const R: usize>(
    input_amounts: [u64; N],
    amounts: [u64; R],
) -> (Shape, Vec<(Option<ShieldedAddress>, u64)>) {
    let sender = keypair(5);
    let address = sender.shielded_address().expect("sender address");
    let payer = address.solana_address().expect("payer");
    let inputs: [WalletUtxo; N] = std::array::from_fn(|index| {
        token_input(
            &sender,
            Mint::SOL,
            input_amounts.get(index).copied().expect("input amount"),
            u64::try_from(index).expect("leaf index"),
        )
    });

    let payment = Payment {
        private: PaymentPrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: inputs,
            amounts,
        },
        public: PaymentPublicInputs {
            recipients: recipients::<R>(),
        },
    };
    let spp_proof_inputs = payment
        .create_proof_inputs_and_encrypt(&sender, payer, u64::MAX)
        .expect("payment proof inputs");

    let prover = Groth16Prover::<Payment<N, R>>::new_with_test_setup().expect("payment setup");
    let result = prove(&prover, &payment, "payment proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");

    (
        spp_proof_inputs.check_shape().expect("payment shape"),
        spp_proof_inputs
            .output_utxos
            .iter()
            .map(|output| (output.owner_address, output.amount))
            .collect(),
    )
}

#[circuit]
impl<const N: usize, const R: usize> Circuit for Payment<N, R> {
    fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
        let private = &self.private;
        let mut tokens = TokenUtxo::new_mut(&private.token_utxos_asset_a)?;
        let mut payments = self
            .public
            .recipients
            .each_ref()
            .map(|recipient| TokenUtxo::new_init(recipient, &tokens.asset()));
        payments
            .iter_mut()
            .zip(&private.amounts)
            .try_for_each(|(payment, amount)| tokens.transfer(payment, amount))?;

        payments
            .into_iter()
            .fold(
                ConfidentialTransaction::new(&private.tx_context, &self.public)
                    .with_token_utxos(tokens),
                ConfidentialTransaction::with_token_utxos,
            )
            .check()
    }
}

#[test]
fn payment_3x3_prove_and_verify() {
    let [recipient] = recipients::<1>();
    let sender = keypair(5).shielded_address().expect("sender address");

    assert_eq!(
        payment_prove_and_verify([300, 200, 100], [450]),
        (
            Shape::IN3_OUT3,
            vec![(Some(sender), 150), (Some(recipient), 450), (None, 0)]
        )
    );
}

#[test]
fn payment_4x3_prove_and_verify() {
    let [recipient] = recipients::<1>();
    let sender = keypair(5).shielded_address().expect("sender address");

    assert_eq!(
        payment_prove_and_verify([300, 200, 100, 50], [600]),
        (
            Shape::IN4_OUT3,
            vec![(Some(sender), 50), (Some(recipient), 600), (None, 0)]
        )
    );
}

#[test]
fn payment_5x3_prove_and_verify() {
    let [recipient] = recipients::<1>();
    let sender = keypair(5).shielded_address().expect("sender address");

    assert_eq!(
        payment_prove_and_verify([300, 200, 100, 50, 25], [650]),
        (
            Shape::IN5_OUT3,
            vec![(Some(sender), 25), (Some(recipient), 650), (None, 0)]
        )
    );
}

#[test]
fn payment_5x4_prove_and_verify() {
    let [first, second, third] = recipients::<3>();
    let sender = keypair(5).shielded_address().expect("sender address");

    assert_eq!(
        payment_prove_and_verify([300, 200, 100, 50, 25], [400, 150, 100]),
        (
            Shape::IN5_OUT4,
            vec![
                (Some(sender), 25),
                (Some(first), 400),
                (Some(second), 150),
                (Some(third), 100),
            ]
        )
    );
}
