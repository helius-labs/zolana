use zolana_keypair::ShieldedAddress;
use zolana_program::{
    circuit::{
        CheckedTransaction, Circuit, ConfidentialTransaction, PublicInputs, TokenUtxos, UtxoTrait,
    },
    conversion::ProofInput,
    CircuitError, Groth16Prover, TxContext, ZkProgram,
};
use zolana_transaction::{Mint, WalletUtxo};

use crate::{
    benchmark::prove,
    shared::{keypair, token_input},
};

#[derive(Clone, ProofInput)]
pub struct Payment {
    pub(crate) private: PaymentPrivateInputs,
    pub(crate) public: PaymentPublicInputs,
}

#[derive(Clone, ProofInput)]
pub(crate) struct PaymentPrivateInputs {
    pub(crate) tx_context: TxContext,
    pub(crate) token_utxos_asset_a: [WalletUtxo; 2],
    pub(crate) amount: u64,
}

#[derive(Clone, PublicInputs)]
pub(crate) struct PaymentPublicInputs {
    pub(crate) recipient: ShieldedAddress,
}

#[deny(clippy::disallowed_types)]
impl Circuit for <Payment as ProofInput>::Circuit {
    fn circuit(&self) -> Result<CheckedTransaction, CircuitError> {
        let private = &self.private;
        let mut user_a_tokens = TokenUtxos::new_mut(&private.token_utxos_asset_a)?;
        let mut user_b_tokens =
            TokenUtxos::new_init(&self.public.recipient, &user_a_tokens.asset());
        user_a_tokens.transfer(&mut user_b_tokens, &private.amount)?;

        ConfidentialTransaction::new(&private.tx_context, &self.public)
            .with_token_utxos(user_b_tokens)
            .with_token_utxos(user_a_tokens)
            .check()
    }
}

type Outputs = Vec<(Option<ShieldedAddress>, Mint, u64)>;

fn pay(amount: u64) -> (ShieldedAddress, ShieldedAddress, Outputs) {
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
            amount,
        },
        public: PaymentPublicInputs { recipient },
    };
    let spp_proof_inputs = payment
        .create_proof_inputs_and_encrypt_with_keys(&sender, payer, u64::MAX)
        .expect("payment proof inputs");

    let prover = Groth16Prover::<Payment>::new_with_test_setup().expect("payment setup");
    let result = prove(&prover, &payment, "payment proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");

    let outputs = spp_proof_inputs
        .output_utxos
        .iter()
        .map(|output| (output.owner_address, output.asset, output.amount))
        .collect();
    (address, recipient, outputs)
}

#[test]
fn sol_payment_prove_and_verify() {
    let (address, recipient, outputs) = pay(400);
    assert_eq!(
        outputs,
        vec![
            (Some(recipient), Mint::SOL, 400),
            (Some(address), Mint::SOL, 100),
        ]
    );
}

#[test]
fn sol_payment_of_the_whole_balance_leaves_an_empty_change() {
    let (_, recipient, outputs) = pay(500);
    assert_eq!(
        outputs,
        vec![(Some(recipient), Mint::SOL, 500), (None, Mint::SOL, 0)]
    );
}
