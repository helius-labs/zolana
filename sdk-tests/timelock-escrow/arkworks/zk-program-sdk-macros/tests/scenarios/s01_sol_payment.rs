use zk_program_sdk::{
    circuit,
    circuit::{
        Balance, CheckedTransaction, Circuit, ConfidentialTransaction, PublicInputs, TokenUtxo,
    },
    conversion::ProofInput,
    Groth16Prover, RelationError, TxContext, ZkProgram,
};
use zolana_keypair::ShieldedAddress;
use zolana_transaction::{Mint, WalletUtxo};

use crate::{
    benchmark::prove,
    shared::{keypair, token_input},
};

#[derive(Clone, ProofInput)]
pub(crate) struct Payment {
    pub(crate) private: PaymentPrivateInputs,
    pub(crate) public: PaymentPublicInputs,
}

#[derive(Clone, ProofInput)]
pub(crate) struct PaymentPrivateInputs {
    pub(crate) tx_context: TxContext,
    pub(crate) token_utxos_asset_a: [WalletUtxo; 2],
    pub(crate) amount: u64,
}

#[derive(Clone, ProofInput, PublicInputs)]
pub(crate) struct PaymentPublicInputs {
    pub(crate) recipient: ShieldedAddress,
}

#[circuit]
impl Circuit for Payment {
    fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
        let private = &self.private;
        let mut tokens = TokenUtxo::new_mut(&private.token_utxos_asset_a)?;
        let mut payment = TokenUtxo::new_init(&self.public.recipient, &tokens.asset());
        tokens.transfer(&mut payment, &private.amount)?;

        ConfidentialTransaction::new(&private.tx_context, &self.public)
            .with_token_utxos(tokens)
            .with_token_utxos(payment)
            .check()
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
    let result = prove(&prover, &payment, "payment proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
