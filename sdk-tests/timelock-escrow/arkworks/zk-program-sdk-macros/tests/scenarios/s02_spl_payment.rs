use zk_program_sdk::{
    circuit::{
        CheckedTransaction, Circuit, ConfidentialTransaction, PublicInputs, TokenUtxos, UtxoTrait,
    },
    conversion::ProofInput,
    CircuitError, Groth16Prover, TxContext, ZkProgram,
};
use zolana_keypair::ShieldedAddress;
use zolana_transaction::{Mint, WalletUtxo};

use crate::{
    benchmark::prove,
    shared::{keypair, token_input, USDC},
};

#[derive(Clone, ProofInput)]
pub struct SplPayment {
    private: SplPaymentPrivateInputs,
    public: SplPaymentPublicInputs,
}

#[derive(Clone, ProofInput)]
struct SplPaymentPrivateInputs {
    tx_context: TxContext,
    token_utxos_asset_a: [WalletUtxo; 1],
    amount: u64,
}

#[derive(Clone, ProofInput, PublicInputs)]
struct SplPaymentPublicInputs {
    recipient: ShieldedAddress,
    mint: Mint,
}

#[deny(clippy::disallowed_types)]
impl Circuit for <SplPayment as ProofInput>::Circuit {
    fn circuit(&self) -> Result<CheckedTransaction, CircuitError> {
        let private = &self.private;
        let mut tokens = TokenUtxos::new_mut(&private.token_utxos_asset_a)?;
        let mut payment = TokenUtxos::new_init(&self.public.recipient, &self.public.mint);
        tokens.transfer(&mut payment, &private.amount)?;

        ConfidentialTransaction::new(&private.tx_context, &self.public)
            .with_token_utxos(tokens)
            .with_token_utxos(payment)
            .check()
    }
}

#[test]
fn spl_payment_prove_and_verify() {
    let sender = keypair(5);
    let address = sender.shielded_address().expect("sender address");
    let payer = address.solana_address().expect("payer");
    let recipient = keypair(6).shielded_address().expect("recipient address");
    let input = token_input(&sender, USDC, 500, 0);

    let payment = SplPayment {
        private: SplPaymentPrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: [input],
            amount: 400,
        },
        public: SplPaymentPublicInputs {
            recipient,
            mint: USDC,
        },
    };
    let spp_proof_inputs = payment
        .create_proof_inputs_and_encrypt_with_keys(&sender, payer, u64::MAX)
        .expect("spl payment proof inputs");
    assert_eq!(
        spp_proof_inputs
            .output_utxos
            .iter()
            .map(|output| (output.owner_address, output.asset, output.amount))
            .collect::<Vec<_>>(),
        vec![(Some(address), USDC, 100), (Some(recipient), USDC, 400)]
    );

    let prover = Groth16Prover::<SplPayment>::new_with_test_setup().expect("spl payment setup");
    let result = prove(&prover, &payment, "spl payment proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
