use zk_program_sdk::{
    circuit,
    circuit::{
        zero, Assert, Balance, CheckedTransaction, Circuit, ConfidentialTransaction, PublicInputs,
        TokenUtxo,
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

const RECIPIENTS: usize = 7;

#[derive(Clone, ProofInput)]
struct FanOut {
    private: FanOutPrivateInputs,
    public: FanOutPublicInputs,
}

#[derive(Clone, ProofInput)]
struct FanOutPrivateInputs {
    tx_context: TxContext,
    token_utxos_asset_a: [WalletUtxo; 1],
    recipients: [ShieldedAddress; RECIPIENTS],
    amounts: [u64; RECIPIENTS],
}

#[derive(Clone, ProofInput, PublicInputs)]
struct FanOutPublicInputs {
    total: u64,
}

#[circuit]
impl Circuit for FanOut {
    fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
        let private = &self.private;
        private
            .amounts
            .iter()
            .fold(zero(), |sum, amount| sum + amount)
            .assert_equal(&self.public.total, "the payments do not sum to the total")?;
        let mut tokens = TokenUtxo::new_mut(&private.token_utxos_asset_a)?;
        let mut payments = private
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
fn fan_out_prove_and_verify() {
    let sender = keypair(5);
    let address = sender.shielded_address().expect("sender address");
    let payer = address.solana_address().expect("payer");
    let recipients: [ShieldedAddress; RECIPIENTS] = std::array::from_fn(|index| {
        keypair(6 + u8::try_from(index).expect("recipient seed"))
            .shielded_address()
            .expect("recipient address")
    });
    let amounts = [10, 20, 30, 40, 50, 60, 70];
    let input = token_input(&sender, Mint::SOL, 1_000, 0);

    let fan_out = FanOut {
        private: FanOutPrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: [input],
            recipients,
            amounts,
        },
        public: FanOutPublicInputs { total: 280 },
    };
    let spp_proof_inputs = fan_out
        .create_proof_inputs_and_encrypt(&sender, payer, u64::MAX)
        .expect("fan-out proof inputs");
    assert_eq!(
        spp_proof_inputs
            .output_utxos
            .iter()
            .map(|output| (output.owner_address, output.amount))
            .collect::<Vec<_>>(),
        core::iter::once((Some(address), 720))
            .chain(
                recipients
                    .iter()
                    .zip(amounts)
                    .map(|(recipient, amount)| (Some(*recipient), amount))
            )
            .collect::<Vec<_>>()
    );

    let prover = Groth16Prover::<FanOut>::new_with_test_setup().expect("fan-out setup");
    let result = prove(&prover, &fan_out, "fan-out proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
