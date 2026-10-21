use zolana_keypair::ShieldedAddress;
use zolana_program::{
    circuit::{
        CheckedTransaction, Circuit, ConfidentialTransaction, PublicInputs, TokenUtxos, UtxoTrait,
    },
    conversion::ProofInput,
    CircuitError, Groth16Prover, TxContext, ZkProgramCircuit,
};
use zolana_transaction::{Mint, WalletUtxo};

use crate::{
    benchmark::prove,
    shared::{dummy, keypair, token_input},
};

#[derive(Clone, ZkProgramCircuit)]
pub struct Sweep {
    private: SweepPrivateInputs,
    public: SweepPublicInputs,
}

#[derive(Clone, ProofInput)]
struct SweepPrivateInputs {
    tx_context: TxContext,
    token_utxos_asset_a: [WalletUtxo; 2],
}

#[derive(Clone, PublicInputs)]
struct SweepPublicInputs {
    recipient: ShieldedAddress,
}

#[deny(clippy::disallowed_types)]
impl Circuit for <Sweep as ProofInput>::Circuit {
    type Output = CheckedTransaction;

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        let private = &self.private;
        let mut tokens = TokenUtxos::new_mut(&private.token_utxos_asset_a)?.close();
        let mut sweep = TokenUtxos::new_init(&self.public.recipient, &tokens.asset());
        tokens.transfer_all(&mut sweep)?;

        ConfidentialTransaction::new(&private.tx_context, &self.public)
            .with(tokens)
            .with(sweep)
            .check()
    }
}

#[test]
fn sweep_prove_and_verify() {
    let sender = keypair(5);
    let address = sender.shielded_address().expect("sender address");
    let payer = address.solana_address().expect("payer");
    let recipient = keypair(6).shielded_address().expect("recipient address");
    let input = token_input(&sender, Mint::SOL, 500, 0);

    let sweep = Sweep {
        private: SweepPrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: [input, dummy()],
        },
        public: SweepPublicInputs { recipient },
    };
    let spp_proof_inputs = sweep
        .create_proof_inputs_and_encrypt_with_keys(&sender, payer, u64::MAX)
        .expect("sweep proof inputs");
    assert_eq!(
        (
            spp_proof_inputs
                .input_utxos
                .iter()
                .map(|input| input.is_dummy())
                .collect::<Vec<_>>(),
            spp_proof_inputs
                .output_utxos
                .iter()
                .map(|output| (output.owner_address, output.asset, output.amount))
                .collect::<Vec<_>>(),
        ),
        (
            vec![false],
            vec![(Some(recipient), Mint::SOL, 500), (None, Mint::SOL, 0)]
        )
    );

    let prover = Groth16Prover::<Sweep>::new_with_test_setup().expect("sweep setup");
    let result = prove(&prover, &sweep, "sweep proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
