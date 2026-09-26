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
    shared::{dummy, keypair, token_input},
};

#[derive(Clone, ProofInput)]
struct Sweep {
    private: SweepPrivateInputs,
    public: SweepPublicInputs,
}

#[derive(Clone, ProofInput)]
struct SweepPrivateInputs {
    tx_context: TxContext,
    token_utxos_asset_a: [WalletUtxo; 2],
}

#[derive(Clone, ProofInput, PublicInputs)]
struct SweepPublicInputs {
    recipient: ShieldedAddress,
}

#[circuit]
impl Circuit for Sweep {
    fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
        let private = &self.private;
        let mut tokens = TokenUtxo::new_burn(&private.token_utxos_asset_a)?;
        let mut sweep = TokenUtxo::new_init(&self.public.recipient, &tokens.asset());
        tokens.transfer_all(&mut sweep)?;

        ConfidentialTransaction::new(&private.tx_context, &self.public)
            .with_token_utxos(tokens)
            .with_token_utxos(sweep)
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
        .create_proof_inputs_and_encrypt(&sender, payer, u64::MAX)
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
        (vec![false], vec![(Some(recipient), Mint::SOL, 500)])
    );

    let prover = Groth16Prover::<Sweep>::new_with_test_setup().expect("sweep setup");
    let result = prove(&prover, &sweep, "sweep proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
