use zk_program_sdk::{
    circuit,
    circuit::{
        Balance, CheckedTransaction, Circuit, ConfidentialTransaction, PublicInputs, TokenUtxo,
    },
    conversion::ProofInput,
    Groth16Prover, RelationError, TxContext, ZkProgram,
};
use zolana_hasher::{Hasher, Poseidon};
use zolana_keypair::ShieldedAddress;
use zolana_transaction::{Mint, WalletUtxo};

use crate::{
    benchmark::prove,
    shared::{dummy, keypair, token_input},
};

#[derive(Clone, ProofInput)]
struct PrivateSweep {
    private: PrivateSweepPrivateInputs,
    public: NoPublicInputs,
}

#[derive(Clone, ProofInput)]
struct PrivateSweepPrivateInputs {
    tx_context: TxContext,
    token_utxos_asset_a: [WalletUtxo; 2],
    recipient: ShieldedAddress,
}

#[derive(Clone, ProofInput, PublicInputs)]
struct NoPublicInputs;

#[circuit]
impl Circuit for PrivateSweep {
    fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
        let private = &self.private;
        let mut tokens = TokenUtxo::new_burn(&private.token_utxos_asset_a)?;
        let mut sweep = TokenUtxo::new_init(&private.recipient, &tokens.asset());
        tokens.transfer_all(&mut sweep)?;

        ConfidentialTransaction::new(&private.tx_context, &self.public)
            .with_token_utxos(tokens)
            .with_token_utxos(sweep)
            .check()
    }
}

#[test]
fn no_public_fields_prove_and_verify() {
    let sender = keypair(5);
    let address = sender.shielded_address().expect("sender address");
    let payer = address.solana_address().expect("payer");
    let recipient = keypair(6).shielded_address().expect("recipient address");
    let input = token_input(&sender, Mint::SOL, 500, 0);

    let sweep = PrivateSweep {
        private: PrivateSweepPrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: [input, dummy()],
            recipient,
        },
        public: NoPublicInputs,
    };
    let spp_proof_inputs = sweep
        .create_proof_inputs_and_encrypt(&sender, payer, u64::MAX)
        .expect("sweep proof inputs");
    let private_tx_hash = spp_proof_inputs
        .padding_independent_private_tx_hash()
        .expect("private tx hash");

    let prover = Groth16Prover::<PrivateSweep>::new_with_test_setup().expect("sweep setup");
    let result = prove(&prover, &sweep, "sweep proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");

    assert_eq!(
        (
            spp_proof_inputs
                .output_utxos
                .iter()
                .map(|output| (output.owner_address, output.asset, output.amount))
                .collect::<Vec<_>>(),
            result.public_hash,
        ),
        (
            vec![(Some(recipient), Mint::SOL, 500)],
            Poseidon::hashv(&[private_tx_hash.as_slice()]).expect("public hash"),
        )
    );
}
