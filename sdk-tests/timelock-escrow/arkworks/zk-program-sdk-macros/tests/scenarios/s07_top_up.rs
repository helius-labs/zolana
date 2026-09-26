use solana_address::Address;
use zk_program_sdk::{
    circuit,
    circuit::{
        Balance, CheckedTransaction, Circuit, ConfidentialTransaction, PublicInputs, TokenUtxo,
    },
    conversion::ProofInput,
    Groth16Prover, RelationError, TxContext, ZkProgram,
};
use zolana_transaction::{instructions::transact::SettlementTransfer, Mint, WalletUtxo};

use crate::{
    benchmark::prove,
    shared::{keypair, token_input},
};

#[derive(Clone, ProofInput)]
struct TopUp {
    private: TopUpPrivateInputs,
    public: TopUpPublicInputs,
}

#[derive(Clone, ProofInput)]
struct TopUpPrivateInputs {
    tx_context: TxContext,
    token_utxos_asset_a: [WalletUtxo; 1],
    source: Address,
}

#[derive(Clone, ProofInput, PublicInputs)]
struct TopUpPublicInputs {
    amount: u64,
}

#[circuit]
impl Circuit for TopUp {
    fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
        let private = &self.private;
        let mut tokens = TokenUtxo::new_mut(&private.token_utxos_asset_a)?;
        tokens.deposit(&self.public.amount, &private.source)?;

        ConfidentialTransaction::new(&private.tx_context, &self.public)
            .with_token_utxos(tokens)
            .check()
    }
}

#[test]
fn top_up_prove_and_verify() {
    let sender = keypair(5);
    let address = sender.shielded_address().expect("sender address");
    let payer = address.solana_address().expect("payer");
    let input = token_input(&sender, Mint::SOL, 300, 0);

    let top_up = TopUp {
        private: TopUpPrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: [input],
            source: payer,
        },
        public: TopUpPublicInputs { amount: 50 },
    };
    let spp_proof_inputs = top_up
        .create_proof_inputs_and_encrypt(&sender, payer, u64::MAX)
        .expect("top-up proof inputs");
    assert_eq!(
        (
            spp_proof_inputs
                .output_utxos
                .iter()
                .map(|output| (output.owner_address, output.asset, output.amount))
                .collect::<Vec<_>>(),
            spp_proof_inputs.external_data.interface_transfers.clone(),
        ),
        (
            vec![(Some(address), Mint::SOL, 350)],
            vec![SettlementTransfer::Sol {
                is_deposit: true,
                amount: 50,
                user_sol_account: payer,
            }],
        )
    );

    let prover = Groth16Prover::<TopUp>::new_with_test_setup().expect("top-up setup");
    let result = prove(&prover, &top_up, "top-up proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
