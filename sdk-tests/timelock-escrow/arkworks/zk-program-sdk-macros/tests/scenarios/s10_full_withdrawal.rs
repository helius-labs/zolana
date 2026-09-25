use solana_address::Address;
use zk_program_sdk::{
    circuit,
    circuit::{
        Assert, Balance, CheckedTransaction, Circuit, ConfidentialTransaction, PublicInputs,
        TokenUtxo,
    },
    conversion::ProofInput,
    Groth16Prover, RelationError, TxContext, ZkProgram,
};
use zolana_interface::instruction::instruction_data::transact::OwnerTag;
use zolana_transaction::{instructions::transact::SettlementTransfer, Mint, WalletUtxo};

use crate::{
    benchmark::prove,
    shared::{keypair, token_input},
};

#[derive(Clone, ProofInput)]
struct Withdrawal {
    private: WithdrawalPrivateInputs,
    public: WithdrawalPublicInputs,
}

#[derive(Clone, ProofInput)]
struct WithdrawalPrivateInputs {
    tx_context: TxContext,
    token_utxos_asset_a: [WalletUtxo; 1],
    destination: Address,
}

#[derive(Clone, ProofInput, PublicInputs)]
struct WithdrawalPublicInputs {
    amount: u64,
}

#[circuit]
impl Circuit for Withdrawal {
    fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
        let private = &self.private;
        let mut tokens = TokenUtxo::new_burn(&private.token_utxos_asset_a)?;
        tokens.withdraw_all(&private.destination)?.assert_equal(
            &self.public.amount,
            "the withdrawal is not the public amount",
        )?;

        ConfidentialTransaction::new(&private.tx_context, &self.public)
            .with_token_utxos(tokens)
            .check()
    }
}

#[test]
fn full_withdrawal_prove_and_verify() {
    let sender = keypair(5);
    let address = sender.shielded_address().expect("sender address");
    let payer = address.solana_address().expect("payer");
    let destination = Address::new_from_array([8u8; 32]);
    let input = token_input(&sender, Mint::SOL, 300, 0);

    let withdrawal = Withdrawal {
        private: WithdrawalPrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: [input],
            destination,
        },
        public: WithdrawalPublicInputs { amount: 300 },
    };
    let spp_proof_inputs = withdrawal
        .create_proof_inputs_and_encrypt(&sender, payer, u64::MAX)
        .expect("withdrawal proof inputs");
    let padding_tag = spp_proof_inputs
        .external_data
        .resolved_owner_tags
        .first()
        .copied()
        .expect("padding owner tag");
    assert_eq!(
        (
            spp_proof_inputs
                .output_utxos
                .iter()
                .map(|output| (output.owner_address, output.amount))
                .collect::<Vec<_>>(),
            spp_proof_inputs
                .external_data
                .outputs
                .iter()
                .map(|output| output.owner_tag)
                .collect::<Vec<_>>(),
            padding_tag == *payer.as_array(),
            spp_proof_inputs.external_data.interface_transfers.clone(),
        ),
        (
            vec![(None, 0)],
            vec![OwnerTag::Inline(padding_tag)],
            false,
            vec![SettlementTransfer::Sol {
                is_deposit: false,
                amount: 300,
                user_sol_account: destination,
            }],
        )
    );

    let prover = Groth16Prover::<Withdrawal>::new_with_test_setup().expect("withdrawal setup");
    let result = prove(&prover, &withdrawal, "withdrawal proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
