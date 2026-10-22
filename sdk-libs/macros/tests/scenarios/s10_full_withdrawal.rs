use solana_address::Address;
use zolana_interface::instruction::instruction_data::transact::OwnerTag;
use zolana_program::{
    circuit::{
        Assert, CheckedTransaction, Circuit, ConfidentialTransaction, PublicInputs, TokenUtxos,
        UtxoTrait,
    },
    conversion::ProofInput,
    CircuitError, Groth16Prover, TxContext, ZkProgramCircuit,
};
use zolana_transaction::{instructions::transact::SettlementTransfer, Mint, WalletUtxo};

use crate::{
    benchmark::prove,
    shared::{keypair, token_input},
};

#[derive(Clone, ZkProgramCircuit)]
pub struct Withdrawal {
    private: WithdrawalPrivateInputs,
    public: WithdrawalPublicInputs,
}

#[derive(Clone, ProofInput)]
struct WithdrawalPrivateInputs {
    tx_context: TxContext,
    token_utxos_asset_a: [WalletUtxo; 1],
    destination: Address,
}

#[derive(Clone, PublicInputs)]
struct WithdrawalPublicInputs {
    amount: u64,
}

#[deny(clippy::disallowed_types)]
impl Circuit for <Withdrawal as ProofInput>::Circuit {
    type Output = CheckedTransaction;

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        let private = &self.private;
        let mut tokens = TokenUtxos::new_mut(&private.token_utxos_asset_a)?.close();
        let withdrawn = tokens.withdraw_all(&private.destination)?;
        self.public
            .amount
            .assert_equal(&withdrawn, "the withdrawal is not the public amount")?;

        ConfidentialTransaction::new(&private.tx_context, &self.public)
            .with(tokens)
            .check()
    }
}

#[test]
fn full_withdrawal_prove_and_verify() {
    let sender = keypair(5);
    // Compact padding publishes no owner tags for the empty outputs.
    let payer = sender
        .shielded_address()
        .and_then(|address| address.solana_address())
        .expect("payer");
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
        .create_proof_inputs_and_encrypt_with_keys(&sender, payer, u64::MAX)
        .expect("withdrawal proof inputs");
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
            spp_proof_inputs.external_data.resolved_owner_tags.clone(),
            spp_proof_inputs.external_data.interface_transfers.clone(),
        ),
        (
            vec![(None, 0), (None, 0)],
            Vec::<OwnerTag>::new(),
            Vec::<[u8; 32]>::new(),
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
