use solana_address::Address;
use zk_program_sdk::{
    circuit,
    circuit::{
        Asset, Balance, CheckedTransaction, Circuit, ConfidentialTransaction, PublicInputs,
        TokenUtxo,
    },
    conversion::ProofInput,
    Groth16Prover, RelationError, TxContext, ZkProgram,
};
use zolana_keypair::ShieldedAddress;
use zolana_transaction::{instructions::transact::SettlementTransfer, Mint, WalletUtxo};

use crate::{
    benchmark::prove,
    shared::{keypair, token_input},
};

#[derive(Clone, ProofInput)]
struct Deposit {
    private: DepositPrivateInputs,
    public: DepositPublicInputs,
}

#[derive(Clone, ProofInput)]
struct DepositPrivateInputs {
    tx_context: TxContext,
    token_utxos_asset_a: [WalletUtxo; 1],
    source: Address,
}

#[derive(Clone, ProofInput, PublicInputs)]
struct DepositPublicInputs {
    recipient: ShieldedAddress,
    amount: u64,
}

#[circuit]
impl Circuit for Deposit {
    fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
        let private = &self.private;
        let tokens = TokenUtxo::new_mut(&private.token_utxos_asset_a)?;
        let mut deposit = TokenUtxo::new_init(&self.public.recipient, &Asset::sol());
        deposit.deposit(&self.public.amount, &private.source)?;

        ConfidentialTransaction::new(&private.tx_context, &self.public)
            .with_token_utxos(tokens)
            .with_token_utxos(deposit)
            .check()
    }
}

#[test]
fn deposit_to_another_owner_prove_and_verify() {
    let sender = keypair(5);
    let address = sender.shielded_address().expect("sender address");
    let payer = address.solana_address().expect("payer");
    let recipient = keypair(6).shielded_address().expect("recipient address");
    let input = token_input(&sender, Mint::SOL, 300, 0);

    let deposit = Deposit {
        private: DepositPrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: [input],
            source: payer,
        },
        public: DepositPublicInputs {
            recipient,
            amount: 50,
        },
    };
    let spp_proof_inputs = deposit
        .create_proof_inputs_and_encrypt(&sender, payer, u64::MAX)
        .expect("deposit proof inputs");
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
            vec![
                (Some(address), Mint::SOL, 300),
                (Some(recipient), Mint::SOL, 50),
            ],
            vec![SettlementTransfer::Sol {
                is_deposit: true,
                amount: 50,
                user_sol_account: payer,
            }],
        )
    );

    let prover = Groth16Prover::<Deposit>::new_with_test_setup().expect("deposit setup");
    let result = prove(&prover, &deposit, "deposit proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
