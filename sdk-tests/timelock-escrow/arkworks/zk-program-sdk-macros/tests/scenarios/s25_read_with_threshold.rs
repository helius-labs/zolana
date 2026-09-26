use borsh::{BorshDeserialize, BorshSerialize};
use zk_program_sdk::{
    circuit,
    circuit::{
        Bits, CheckedTransaction, Circuit, CircuitType, ConfidentialTransaction, DataUtxo,
        PublicInputs,
    },
    conversion::ProofInput,
    Groth16Prover, RelationError, TxContext, ZkProgram,
};
use zolana_transaction::{Mint, WalletUtxo};

use crate::{
    benchmark::prove,
    shared::{data_input, keypair},
};

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, CircuitType)]
pub struct Account {
    pub balance: u64,
}

#[derive(Clone, ProofInput)]
struct ReadThreshold {
    private: ReadThresholdPrivateInputs,
    public: ReadThresholdPublicInputs,
}

#[derive(Clone, ProofInput)]
struct ReadThresholdPrivateInputs {
    tx_context: TxContext,
    account_utxo: WalletUtxo,
    account: Account,
}

#[derive(Clone, ProofInput, PublicInputs)]
struct ReadThresholdPublicInputs {
    threshold: u64,
}

#[circuit]
impl Circuit for ReadThreshold {
    fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
        let private = &self.private;
        let account = DataUtxo::new_mut(&private.account_utxo, &private.account)?;
        (account.balance.clone() - &self.public.threshold).check_bits(64)?;

        ConfidentialTransaction::new(&private.tx_context, &self.public)
            .with_data_utxo(account)
            .check()
    }
}

#[test]
fn read_with_threshold_prove_and_verify() {
    let owner = keypair(5);
    let address = owner.shielded_address().expect("owner address");
    let payer = address.solana_address().expect("payer");
    let account = Account { balance: 700 };
    let account_utxo = data_input(&owner, 0, &account, 0);

    let read = ReadThreshold {
        private: ReadThresholdPrivateInputs {
            tx_context: TxContext::new(),
            account_utxo,
            account: account.clone(),
        },
        public: ReadThresholdPublicInputs { threshold: 500 },
    };
    let spp_proof_inputs = read
        .create_proof_inputs_and_encrypt(&owner, payer, u64::MAX)
        .expect("read proof inputs");
    assert_eq!(
        spp_proof_inputs
            .output_utxos
            .iter()
            .map(|output| (
                output.owner_address,
                output.asset,
                output.amount,
                output.data.utxo_data().map(<[u8]>::to_vec),
            ))
            .collect::<Vec<_>>(),
        vec![(
            Some(address),
            Mint::SOL,
            0,
            Some(borsh::to_vec(&account).expect("account bytes")),
        )]
    );

    let prover = Groth16Prover::<ReadThreshold>::new_with_test_setup().expect("read setup");
    let result = prove(&prover, &read, "read proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
