use zk_program_sdk::{
    circuit::{
        poseidon, Assert, CheckedTransaction, Circuit, CircuitVar, ConfidentialTransaction,
        DataUtxo, PublicInputs, TokenUtxos, TxContext, Uint, Utxo, UtxoTrait,
    },
    CircuitError,
};

use super::EscrowTerms;

pub struct Withdraw {
    pub private: WithdrawPrivateInputs,
    pub public: WithdrawPublicInputs,
}

pub struct WithdrawPrivateInputs {
    pub tx_context: TxContext,
    pub escrow: Utxo,
    pub terms: EscrowTerms,
}

pub struct WithdrawPublicInputs {
    pub unlock: Uint<64>,
    pub owner_identity: CircuitVar,
}

impl Circuit for Withdraw {
    fn circuit(&self) -> Result<CheckedTransaction, CircuitError> {
        let private = &self.private;
        let mut escrow = DataUtxo::new_close(&private.escrow, &private.terms)?;
        escrow
            .amount()?
            .assert_not_zero("the escrow utxo holds nothing")?;
        escrow.creator.key().identity()?.assert_equal(
            &self.public.owner_identity,
            "the signer is not the escrow creator",
        )?;
        self.public
            .unlock
            .assert_equal(&escrow.unlock, "the unlock time is not the escrow's")?;
        let mut payout = TokenUtxos::new_init(&escrow.creator, &escrow.asset());
        escrow.transfer_all(&mut payout)?;

        ConfidentialTransaction::new(&private.tx_context, &self.public)
            .with_data_utxo(escrow)
            .with_token_utxos(payout)
            .check()
    }
}

impl PublicInputs for WithdrawPublicInputs {
    fn hash(&self, private_tx_hash: &CircuitVar) -> Result<CircuitVar, CircuitError> {
        poseidon(&[
            self.unlock.clone().into(),
            self.owner_identity.clone(),
            private_tx_hash.clone(),
        ])
    }
}
