use zk_program_sdk::{
    circuit::{
        poseidon, zero, Assert, CheckedTransaction, Circuit, CircuitVar, ConfidentialTransaction,
        DataUtxo, PublicInputs, TxContext, Utxo,
    },
    RelationError,
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
    pub unlock: CircuitVar,
    pub owner_identity: CircuitVar,
}

impl Circuit for Withdraw {
    fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
        let private = &self.private;
        let mut escrow = DataUtxo::new_burn(&private.escrow, private.terms.clone())?;
        escrow
            .amount()
            .assert_not_equal(&zero(), "the escrow utxo holds nothing")?;
        escrow.creator.key().identity()?.assert_equal(
            &self.public.owner_identity,
            "the signer is not the escrow creator",
        )?;
        self.public
            .unlock
            .assert_equal(&escrow.unlock, "the unlock time is not the escrow's")?;
        let (creator, amount) = (escrow.creator.clone(), escrow.amount().clone());
        let payout = escrow.transfer(&creator, amount)?;

        ConfidentialTransaction::new(&private.tx_context, &self.public)
            .with_data_utxo(escrow)
            .with_output_token_utxo(payout)
            .check()
    }
}

impl PublicInputs for WithdrawPublicInputs {
    fn hash(&self, private_tx_hash: &CircuitVar) -> Result<CircuitVar, RelationError> {
        poseidon(&[
            self.unlock.clone(),
            self.owner_identity.clone(),
            private_tx_hash.clone(),
        ])
    }
}
