use zk_program_sdk::{
    circuit::{
        poseidon, zero, Assert, Balance, CheckedTransaction, Circuit, CircuitVar,
        ConfidentialTransaction, DataUtxo, Owner, PublicInputs, TokenUtxo, TxContext, Utxo,
    },
    RelationError,
};

use super::EscrowTerms;
use crate::ESCROW_TOKEN_INPUTS;

pub struct Escrow {
    pub private: EscrowPrivateInputs,
    pub public: EscrowPublicInputs,
}

pub struct EscrowPrivateInputs {
    pub tx_context: TxContext,
    pub token_utxos_asset_a: [Utxo; ESCROW_TOKEN_INPUTS],
    pub unlock: CircuitVar,
    pub amount: CircuitVar,
}

pub struct EscrowPublicInputs {
    pub escrow_owner: Owner,
}

impl Circuit for Escrow {
    fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
        let private = &self.private;
        private
            .amount
            .assert_not_equal(&zero(), "the escrow locks nothing")?;
        let mut tokens = TokenUtxo::new_mut(&private.token_utxos_asset_a)?;
        let mut escrow =
            DataUtxo::<EscrowTerms>::new_init(&self.public.escrow_owner, &tokens.asset());
        tokens.transfer(&mut escrow, &private.amount)?;
        escrow.creator = tokens.owner();
        escrow.unlock = private.unlock.clone();

        ConfidentialTransaction::new(&private.tx_context, &self.public)
            .with_token_utxos(tokens)
            .with_data_utxo(escrow)
            .check()
    }
}

impl PublicInputs for EscrowPublicInputs {
    fn hash(&self, private_tx_hash: &CircuitVar) -> Result<CircuitVar, RelationError> {
        poseidon(&[self.escrow_owner.hash()?, private_tx_hash.clone()])
    }
}
