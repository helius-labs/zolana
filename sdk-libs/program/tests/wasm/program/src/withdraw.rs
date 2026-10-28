use spr_program::{input, Field, ZkProgram};
use spr_program::{
    circuit::{
        require, require_eq, CheckedTransaction, ConfidentialTransaction, DataUtxo, PublicInputs,
        TokenUtxos, UtxoTrait,
    },
    CircuitError, TxContext,
};
use spr_program::circuit::Utxo;

use super::EscrowTerms;

#[input]
#[derive(ZkProgram)]
#[zk_program(path = "Withdraw", raw_client)]
pub struct Withdraw {
    pub private: WithdrawPrivateInputs,
    pub public: WithdrawPublicInputs,
}

#[input]
pub struct WithdrawPrivateInputs {
    pub tx_context: TxContext,
    pub escrow: Utxo,
    pub terms: EscrowTerms,
}

#[input]
#[derive(PublicInputs)]
pub struct WithdrawPublicInputs {
    pub unlock: u64,
    pub owner_identity: Field,
}

impl Withdraw {
    pub fn execute(&self) -> Result<CheckedTransaction, CircuitError> {
        let private = &self.private;
        let mut escrow = DataUtxo::new_mut(&private.escrow, &private.terms)?.close();
        require(escrow.amount()? != 0);
        require_eq(escrow.creator.key().identity()?, self.public.owner_identity);
        require_eq(self.public.unlock, escrow.unlock);
        let mut payout = TokenUtxos::new_init(&escrow.creator, &escrow.asset());
        escrow.transfer_all(&mut payout)?;

        ConfidentialTransaction::new(&private.tx_context, &self.public)
            .with(escrow)
            .with(payout)
            .check()
    }
}
