use zolana_program::{input, ArrayVec, Field, ShieldedAddress, ZkProgram};
use zolana_program::{
    circuit::{
        require, require_eq, CheckedTransaction, ConfidentialTransaction, DataUtxo, PublicInputs,
        TokenUtxos, UtxoTrait,
    },
    CircuitError, TxContext,
};
use zolana_program::circuit::Utxo;

use super::EscrowTerms;

pub const ESCROW_TOKEN_INPUTS: usize = 5;

#[input(no_derive)]
#[derive(Clone, Debug, ZkProgram)]
pub struct Escrow {
    pub private: EscrowPrivateInputs,
    pub public: EscrowPublicInputs,
}

#[input(no_derive)]
#[derive(Clone, Debug)]
pub struct EscrowPrivateInputs {
    pub tx_context: TxContext,
    pub token_utxos_asset_a: ArrayVec<Utxo, ESCROW_TOKEN_INPUTS>,
    pub unlock: u64,
    pub amount: u64,
}

#[input(no_derive)]
#[derive(Clone, Debug, PublicInputs)]
pub struct EscrowPublicInputs {
    pub escrow_owner: ShieldedAddress,
    pub creator_identity: Field,
}

impl Escrow {
    pub fn execute(&self) -> Result<CheckedTransaction, CircuitError> {
        let private = &self.private;
        require(private.amount != 0);
        let mut tokens = TokenUtxos::new_mut(&private.token_utxos_asset_a)?;
        require_eq(tokens.owner().key().identity()?, self.public.creator_identity);
        let mut escrow = DataUtxo::<EscrowTerms>::new_init(&self.public.escrow_owner)
            .with_asset(&tokens.asset())?;
        tokens.transfer(&mut escrow, &private.amount)?;
        escrow.creator = tokens.owner();
        escrow.unlock = private.unlock;

        ConfidentialTransaction::new(&private.tx_context, &self.public)
            .with(tokens)
            .with(escrow)
            .check()
    }
}
