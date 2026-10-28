use spr_keypair::ShieldedAddress;
use spr_program::ZkProgramCircuit;
use spr_program::{
    circuit::{
        CheckedTransaction, Circuit, ConfidentialTransaction, DataUtxo, PublicInputs, TokenUtxos,
        UtxoTrait,
    },
    conversion::ProofInput,
    CircuitError, TxContext,
};
use spr_transaction::WalletUtxo;

use super::EscrowTermsCircuit;

pub const ESCROW_TOKEN_INPUTS: usize = 5;

pub const ESCROW_OUTPUT_SLOT: usize = 1;

#[derive(Clone, ZkProgramCircuit)]
pub struct Escrow {
    pub private: EscrowPrivateInputs,
    pub public: EscrowPublicInputs,
}

#[derive(Clone, ProofInput)]
pub struct EscrowPrivateInputs {
    pub tx_context: TxContext,
    #[max_len(ESCROW_TOKEN_INPUTS)]
    pub token_utxos_asset_a: Vec<WalletUtxo>,
    pub unlock: u64,
    pub amount: u64,
}

#[derive(Clone, PublicInputs)]
pub struct EscrowPublicInputs {
    pub escrow_owner: ShieldedAddress,
}

#[deny(clippy::disallowed_types)]
impl Circuit for EscrowCircuit {
    type Output = CheckedTransaction;

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        let private = &self.private;
        private.amount.assert_not_zero("the escrow locks nothing")?;
        let mut tokens = TokenUtxos::new_mut(&private.token_utxos_asset_a)?;
        let mut escrow = DataUtxo::<EscrowTermsCircuit>::new_init(&self.public.escrow_owner)
            .with_asset(&tokens.asset())?;
        tokens.transfer(&mut escrow, &private.amount)?;
        escrow.creator = tokens.owner();
        escrow.unlock = private.unlock.clone();

        ConfidentialTransaction::new(&private.tx_context, &self.public)
            .with(tokens)
            .with(escrow)
            .check()
    }
}
