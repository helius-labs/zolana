use zolana_keypair::ShieldedAddress;
use zolana_program::{
    circuit::{
        Assert, CheckedTransaction, Circuit, ConfidentialTransaction, DataUtxo, PublicInputs,
        TokenUtxos, UtxoTrait,
    },
    conversion::ProofInput,
    CircuitError, TxContext,
};
use zolana_transaction::WalletUtxo;

use super::EscrowTermsCircuit;

pub const ESCROW_TOKEN_INPUTS: usize = 5;

pub const ESCROW_OUTPUT_SLOT: usize = crate::instructions::escrow::slot::ESCROW;

#[derive(Clone, ProofInput)]
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
    pub creator_identity: [u8; 32],
}

impl Circuit for EscrowCircuit {
    fn circuit(&self) -> Result<CheckedTransaction, CircuitError> {
        let private = &self.private;
        private.amount.assert_not_zero("the escrow locks nothing")?;
        let mut tokens = TokenUtxos::new_mut(&private.token_utxos_asset_a)?;
        tokens.owner().key().identity()?.assert_equal(
            &self.public.creator_identity,
            "the signer does not own the escrowed tokens",
        )?;
        let mut escrow = DataUtxo::<EscrowTermsCircuit>::new_init(&self.public.escrow_owner)
            .with_asset(&tokens.asset())?;
        tokens.transfer(&mut escrow, &private.amount)?;
        escrow.creator = tokens.owner();
        escrow.unlock = private.unlock.clone();

        ConfidentialTransaction::new(&private.tx_context, &self.public)
            .with_token_utxos(tokens)
            .with_data_utxo(escrow)
            .check()
    }
}
