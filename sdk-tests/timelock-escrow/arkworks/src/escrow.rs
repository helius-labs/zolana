use zk_program_sdk::{
    conversion::{Allocator, ProofInput},
    RelationError, TxContext, ZkProgram,
};
use zolana_keypair::ShieldedAddress;
use zolana_transaction::WalletUtxo;

use crate::circuit;

pub const ESCROW_TOKEN_INPUTS: usize = 5;

#[derive(Clone)]
pub struct Escrow {
    pub private: EscrowPrivateInputs,
    pub public: EscrowPublicInputs,
}

#[derive(Clone)]
pub struct EscrowPrivateInputs {
    pub tx_context: TxContext,
    pub token_utxos_asset_a: [WalletUtxo; ESCROW_TOKEN_INPUTS],
    pub unlock: u64,
    pub amount: u64,
}

#[derive(Clone)]
pub struct EscrowPublicInputs {
    pub escrow_owner: ShieldedAddress,
}

impl ProofInput for Escrow {
    type Circuit = circuit::Escrow;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::Escrow, RelationError> {
        let private = &self.private;
        Ok(circuit::Escrow {
            private: circuit::EscrowPrivateInputs {
                tx_context: private.tx_context.instantiate(allocator)?,
                token_utxos_asset_a: private.token_utxos_asset_a.instantiate(allocator)?,
                unlock: private.unlock.instantiate(allocator)?,
                amount: private.amount.instantiate(allocator)?,
            },
            public: circuit::EscrowPublicInputs {
                escrow_owner: self.public.escrow_owner.instantiate(allocator)?,
            },
        })
    }
}

impl ZkProgram for Escrow {}
