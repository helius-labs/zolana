use anyhow::Result;
use solana_address::Address;
use timelock_escrow_program::instructions::withdraw::{
    slot, WithdrawPublicInput, N_INPUTS, N_OUTPUTS,
};
use timelock_escrow_prover::{WithdrawProofInputs, WithdrawPublicProofInputs};
use zolana_hasher::primitives::solana_owner_identity;
use zolana_keypair::ViewingKeyTrait;
use zolana_transaction::{instructions::transact::SppProofInputs, SppProofOutputUtxo};

use crate::{
    err,
    state::EscrowUtxo,
    zk_program::{BuiltTransaction, ProgramTransaction},
};

pub struct WithdrawProofInputParams {
    pub escrow_utxo: EscrowUtxo,
    pub escrow_leaf_index: u64,
    pub payer: Address,
    pub expiry_unix_ts: u64,
    pub output_tree_id: u16,
}

impl WithdrawProofInputParams {
    pub fn build(self, viewing_key: &impl ViewingKeyTrait) -> Result<WithdrawTransaction> {
        let Self {
            escrow_utxo,
            escrow_leaf_index,
            payer,
            expiry_unix_ts,
            output_tree_id,
        } = self;
        let source_output = SppProofOutputUtxo::new(
            escrow_utxo.asset(),
            escrow_utxo.amount(),
            escrow_utxo.state().creator,
        )
        .map_err(err)?;
        let transaction = ProgramTransaction::<N_INPUTS, N_OUTPUTS>::new(payer, output_tree_id)
            .with_expiry(expiry_unix_ts)
            .with_input(slot::ESCROW, escrow_utxo.input(escrow_leaf_index)?)?
            .with_output(slot::SOURCE_OUTPUT, source_output)?
            .build(viewing_key)?;
        Ok(WithdrawTransaction {
            transaction,
            escrow_utxo,
        })
    }
}

pub struct WithdrawTransaction {
    pub(super) transaction: BuiltTransaction<N_INPUTS, N_OUTPUTS>,
    pub(super) escrow_utxo: EscrowUtxo,
}

impl WithdrawTransaction {
    pub fn spp_proof_inputs(&self) -> SppProofInputs {
        self.transaction.spp_proof_inputs()
    }

    pub fn transaction(&self) -> &BuiltTransaction<N_INPUTS, N_OUTPUTS> {
        &self.transaction
    }

    pub fn escrow_utxo(&self) -> &EscrowUtxo {
        &self.escrow_utxo
    }

    pub fn source_output(&self) -> Result<&SppProofOutputUtxo> {
        self.transaction.output(slot::SOURCE_OUTPUT)
    }

    pub fn creator(&self) -> Result<Address> {
        self.escrow_utxo
            .state()
            .creator
            .solana_address()
            .map_err(err)
    }

    pub fn to_proof_inputs(&self) -> Result<WithdrawProofInputs> {
        let terms = self.escrow_utxo.state();
        let owner_pk_field = solana_owner_identity(self.creator()?.as_array()).map_err(err)?;
        let private_tx_hash = *self.transaction.private_tx_hash();
        let public_input_hash = WithdrawPublicInput {
            private_tx_hash: &private_tx_hash,
            unlock: terms.unlock_timestamp,
            owner_pk_field: &owner_pk_field,
        }
        .hash()
        .map_err(err)?;
        Ok(WithdrawProofInputs {
            public: WithdrawPublicProofInputs {
                public_input_hash,
                private_tx_hash,
            },
            tx: self.transaction.transaction_proof_inputs()?,
            escrow_utxo: self.escrow_utxo.proof_inputs()?,
            owner_pk_field,
            nullifier_pk: terms.creator.nullifier_pubkey,
        })
    }
}
