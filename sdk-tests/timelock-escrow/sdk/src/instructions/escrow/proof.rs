use anyhow::{anyhow, bail, Result};
use timelock_escrow_program::instructions::escrow::{slot, EscrowPublicInput, N_INPUTS, N_OUTPUTS};
use timelock_escrow_prover::{EscrowProofInputs, EscrowPublicProofInputs};
use zolana_keypair::{ShieldedAddress, ViewingKeyTrait};
use zolana_transaction::{
    instructions::transact::SppProofInputs, utxo::SppProofInputUtxo, SppProofOutputUtxo,
};

use crate::{
    err, escrow_authority,
    state::{EscrowTerms, EscrowUtxo},
    zk_program::{BuiltTransaction, NewProgramUtxo, ProgramState, ProgramTransaction},
};

pub struct EscrowProofInputParams {
    pub creator: ShieldedAddress,
    pub source: SppProofInputUtxo,
    pub amount: u64,
    pub unlock_timestamp: u64,
    pub output_tree_id: u16,
}

impl EscrowProofInputParams {
    pub fn build(self, viewing_key: &impl ViewingKeyTrait) -> Result<EscrowTransaction> {
        let Self {
            creator,
            source,
            amount,
            unlock_timestamp,
            output_tree_id,
        } = self;
        if source.utxo.owner != creator.signing_pubkey
            || source.nullifier_pubkey != creator.nullifier_pubkey
        {
            bail!("the source belongs to another owner than the creator");
        }
        let asset = source.utxo.asset;
        let change_amount = source.utxo.amount.checked_sub(amount).ok_or_else(|| {
            anyhow!(
                "the source holds {} but the escrow locks {amount}",
                source.utxo.amount
            )
        })?;
        let escrow_utxo = NewProgramUtxo::new(
            escrow_authority(),
            EscrowTerms {
                creator,
                unlock_timestamp,
            },
            asset,
            amount,
            creator.viewing_pubkey,
        );
        let change = SppProofOutputUtxo::new(asset, change_amount, creator).map_err(err)?;
        let transaction = ProgramTransaction::<N_INPUTS, N_OUTPUTS>::new(
            creator.solana_address().map_err(err)?,
            output_tree_id,
        )
        .with_input(slot::SOURCE, source)?
        .with_output(slot::CHANGE, change)?
        .with_program_output(slot::ESCROW, &escrow_utxo)?
        .build(viewing_key)?;
        let escrow_utxo = transaction.created(slot::ESCROW, escrow_utxo)?;
        Ok(EscrowTransaction {
            transaction,
            escrow_utxo,
        })
    }
}

pub struct EscrowTransaction {
    pub(super) transaction: BuiltTransaction<N_INPUTS, N_OUTPUTS>,
    escrow_utxo: EscrowUtxo,
}

impl EscrowTransaction {
    pub fn spp_proof_inputs(&self) -> SppProofInputs {
        self.transaction.spp_proof_inputs()
    }

    pub fn transaction(&self) -> &BuiltTransaction<N_INPUTS, N_OUTPUTS> {
        &self.transaction
    }

    pub fn source(&self) -> Result<&SppProofInputUtxo> {
        self.transaction.input(slot::SOURCE)
    }

    pub fn escrow_utxo(&self) -> &EscrowUtxo {
        &self.escrow_utxo
    }

    pub fn change(&self) -> Result<&SppProofOutputUtxo> {
        self.transaction.output(slot::CHANGE)
    }

    pub fn to_proof_inputs(&self) -> Result<EscrowProofInputs> {
        let private_tx_hash = *self.transaction.private_tx_hash();
        let escrow_owner_hash = self.escrow_utxo.owner().owner_hash()?;
        let public_input_hash = EscrowPublicInput {
            private_tx_hash: &private_tx_hash,
            escrow_owner_hash: &escrow_owner_hash,
        }
        .hash()
        .map_err(err)?;
        Ok(EscrowProofInputs {
            public: EscrowPublicProofInputs {
                public_input_hash,
                private_tx_hash,
                escrow_owner_hash,
            },
            tx: self.transaction.transaction_proof_inputs()?,
            source: self.transaction.input_proof_inputs(slot::SOURCE)?,
            terms: self.escrow_utxo.state().proof_inputs()?,
            amount: self.escrow_utxo.amount(),
        })
    }
}
