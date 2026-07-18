use anyhow::{bail, Result};
use timelock_escrow_program::instructions::withdraw::WithdrawPublicInput;
use timelock_escrow_prover::{EscrowTermsProofInput, WithdrawProofInputs};
use zolana_transaction::{
    instructions::transact::{PrivateTxHash, SppProofOutputUtxo},
    ProofInputUtxo,
};

use crate::{err, shared::check_output_utxo, state::EscrowUtxo};

pub struct WithdrawProofInputParams {
    pub escrow_utxo: EscrowUtxo,
    pub source_output: SppProofOutputUtxo,
    pub external_data_hash: [u8; 32],
}

impl WithdrawProofInputParams {
    pub fn to_proof_inputs(&self) -> Result<WithdrawProofInputs> {
        let terms = &self.escrow_utxo.terms;
        let creator = check_output_utxo(
            "source_output",
            &self.source_output,
            &self.escrow_utxo.asset,
            self.escrow_utxo.amount,
        )?;
        if creator != terms.creator {
            bail!("source output owner does not match the escrow creator");
        }
        let terms_input = EscrowTermsProofInput::try_from(terms)?;
        let owner_pk_field = creator.signing_pubkey.owner_pk_field().map_err(err)?;
        let escrow_utxo =
            ProofInputUtxo::try_from(&self.escrow_utxo.to_input_utxo()?).map_err(err)?;
        let source_output = ProofInputUtxo::try_from(&self.source_output).map_err(err)?;
        let private_tx_hash = PrivateTxHash::new(
            &[escrow_utxo.hash().map_err(err)?],
            &[source_output.hash().map_err(err)?],
            &self.external_data_hash,
        )
        .hash()
        .map_err(err)?;
        let public_input_hash = WithdrawPublicInput {
            private_tx_hash: &private_tx_hash,
            unlock: terms.unlock_timestamp,
            owner_pk_field: &owner_pk_field,
        }
        .hash()
        .map_err(err)?;
        Ok(WithdrawProofInputs {
            public_input_hash,
            private_tx_hash,
            terms: terms_input,
            owner_pk_field,
            nullifier_pk: creator.nullifier_pubkey,
            escrow_utxo,
            source_output,
            external_data_hash: self.external_data_hash,
        })
    }
}
