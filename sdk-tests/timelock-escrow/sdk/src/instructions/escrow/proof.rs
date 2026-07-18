use anyhow::{bail, Result};
use timelock_escrow_prover::{EscrowProofInputs, EscrowTermsProofInput};
use zolana_transaction::{
    instructions::transact::{PrivateTxHash, SppProofInputs, SppProofOutputUtxo},
    ProofInputUtxo,
};

use crate::{err, state::EscrowUtxo};

pub struct SppTxHashes {
    pub source_input_hash: [u8; 32],
    pub external_data_hash: [u8; 32],
}

impl SppTxHashes {
    pub fn new(spp_proof_inputs: &SppProofInputs) -> Result<Self> {
        let source_input = spp_proof_inputs
            .input_utxos
            .first()
            .ok_or_else(|| err("missing source input"))?;
        Ok(Self {
            source_input_hash: source_input.hash().map_err(err)?,
            external_data_hash: spp_proof_inputs.external_data.hash().map_err(err)?,
        })
    }
}

pub struct EscrowProofInputParams {
    pub escrow_utxo: EscrowUtxo,
    pub change: SppProofOutputUtxo,
    pub spp_tx_hashes: SppTxHashes,
}

impl EscrowProofInputParams {
    pub fn to_proof_inputs(&self) -> Result<EscrowProofInputs> {
        let terms = &self.escrow_utxo.terms;
        if self.change.owner_address != Some(terms.creator) {
            bail!("change owner does not match escrow creator");
        }
        if self.change.asset != self.escrow_utxo.asset {
            bail!("change asset does not match escrow asset");
        }
        if self.change.data_hash.is_some()
            || self.change.zone_data_hash.is_some()
            || self.change.zone_program_id.is_some()
        {
            bail!("change output must not carry data or zone commitments");
        }
        let terms_input = EscrowTermsProofInput::try_from(terms)?;
        let escrow_utxo =
            ProofInputUtxo::try_from(&self.escrow_utxo.to_input_utxo()?).map_err(err)?;
        let change = ProofInputUtxo::try_from(&self.change).map_err(err)?;
        let private_tx_hash = PrivateTxHash::new(
            &[self.spp_tx_hashes.source_input_hash, [0u8; 32]],
            &[
                change.hash().map_err(err)?,
                escrow_utxo.hash().map_err(err)?,
            ],
            &self.spp_tx_hashes.external_data_hash,
        )
        .hash()
        .map_err(err)?;
        Ok(EscrowProofInputs {
            private_tx_hash,
            terms: terms_input,
            escrow_utxo,
            change,
            source_input_hash: self.spp_tx_hashes.source_input_hash,
            external_data_hash: self.spp_tx_hashes.external_data_hash,
        })
    }
}
