use anyhow::{bail, Result};
use swap_prover::{MakeProofInputs, OrderTermsProofInput};
use zolana_transaction::{
    instructions::transact::{OutputUtxo, PrivateTxHash, SppProofInputs},
    ProofInputUtxo,
};

use crate::{err, state::OrderUtxo};

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

pub struct MakeProofInputParams {
    pub escrow: OrderUtxo,
    pub change: OutputUtxo,
    pub spp_tx_hashes: SppTxHashes,
}

impl MakeProofInputParams {
    pub fn to_proof_inputs(&self) -> Result<MakeProofInputs> {
        let terms = &self.escrow.terms;
        if self.change.owner_address != Some(terms.destination) {
            bail!("change owner does not match order destination");
        }
        if self.change.asset != self.escrow.source_mint {
            bail!("change asset does not match order source mint");
        }
        if self.change.data_hash.is_some()
            || self.change.zone_data_hash.is_some()
            || self.change.zone_program_id.is_some()
        {
            bail!("change output must not carry data or zone commitments");
        }
        let order = OrderTermsProofInput::try_from(terms)?;
        let escrow = ProofInputUtxo::try_from(&self.escrow.to_input_utxo()?).map_err(err)?;
        let change = ProofInputUtxo::try_from(&self.change).map_err(err)?;
        let change_output_hash = if self.change.amount == 0 {
            [0u8; 32]
        } else {
            change.hash().map_err(err)?
        };
        let private_tx_hash = PrivateTxHash::new(
            &[self.spp_tx_hashes.source_input_hash, [0u8; 32]],
            &[change_output_hash, escrow.hash().map_err(err)?],
            &self.spp_tx_hashes.external_data_hash,
        )
        .hash()
        .map_err(err)?;
        Ok(MakeProofInputs {
            private_tx_hash,
            order,
            escrow,
            change,
            source_input_hash: self.spp_tx_hashes.source_input_hash,
            external_data_hash: self.spp_tx_hashes.external_data_hash,
        })
    }
}
