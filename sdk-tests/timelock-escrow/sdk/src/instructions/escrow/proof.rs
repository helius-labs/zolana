use anyhow::{bail, Result};
use timelock_escrow_prover::{EscrowProofInputs, EscrowTermsProofInput};
use zolana_transaction::{
    instructions::transact::{PrivateTxHash, SppProofInputs, SppProofOutputUtxo},
    ProofInputUtxo,
};

use crate::{err, state::EscrowUtxo};

/// The parts of the SPP transact this escrow CPIs into that the escrow proof has
/// to reproduce byte-for-byte, or the two proofs bind different
/// `private_tx_hash` values and the instruction can never land.
pub struct SppTxHashes {
    pub source_input_hash: [u8; 32],
    pub external_data_hash: [u8; 32],
    /// `SppProofInputs::private_tx_blinding()`, the fifth `private_tx_hash`
    /// preimage element.
    pub private_tx_blinding: [u8; 32],
    /// Raw id of the tree the escrow and change outputs are appended to; it is
    /// the second element of every output's commitment.
    pub output_tree_id: u16,
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
            private_tx_blinding: spp_proof_inputs.private_tx_blinding().map_err(err)?,
            output_tree_id: spp_proof_inputs.output_tree_id,
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
            || self.change.ring_data_hash.is_some()
            || self.change.ring_program_id.is_some()
        {
            bail!("change output must not carry data or ring commitments");
        }
        let terms_input = EscrowTermsProofInput::try_from(terms)?;
        // Both are created by this transaction, so both commit under the output
        // tree's id.
        let output_tree_id = self.spp_tx_hashes.output_tree_id;
        let escrow_utxo =
            ProofInputUtxo::try_from(&self.escrow_utxo.to_input_utxo()?.in_tree(output_tree_id))
                .map_err(err)?;
        let change = ProofInputUtxo::try_from((&self.change, output_tree_id)).map_err(err)?;
        let private_tx_hash = PrivateTxHash::new(
            &[self.spp_tx_hashes.source_input_hash, [0u8; 32]],
            &[
                change.hash().map_err(err)?,
                escrow_utxo.hash().map_err(err)?,
            ],
            &self.spp_tx_hashes.external_data_hash,
            &self.spp_tx_hashes.private_tx_blinding,
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
            private_tx_blinding: self.spp_tx_hashes.private_tx_blinding,
        })
    }
}
