use anyhow::{bail, Result};
use swap_prover::{MakeProofInputs, OrderTermsProofInput};
use zolana_transaction::{
    instructions::transact::{PrivateTxHash, SppProofInputs, SppProofOutputUtxo},
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
    pub order_utxo: OrderUtxo,
    pub change: SppProofOutputUtxo,
    pub spp_tx_hashes: SppTxHashes,
}

impl MakeProofInputParams {
    pub fn to_proof_inputs(&self) -> Result<MakeProofInputs> {
        let terms = &self.order_utxo.terms;
        if self.change.owner_address != Some(terms.destination) {
            bail!("change owner does not match order destination");
        }
        if self.change.asset != self.order_utxo.source_mint {
            bail!("change asset does not match order source mint");
        }
        if self.change.data_hash.is_some()
            || self.change.zone_data_hash.is_some()
            || self.change.zone_program_id.is_some()
        {
            bail!("change output must not carry data or zone commitments");
        }
        let order = OrderTermsProofInput::try_from(terms)?;
        let order_utxo =
            ProofInputUtxo::try_from(&self.order_utxo.to_input_utxo()?).map_err(err)?;
        let change = ProofInputUtxo::try_from(&self.change).map_err(err)?;
        let private_tx_hash = PrivateTxHash::new(
            &[self.spp_tx_hashes.source_input_hash, [0u8; 32]],
            &[change.hash().map_err(err)?, order_utxo.hash().map_err(err)?],
            &self.spp_tx_hashes.external_data_hash,
        )
        .hash()
        .map_err(err)?;
        Ok(MakeProofInputs {
            private_tx_hash,
            order,
            order_utxo,
            change,
            source_input_hash: self.spp_tx_hashes.source_input_hash,
            external_data_hash: self.spp_tx_hashes.external_data_hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use solana_address::Address;
    use solana_keypair::Keypair;
    use swap_prover::TAKE_MODE_DERIVED;
    use zolana_keypair::{constants::BLINDING_LEN, shielded::ShieldedKeypair};
    use zolana_transaction::SOL_MINT;

    use super::*;
    use crate::state::{OrderTerms, OrderUtxo};

    // A make funded by an input whose value equals the order amount produces a
    // zero-value change output. That output is non-dummy (owner = order
    // destination), so SPP folds its real utxo hash into private_tx_hash. The
    // make proof must fold the same real hash -- never a zeroed hash keyed on
    // amount == 0 -- or the proof verifies against a different private_tx_hash
    // than the SPP transact it CPIs into and the instruction can never land.
    #[test]
    fn zero_change_folds_real_hash_matching_spp() {
        let destination =
            ShieldedKeypair::from_solana_keypair(&Keypair::new_from_array([21u8; 32]))
                .expect("destination keypair")
                .shielded_address()
                .expect("destination address");

        let order_utxo = OrderUtxo {
            terms: OrderTerms {
                destination_mint: SOL_MINT,
                destination_amount: 250_000,
                destination,
                taker: Address::default(),
                expiry: 1_700_000_000,
                take_mode: TAKE_MODE_DERIVED,
            },
            blinding: [11u8; BLINDING_LEN],
            source_mint: SOL_MINT,
            source_amount: 400_000,
            destination_asset_id: 1,
        };
        let change = SppProofOutputUtxo::new(SOL_MINT, 0, destination).expect("change output");
        let spp_tx_hashes = SppTxHashes {
            source_input_hash: [3u8; 32],
            external_data_hash: [4u8; 32],
        };

        let source_input_hash = spp_tx_hashes.source_input_hash;
        let external_data_hash = spp_tx_hashes.external_data_hash;
        let change_hash = change.hash().expect("change hash");
        let order_utxo_hash = order_utxo
            .to_input_utxo()
            .expect("order input")
            .hash()
            .expect("order hash");

        let inputs = MakeProofInputParams {
            order_utxo,
            change,
            spp_tx_hashes,
        }
        .to_proof_inputs()
        .expect("proof inputs");

        // SPP (spp_proof_inputs::message_hash) hashes a non-dummy output at its
        // real hash; the make proof's public input must equal that.
        let expected = PrivateTxHash::new(
            &[source_input_hash, [0u8; 32]],
            &[change_hash, order_utxo_hash],
            &external_data_hash,
        )
        .hash()
        .expect("private tx hash");
        assert_eq!(inputs.private_tx_hash, expected);
    }
}
