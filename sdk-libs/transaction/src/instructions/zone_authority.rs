//! Zone-authority state transition (`zone_authority_transact`): an unsigned
//! transact over zone-owned UTXOs. The zone authority is authorized on-chain (the
//! `zone_config` PDA signs), so unlike [`SppProofInputs`](super::transact::SppProofInputs)
//! there is no owner signature. Mirrors the merge prepared form: it carries the
//! padded inputs (real first, dummies at the tail) and yields the input
//! commitments to fetch Merkle proofs for.

use solana_address::Address;
use zolana_keypair::hash::sha256_be;

use crate::{
    error::TransactionError,
    instructions::{
        transact::{shape::Shape, spp_proof_inputs::PublicAmounts, SppProofInputs},
        types::{InputUtxoContext, SppProofInputUtxo},
    },
    ExternalData, SppProofOutputUtxo,
};

/// A prepared, unsigned zone-authority transact. `external_data`'s
/// `instruction_discriminator` must be `ZONE_AUTHORITY_TRANSACT` (Tag 3) so its
/// `external_data_hash` matches what the program recomputes on-chain.
pub struct PreparedZoneAuthority {
    pub inputs: Vec<SppProofInputUtxo>,
    pub outputs: Vec<SppProofOutputUtxo>,
    pub public_amounts: PublicAmounts,
    pub external_data: ExternalData,
    pub payer_pubkey_hash: [u8; 32],
    /// The zone program; bound to the public `zone_program_id` and to each
    /// non-dummy UTXO's zone field by the circuit. Every input/output UTXO must
    /// already carry this `zone_program_id`.
    pub zone_program_id: Option<Address>,
    pub shape: Shape,
}

impl PreparedZoneAuthority {
    /// Pin the zone and bind every real UTXO to it.
    ///
    /// Nobody authorizes this spend: the circuit checks only `nullifier_secret`
    /// knowledge, so the zone binding is the sole reason the authority cannot
    /// move value out of its policy zone. The public `zone_program_id` is
    /// therefore nonzero and every non-dummy input and output must carry exactly
    /// it, with no exemption for the default zone, and no public leg may pay
    /// value out.
    pub fn new(
        zone_program_id: Address,
        inputs: Vec<SppProofInputUtxo>,
        outputs: Vec<SppProofOutputUtxo>,
        external_data: ExternalData,
        payer: Address,
    ) -> Result<Self, TransactionError> {
        if zone_program_id == Address::default() {
            return Err(TransactionError::MissingZoneAuthorityProgramId);
        }
        for (index, spend) in inputs.iter().enumerate() {
            spend.check_canonical_dummy()?;
            if spend.is_dummy() {
                continue;
            }
            if spend.utxo.zone_program_id != Some(zone_program_id) {
                return Err(TransactionError::ZoneAuthorityInputZoneMismatch { index });
            }
        }
        for (index, output) in outputs.iter().enumerate() {
            if output.is_dummy() {
                continue;
            }
            if output.zone_program_id != Some(zone_program_id) {
                return Err(TransactionError::ZoneAuthorityOutputZoneMismatch { index });
            }
        }
        if external_data
            .public_sol_amount
            .is_some_and(|amount| amount != 0)
            || external_data
                .public_spl_amount
                .is_some_and(|amount| amount != 0)
        {
            return Err(TransactionError::ZoneAuthorityWithdrawalNotAllowed);
        }

        let shape = SppProofInputs::new(
            inputs.clone(),
            outputs.clone(),
            external_data.clone(),
            payer,
        )
        .check_shape()?;

        Ok(Self {
            inputs,
            outputs,
            public_amounts: PublicAmounts::default(),
            external_data,
            payer_pubkey_hash: sha256_be(payer.as_array()),
            zone_program_id: Some(zone_program_id),
            shape,
        })
    }

    /// Commitments for the real inputs only; dummy padding has a zero owner and no
    /// meaningful commitment to look up.
    pub fn input_utxo_hashes(&self) -> Result<Vec<InputUtxoContext>, TransactionError> {
        self.inputs
            .iter()
            .filter(|spend| !spend.is_dummy())
            .enumerate()
            .map(|(index, spend)| {
                Ok(InputUtxoContext {
                    index,
                    utxo_hash: spend.hash()?,
                    nullifier: spend.nullifier()?,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use zolana_keypair::{constants::BLINDING_LEN, ShieldedKeypair};

    use super::*;
    use crate::{data::Data, utxo::Utxo, ExternalData, SOL_MINT};

    const ZONE: Address = Address::new_from_array([9u8; 32]);
    const OTHER_ZONE: Address = Address::new_from_array([8u8; 32]);

    fn external_data() -> ExternalData {
        ExternalData::new([2u8; 33], [3u8; 16], Vec::new(), Vec::new(), Vec::new())
    }

    fn zone_input(
        keypair: &ShieldedKeypair,
        zone_program_id: Option<Address>,
    ) -> SppProofInputUtxo {
        SppProofInputUtxo::new(
            Utxo {
                owner: keypair.signing_pubkey(),
                asset: SOL_MINT,
                amount: 500,
                blinding: [5u8; BLINDING_LEN],
                zone_program_id,
                data: Data::default(),
            },
            keypair,
        )
    }

    fn zone_output(
        keypair: &ShieldedKeypair,
        zone_program_id: Option<Address>,
    ) -> SppProofOutputUtxo {
        let address = keypair.shielded_address().unwrap();
        let mut output = SppProofOutputUtxo::new(SOL_MINT, 500, address).unwrap();
        output.zone_program_id = zone_program_id;
        output
    }

    fn prepare(
        inputs: Vec<SppProofInputUtxo>,
        outputs: Vec<SppProofOutputUtxo>,
        external_data: ExternalData,
    ) -> Result<PreparedZoneAuthority, TransactionError> {
        PreparedZoneAuthority::new(ZONE, inputs, outputs, external_data, Address::default())
    }

    fn reject(
        inputs: Vec<SppProofInputUtxo>,
        outputs: Vec<SppProofOutputUtxo>,
        external_data: ExternalData,
    ) -> TransactionError {
        match prepare(inputs, outputs, external_data) {
            Ok(_) => panic!("zone-authority transact was accepted"),
            Err(err) => err,
        }
    }

    fn padded(
        keypair: &ShieldedKeypair,
        zone_program_id: Option<Address>,
    ) -> (Vec<SppProofInputUtxo>, Vec<SppProofOutputUtxo>) {
        (
            vec![
                zone_input(keypair, zone_program_id),
                SppProofInputUtxo::new_dummy(),
            ],
            vec![
                zone_output(keypair, zone_program_id),
                SppProofOutputUtxo::default(),
            ],
        )
    }

    #[test]
    fn a_zone_bound_transact_is_accepted_and_pins_its_zone() {
        let keypair = ShieldedKeypair::new().unwrap();
        let (inputs, outputs) = padded(&keypair, Some(ZONE));
        let prepared = prepare(inputs, outputs, external_data()).expect("zone-bound transact");

        assert_eq!(prepared.zone_program_id, Some(ZONE));
        // Only the real input needs a Merkle proof; the dummy has no commitment.
        assert_eq!(prepared.input_utxo_hashes().unwrap().len(), 1);
    }

    /// The zone binding is the only thing keeping the authority inside its policy
    /// zone, so the default zone gets no exemption and no UTXO may sit outside it.
    #[test]
    fn a_utxo_outside_the_pinned_zone_is_rejected() {
        let keypair = ShieldedKeypair::new().unwrap();

        let (inputs, outputs) = padded(&keypair, Some(ZONE));
        let unpinned = match PreparedZoneAuthority::new(
            Address::default(),
            inputs,
            outputs,
            external_data(),
            Address::default(),
        ) {
            Ok(_) => panic!("an unpinned zone was accepted"),
            Err(err) => err,
        };
        assert_eq!(unpinned, TransactionError::MissingZoneAuthorityProgramId);

        for stray in [None, Some(OTHER_ZONE)] {
            let (_, good_outputs) = padded(&keypair, Some(ZONE));
            let (stray_inputs, _) = padded(&keypair, stray);
            assert_eq!(
                reject(stray_inputs, good_outputs, external_data()),
                TransactionError::ZoneAuthorityInputZoneMismatch { index: 0 }
            );

            let (good_inputs, _) = padded(&keypair, Some(ZONE));
            let (_, stray_outputs) = padded(&keypair, stray);
            assert_eq!(
                reject(good_inputs, stray_outputs, external_data()),
                TransactionError::ZoneAuthorityOutputZoneMismatch { index: 0 }
            );
        }
    }

    /// Value cannot leave the zone, and nobody signs this spend, so a public leg
    /// would let the authority pay itself out.
    #[test]
    fn a_public_leg_is_rejected() {
        let keypair = ShieldedKeypair::new().unwrap();
        for external_data in [
            external_data()
                .with_public_sol(-500, Address::default())
                .unwrap(),
            external_data()
                .with_public_spl(-500, Address::default(), Address::default())
                .unwrap(),
        ] {
            let (inputs, outputs) = padded(&keypair, Some(ZONE));
            assert_eq!(
                reject(inputs, outputs, external_data),
                TransactionError::ZoneAuthorityWithdrawalNotAllowed
            );
        }
    }
}
