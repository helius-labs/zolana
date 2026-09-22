use solana_address::Address;
use zolana_client::{
    attach_input_proofs, ClientError, NonInclusionProof, RingAuthorityProver, SpendProof,
};
use zolana_transaction::{
    error::TransactionError,
    instructions::transact::{shape::Shape, PublicTransfers},
    utxo::{derive_output_blinding_seed, derive_private_tx_blinding, SppProofInputUtxo},
    ExternalData, SppProofOutputUtxo,
};

/// A prepared, unsigned ring-authority transact. `external_data`'s
/// `instruction_discriminator` must be `RING_AUTHORITY_TRANSACT` (tag 21) so its
/// `external_data_hash` matches what the program recomputes on-chain.
pub struct RingAuthorityProofInputs {
    pub inputs: Vec<SppProofInputUtxo>,
    pub outputs: Vec<SppProofOutputUtxo>,
    /// The transaction's private random root seed. See
    /// [`SppProofInputs::blinding_seed`](zolana_transaction::instructions::transact::SppProofInputs).
    pub blinding_seed: [u8; 32],
    pub output_tree_id: u16,
    pub public_transfers: PublicTransfers,
    pub external_data: ExternalData,
    pub payer: Address,
    pub ring_program_id: Option<Address>,
    pub shape: Shape,
}

impl RingAuthorityProofInputs {
    pub fn first_nullifier(&self) -> Result<[u8; 32], TransactionError> {
        Ok(self
            .inputs
            .first()
            .ok_or(TransactionError::NoInputs)?
            .nullifier())
    }

    pub fn output_blinding_seed(&self) -> Result<[u8; 32], TransactionError> {
        derive_output_blinding_seed(&self.first_nullifier()?, &self.blinding_seed)
    }

    pub fn private_tx_blinding(&self) -> Result<[u8; 32], TransactionError> {
        derive_private_tx_blinding(&self.first_nullifier()?, &self.blinding_seed)
    }

    pub fn input_utxo_hashes(&self) -> Result<Vec<&SppProofInputUtxo>, TransactionError> {
        let inputs = self
            .inputs
            .iter()
            .filter(|input_utxo| !input_utxo.is_dummy())
            .collect::<Vec<_>>();
        if inputs.is_empty() {
            return Err(TransactionError::NoInputs);
        }
        Ok(inputs)
    }
}

/// A prepared authority move plus the state and nullifier proofs needed by the
/// shared transaction prover.
pub struct RingAuthorityProofs {
    pub prepared: RingAuthorityProofInputs,
    /// One proof per real input, in input order.
    pub proofs: Vec<SpendProof>,
    /// One nullifier non-inclusion proof per dummy input, in dummy-slot order.
    pub dummy_nullifier_proofs: Vec<NonInclusionProof>,
}

impl TryFrom<RingAuthorityProofs> for RingAuthorityProver {
    type Error = ClientError;

    fn try_from(value: RingAuthorityProofs) -> Result<Self, Self::Error> {
        let RingAuthorityProofs {
            prepared,
            proofs,
            dummy_nullifier_proofs,
        } = value;
        let RingAuthorityProofInputs {
            inputs,
            outputs,
            blinding_seed,
            output_tree_id,
            public_transfers,
            external_data,
            payer,
            ring_program_id,
            shape,
        } = prepared;
        let inputs = attach_input_proofs(inputs, &proofs, &dummy_nullifier_proofs)?;

        Ok(RingAuthorityProver {
            inputs,
            outputs,
            blinding_seed,
            output_tree_id,
            external_data,
            public_transfers,
            payer,
            allow_dummy_inputs: true,
            ring_program_id,
            shape,
        })
    }
}

#[cfg(test)]
mod tests {
    use zolana_keypair::ShieldedKeypair;
    use zolana_transaction::{Data, Mint, Utxo};

    use super::*;

    #[test]
    fn blindings_derive_from_the_first_real_input() {
        let owner = ShieldedKeypair::new_ed25519().unwrap();
        let input = SppProofInputUtxo::from(
            zolana_test_utils::utxo::wallet(
                Utxo {
                    owner: owner.signing_pubkey(),
                    asset: Mint::SOL,
                    amount: 1,
                    blinding: [1; 32],
                    ring_program_id: None,
                    data: Data::default(),
                },
                &owner.nullifier_key,
                0,
                0,
                None,
                None,
            )
            .unwrap(),
        );
        let seed = [42; 32];
        let mut prepared = RingAuthorityProofInputs {
            inputs: vec![
                input.clone(),
                SppProofInputUtxo::dummy_with_blinding([8; 32], 0).unwrap(),
            ],
            outputs: vec![],
            blinding_seed: seed,
            output_tree_id: 0,
            public_transfers: PublicTransfers::default(),
            external_data: ExternalData {
                instruction_discriminator: 0,
                expiry_unix_ts: 0,
                interface_transfers: vec![],
                data_hash: None,
                ring_data_hash: None,
                tx_viewing_pk: [0; 33],
                salt: [0; 16],
                outputs: vec![],
                resolved_owner_tags: vec![],
                messages: vec![],
            },
            payer: Address::default(),
            ring_program_id: None,
            shape: Shape::IN2_OUT3,
        };
        let first = input.nullifier();
        assert_eq!(prepared.first_nullifier().unwrap(), first);
        assert_eq!(
            prepared.output_blinding_seed().unwrap(),
            derive_output_blinding_seed(&first, &seed).unwrap()
        );
        assert_eq!(
            prepared.private_tx_blinding().unwrap(),
            derive_private_tx_blinding(&first, &seed).unwrap()
        );
        let real = prepared.input_utxo_hashes().unwrap();
        assert_eq!(real.len(), 1);
        assert_eq!(real[0].nullifier(), first);
        prepared.inputs.truncate(1);
        prepared.inputs[0] = SppProofInputUtxo::dummy(0).unwrap();
        assert!(matches!(
            prepared.input_utxo_hashes(),
            Err(TransactionError::NoInputs)
        ));
        prepared.inputs.clear();
        assert!(matches!(
            prepared.first_nullifier(),
            Err(TransactionError::NoInputs)
        ));
        assert!(matches!(
            prepared.output_blinding_seed(),
            Err(TransactionError::NoInputs)
        ));
        assert!(matches!(
            prepared.private_tx_blinding(),
            Err(TransactionError::NoInputs)
        ));
    }
}
