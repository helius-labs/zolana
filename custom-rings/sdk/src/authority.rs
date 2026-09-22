use borsh::BorshDeserialize;
use solana_address::Address;
use zolana_event::OutputDataEncoding;
use zolana_interface::instruction::{
    instruction_data::transact::{OwnerTag, TransactOutput},
    tag::RING_AUTHORITY_TRANSACT,
};
use zolana_keypair::{constants::SALT_LEN, random_blinding, ViewingKey};

use zolana_transaction::{
    error::TransactionError,
    instructions::transact::{shape::Shape, PublicTransfers},
    serialization::confidential::{Confidential, ConfidentialEncode, ConfidentialOutputPlaintext},
    utxo::{derive_output_blinding_seed, derive_transact_output_blinding, SppProofInputUtxo},
    AssetRegistry, EncryptedScheme, ExternalData, SppProofOutputUtxo, UtxoSerialization,
};

use crate::PreparedRingAuthority;

const MAX_AUTHORITY_SLOTS: usize = 4;

pub struct RingAuthorityMove {
    pub ring_program_id: Address,
    pub inputs: Vec<SppProofInputUtxo>,
    pub outputs: Vec<SppProofOutputUtxo>,
    pub payer: Address,
    pub input_tree_id: u16,
    pub output_tree_id: u16,
}

pub struct RingAuthorityDraft {
    pub inputs: Vec<SppProofInputUtxo>,
    pub outputs: Vec<SppProofOutputUtxo>,
    pub shape: Shape,
    ring_program_id: Address,
    payer: Address,
    output_tree_id: u16,
    blinding_seed: [u8; 32],
    dummy_tag: [u8; 32],
}

pub struct AuthoritySeal<'a> {
    pub tx: &'a ViewingKey,
    pub assets: &'a AssetRegistry,
    pub salt: [u8; SALT_LEN],
}

impl RingAuthorityMove {
    pub fn prepare(self) -> Result<RingAuthorityDraft, TransactionError> {
        let Self {
            ring_program_id,
            mut inputs,
            mut outputs,
            payer,
            input_tree_id,
            output_tree_id,
        } = self;
        if inputs.first().is_none_or(SppProofInputUtxo::is_dummy) {
            return Err(TransactionError::NoInputs);
        }
        if outputs.iter().any(SppProofOutputUtxo::is_dummy) {
            return Err(TransactionError::MissingOutput);
        }
        let width = inputs.len().max(outputs.len());
        if width > MAX_AUTHORITY_SLOTS {
            return Err(TransactionError::UnsupportedShape {
                n_in: inputs.len(),
                n_out: outputs.len(),
            });
        }
        let shape = Shape::new(width, width);
        let padded_outputs = width - outputs.len();
        // A pad names a recipient, never a private input owner.
        let dummy_tag = outputs
            .iter()
            .find_map(|output| output.owner_address.as_ref())
            .ok_or(TransactionError::MissingOutput)?
            .signing_pubkey
            .confidential_view_tag()?;
        for _ in 0..padded_outputs {
            outputs.push(SppProofOutputUtxo {
                owner_tag: Some(dummy_tag),
                ring_program_id: Some(ring_program_id),
                ..Default::default()
            });
        }
        while inputs.len() < width {
            inputs.push(SppProofInputUtxo::dummy(input_tree_id)?);
        }
        if let Some((index, input)) = inputs
            .iter()
            .enumerate()
            .find(|(_, input)| input.is_dummy() && input.tree_id != input_tree_id)
        {
            return Err(TransactionError::PaddingInUndeclaredTree {
                index,
                tree_id: input.tree_id,
            });
        }
        let blinding_seed = random_blinding();
        let first_nullifier = inputs
            .first()
            .ok_or(TransactionError::NoInputs)?
            .nullifier();
        let output_seed = derive_output_blinding_seed(&first_nullifier, &blinding_seed)?;
        for (index, output) in outputs.iter_mut().enumerate() {
            output.blinding = derive_transact_output_blinding(
                &first_nullifier,
                &output_seed,
                u32::try_from(index).map_err(|_| TransactionError::TooManyOutputs)?,
            )?;
        }
        Ok(RingAuthorityDraft {
            inputs,
            outputs,
            shape,
            ring_program_id,
            payer,
            output_tree_id,
            blinding_seed,
            dummy_tag,
        })
    }
}

impl RingAuthorityDraft {
    pub fn finalize(
        self,
        seal: AuthoritySeal<'_>,
    ) -> Result<PreparedRingAuthority, TransactionError> {
        let Self {
            inputs,
            outputs,
            shape,
            ring_program_id,
            payer,
            output_tree_id,
            blinding_seed,
            dummy_tag,
        } = self;
        let AuthoritySeal {
            tx,
            assets: _,
            salt,
        } = seal;
        let mut transact_outputs = Vec::with_capacity(outputs.len());
        let mut resolved_owner_tags = Vec::with_capacity(outputs.len());
        for (slot_index, output) in outputs.iter().enumerate() {
            let utxo_hash = output.hash(output_tree_id)?;
            let (tag, data) = match output.owner_address {
                Some(address) => {
                    let tag = address.signing_pubkey.confidential_view_tag()?;
                    let mut message = Confidential::encode_plaintext(
                        &ConfidentialOutputPlaintext {
                            asset_id: output.asset.asset_id,
                            amount: output.amount,
                            blinding: output.blinding,
                            ring_program_id: output.ring_program_id,
                            data: output.data.clone(),
                        },
                        tag,
                        &ConfidentialEncode {
                            tx: tx.clone(),
                            recipient_pubkey: address.viewing_pubkey,
                            salt,
                            slot_index: slot_index as u32,
                        },
                    )?;
                    let OutputDataEncoding::Encrypted(mut blob) =
                        OutputDataEncoding::try_from_slice(&message.data)
                            .map_err(|error| TransactionError::Deserialize(error.to_string()))?
                    else {
                        return Err(TransactionError::BadDiscriminator(
                            EncryptedScheme::Confidential.as_byte(),
                        ));
                    };
                    *blob.first_mut().ok_or(TransactionError::MissingOutput)? =
                        EncryptedScheme::RingConfidential.as_byte();
                    message.data = borsh::to_vec(&OutputDataEncoding::Encrypted(blob))
                        .map_err(|error| TransactionError::Deserialize(error.to_string()))?;
                    (tag, Some(message.data))
                }
                None => (dummy_tag, None),
            };
            transact_outputs.push(TransactOutput {
                utxo_hash,
                owner_tag: OwnerTag::Inline(tag),
                data,
            });
            resolved_owner_tags.push(tag);
        }
        let mut external_data = ExternalData::new(
            *tx.pubkey().as_bytes(),
            salt,
            transact_outputs,
            resolved_owner_tags,
            Vec::new(),
        );
        external_data.instruction_discriminator = RING_AUTHORITY_TRANSACT;
        Ok(PreparedRingAuthority {
            inputs,
            outputs,
            blinding_seed,
            output_tree_id,
            public_transfers: PublicTransfers::default(),
            external_data,
            payer,
            ring_program_id: Some(ring_program_id),
            shape,
        })
    }
}

#[cfg(test)]
mod tests {
    use zolana_keypair::{random_blinding, random_salt, ShieldedKeypair, ViewingKey};

    use super::*;
    use zolana_transaction::{data::Data, utxo::Utxo, AssetRegistry, Mint};

    const RING: Address = Address::new_from_array([42u8; 32]);

    fn note(owner: &ShieldedKeypair, amount: u64) -> SppProofInputUtxo {
        zolana_test_utils::utxo::wallet(
            Utxo {
                owner: owner.signing_pubkey(),
                asset: Mint::SOL,
                amount,
                blinding: random_blinding(),
                ring_program_id: Some(RING),
                data: Data::default(),
            },
            &owner.nullifier_key,
            3,
            0,
            None,
            None,
        )
        .expect("wallet UTXO")
        .into()
    }

    fn recipient(owner: &ShieldedKeypair, amount: u64) -> SppProofOutputUtxo {
        let address = owner.shielded_address().expect("address");
        SppProofOutputUtxo {
            ring_program_id: Some(RING),
            ..SppProofOutputUtxo::new(Mint::SOL, amount, address).expect("output")
        }
    }

    fn prepare(
        inputs: Vec<SppProofInputUtxo>,
        outputs: Vec<SppProofOutputUtxo>,
    ) -> Result<PreparedRingAuthority, TransactionError> {
        RingAuthorityMove {
            ring_program_id: RING,
            inputs,
            outputs,
            payer: Address::new_from_array([9u8; 32]),
            input_tree_id: 3,
            output_tree_id: 3,
        }
        .prepare()?
        .finalize(AuthoritySeal {
            tx: &ViewingKey::new(),
            assets: &AssetRegistry::default(),
            salt: random_salt(),
        })
    }

    #[test]
    fn prepare_pads_to_the_smallest_square_shape() {
        let member = ShieldedKeypair::new_ed25519().expect("member");
        let other = ShieldedKeypair::new_ed25519().expect("other");
        let prepared = prepare(
            vec![note(&member, 5), note(&other, 7)],
            vec![recipient(&other, 12)],
        )
        .expect("prepared");
        assert_eq!(prepared.shape, Shape::new(2, 2));
        assert_eq!(prepared.inputs.len(), 2);
        assert_eq!(prepared.outputs.len(), 2);
        assert!(prepared.outputs[1].is_dummy());
        assert_eq!(prepared.external_data.outputs.len(), 2);
        assert_eq!(prepared.external_data.resolved_owner_tags.len(), 2);
        assert_eq!(
            prepared.external_data.instruction_discriminator,
            RING_AUTHORITY_TRANSACT
        );
    }

    #[test]
    fn a_pad_names_a_recipient_not_an_input_owner() {
        let member = ShieldedKeypair::new_ed25519().expect("member");
        let other = ShieldedKeypair::new_ed25519().expect("other");
        let prepared = prepare(
            vec![note(&member, 3), note(&member, 2)],
            vec![recipient(&other, 5)],
        )
        .expect("prepared");
        let recipient_tag = other
            .signing_pubkey()
            .confidential_view_tag()
            .expect("recipient tag");
        let member_tag = member
            .signing_pubkey()
            .confidential_view_tag()
            .expect("member tag");
        assert_eq!(prepared.external_data.resolved_owner_tags[1], recipient_tag);
        assert_ne!(prepared.external_data.resolved_owner_tags[1], member_tag);
    }

    #[test]
    fn prepare_tags_padded_inputs_with_the_input_tree() {
        let member = ShieldedKeypair::new_ed25519().expect("member");
        let prepared = prepare(
            vec![note(&member, 5)],
            vec![recipient(&member, 2), recipient(&member, 3)],
        )
        .expect("prepared");
        assert_eq!(prepared.inputs.len(), 2);
        assert!(prepared.inputs[1].is_dummy());
        assert_eq!(prepared.inputs[1].tree_id, 3);
    }

    #[test]
    fn prepare_refuses_a_fifth_slot() {
        let member = ShieldedKeypair::new_ed25519().expect("member");
        let inputs = (0..5).map(|_| note(&member, 1)).collect();
        assert!(matches!(
            prepare(inputs, vec![recipient(&member, 5)]),
            Err(TransactionError::UnsupportedShape { n_in: 5, n_out: 1 })
        ));
    }

    #[test]
    fn prepare_refuses_a_dummy_output_and_a_dummy_first_input() {
        let member = ShieldedKeypair::new_ed25519().expect("member");
        assert!(matches!(
            prepare(vec![note(&member, 5)], vec![SppProofOutputUtxo::default()]),
            Err(TransactionError::MissingOutput)
        ));
        assert!(matches!(
            prepare(
                vec![
                    SppProofInputUtxo::dummy(3).expect("dummy"),
                    note(&member, 5)
                ],
                vec![recipient(&member, 5)]
            ),
            Err(TransactionError::NoInputs)
        ));
    }
}
