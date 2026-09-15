//! Ring-authority state transition (`ring_authority_transact`): an unsigned
//! transact over ring-owned UTXOs. The ring authority is authorized on-chain (the
//! `ring_config` PDA signs), so unlike [`SppProofInputs`](super::transact::SppProofInputs)
//! there is no owner signature. Mirrors the merge prepared form: it carries the
//! padded inputs (real first, dummies at the tail) and yields the input
//! commitments to fetch Merkle proofs for.

use solana_address::Address;
use zolana_interface::instruction::{
    instruction_data::transact::{OwnerTag, TransactOutput},
    tag::RING_AUTHORITY_TRANSACT,
};
use zolana_keypair::{constants::SALT_LEN, ViewingKey};

use crate::{
    error::TransactionError,
    instructions::{
        transact::{
            shape::Shape,
            slots::encode_confidential_slots,
            spp_proof_inputs::{first_nullifier, prepare_output_blindings, PublicTransfers},
            transfer::{dummy_len, random_dummy_ciphertext},
        },
        types::{InputUtxoContext, SppProofInputUtxo},
    },
    utxo::{derive_output_blinding_seed, derive_private_tx_blinding},
    AssetRegistry, ExternalData, SppProofOutputUtxo,
};

/// Largest square shape the authority rail proves.
const MAX_AUTHORITY_SLOTS: usize = 4;

pub struct RingAuthorityMove {
    pub ring_program_id: Address,
    /// The delegate holds every nullifier key.
    pub inputs: Vec<SppProofInputUtxo>,
    pub outputs: Vec<SppProofOutputUtxo>,
    pub payer: Address,
    pub input_tree_id: u16,
    pub output_tree_id: u16,
}

/// Every blinding derived, nothing encrypted yet.
pub struct RingAuthorityDraft {
    pub inputs: Vec<SppProofInputUtxo>,
    pub outputs: Vec<SppProofOutputUtxo>,
    pub shape: Shape,
    ring_program_id: Address,
    payer: Address,
    output_tree_id: u16,
    blinding_seed: [u8; 32],
    dummy_tag: [u8; 32],
    padded_outputs: usize,
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
        for spend in inputs.iter_mut().filter(|spend| spend.is_dummy()) {
            spend.tree_id = input_tree_id;
        }
        while inputs.len() < width {
            inputs.push(SppProofInputUtxo::new_dummy().in_tree(input_tree_id));
        }
        let blinding_seed = prepare_output_blindings(&inputs, &mut outputs)?;
        Ok(RingAuthorityDraft {
            inputs,
            outputs,
            shape,
            ring_program_id,
            payer,
            output_tree_id,
            blinding_seed,
            dummy_tag,
            padded_outputs,
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
            padded_outputs,
        } = self;
        let AuthoritySeal { tx, assets, salt } = seal;
        let slots = encode_confidential_slots(&outputs, assets, tx, salt)?;
        let pad_len = if padded_outputs > 0 {
            dummy_len(salt)?
        } else {
            0
        };
        let mut transact_outputs = Vec::with_capacity(outputs.len());
        let mut resolved_owner_tags = Vec::with_capacity(outputs.len());
        for (output, slot) in outputs.iter().zip(slots) {
            let utxo_hash = output.hash(output_tree_id)?;
            let (tag, data) = match slot {
                Some(slot) => (slot.view_tag, slot.data),
                None => (dummy_tag, random_dummy_ciphertext(pad_len)),
            };
            transact_outputs.push(TransactOutput {
                utxo_hash,
                owner_tag: OwnerTag::Inline(tag),
                data: Some(data),
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

/// A prepared, unsigned ring-authority transact. `external_data`'s
/// `instruction_discriminator` must be `RING_AUTHORITY_TRANSACT` (tag 21) so its
/// `external_data_hash` matches what the program recomputes on-chain.
pub struct PreparedRingAuthority {
    pub inputs: Vec<SppProofInputUtxo>,
    pub outputs: Vec<SppProofOutputUtxo>,
    /// The transaction's private random root seed. See
    /// [`SppProofInputs::blinding_seed`](super::transact::SppProofInputs).
    pub blinding_seed: [u8; 32],
    /// Raw id of the tree every output is appended to.
    // TODO(tree-id): resolve the tree id from the tree account.
    pub output_tree_id: u16,
    pub public_transfers: PublicTransfers,
    pub external_data: ExternalData,
    pub payer: Address,
    /// The ring program; bound to the public `ring_program_id` and to each
    /// non-dummy UTXO's ring field by the circuit. Every input/output UTXO must
    /// already carry this `ring_program_id`.
    pub ring_program_id: Option<Address>,
    pub shape: Shape,
}

impl PreparedRingAuthority {
    /// Nullifier of the first input slot, which must be a real spend.
    pub fn first_nullifier(&self) -> Result<[u8; 32], TransactionError> {
        first_nullifier(&self.inputs)
    }

    /// Seed every physical output blinding derives from.
    pub fn output_blinding_seed(&self) -> Result<[u8; 32], TransactionError> {
        derive_output_blinding_seed(&self.first_nullifier()?, &self.blinding_seed)
    }

    /// Final `private_tx_hash` preimage element.
    pub fn private_tx_blinding(&self) -> Result<[u8; 32], TransactionError> {
        derive_private_tx_blinding(&self.first_nullifier()?, &self.blinding_seed)
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
    use zolana_keypair::{random_blinding, random_salt, ShieldedKeypair, ViewingKey};

    use super::*;
    use crate::{data::Data, utxo::Utxo, AssetRegistry, SOL_MINT};

    const RING: Address = Address::new_from_array([42u8; 32]);

    fn note(owner: &ShieldedKeypair, amount: u64) -> SppProofInputUtxo {
        SppProofInputUtxo::new(
            Utxo {
                owner: owner.signing_pubkey(),
                asset: SOL_MINT,
                amount,
                blinding: random_blinding(),
                ring_program_id: Some(RING),
                data: Data::default(),
            },
            owner,
        )
        .in_tree(3)
    }

    fn recipient(owner: &ShieldedKeypair, amount: u64) -> SppProofOutputUtxo {
        let address = owner.shielded_address().expect("address");
        SppProofOutputUtxo {
            ring_program_id: Some(RING),
            ..SppProofOutputUtxo::new(SOL_MINT, amount, address).expect("output")
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

    /// The rail keeps input owners private, a pad never names the moved-from owner.
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
                vec![SppProofInputUtxo::new_dummy(), note(&member, 5)],
                vec![recipient(&member, 5)]
            ),
            Err(TransactionError::NoInputs)
        ));
    }
}
