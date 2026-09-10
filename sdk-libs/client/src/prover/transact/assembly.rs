use num_bigint::BigUint;
use solana_address::Address;
use zolana_hasher::{
    hash_chain::{create_hash_chain_from_slice, create_right_hash_chain_from_slice},
    primitives::solana_owner_identity,
};
use zolana_interface::{
    output_data::is_confidential_encrypted_output,
    tree_slot::{tree_id_field, tree_slots_hash_chain, TreeSlot},
    INPUT_TREES,
};
use zolana_keypair::{Curve, NullifierKey};
use zolana_transaction::{
    instructions::transact::{assign_output_blindings, PublicTransfers},
    utxo::{derive_output_blinding_seed, derive_transact_output_blinding},
    ExternalData, ProofInputUtxo, SppProofOutputUtxo, Utxo,
};

use crate::{
    error::ClientError,
    prover::{
        field::{be, right_align_slice},
        transact::witness::SpendProof,
        TransferInput, TransferOutput,
    },
    rpc::{NonInclusionProof, NULLIFIER_TREE_HEIGHT, STATE_TREE_HEIGHT},
};

#[derive(Clone)]
pub struct TransferSpendInput {
    pub utxo: Utxo,
    pub nullifier_key: NullifierKey,
    pub data_hash: Option<[u8; 32]>,
    pub ring_data_hash: Option<[u8; 32]>,
    /// Raw id of the tree this UTXO is spent from. It is hashed into the UTXO
    /// commitment, so it must be the id of the tree the state proof came from.
    // TODO(tree-id): resolve the tree id from the tree account.
    pub tree_id: u16,
    /// `Some` for a real spend, `None` for a padding (dummy) slot. A dummy sits
    /// in tree slot 0, so it has no state proof of its own.
    pub proof: Option<SpendProof>,
    /// Padding slots only: the fetched non-inclusion proof for the dummy's own
    /// nullifier. The circuit checks non-inclusion for every slot, dummies
    /// included, so a dummy needs a real low-element witness.
    pub nullifier_proof: Option<NonInclusionProof>,
}

/// Assigns deterministic final blindings for a low-level prover transaction
/// from its blinding seed. Call this before hashing or encrypting its
/// outputs, and pass the same `blinding_seed` to the prover: the circuit repeats
/// the seed derivation and asserts every output blinding.
pub fn assign_spend_output_blindings(
    inputs: &[TransferSpendInput],
    outputs: &mut [SppProofOutputUtxo],
    blinding_seed: &[u8; 32],
) -> Result<(), ClientError> {
    let first = inputs.first().ok_or(ClientError::NoInputs)?;
    let nullifier_pubkey = first.nullifier_key.pubkey()?;
    let input = first.utxo.proof_input(
        &nullifier_pubkey,
        &first.data_hash.unwrap_or_default(),
        &first.ring_data_hash.unwrap_or_default(),
        first.tree_id,
    )?;
    let input_hash = input.hash()?;
    let first_nullifier = first
        .nullifier_key
        .nullifier(&input_hash, &first.utxo.blinding)?;
    let seed = derive_output_blinding_seed(&first_nullifier, blinding_seed)?;
    assign_output_blindings(outputs, &first_nullifier, &seed)?;
    Ok(())
}

pub(crate) struct AssembledInputs {
    pub inputs: Vec<TransferInput>,
    pub input_hashes: Vec<[u8; 32]>,
    pub nullifiers: Vec<[u8; 32]>,
    /// The circuit's tree slots: slot 0 is `input_tree`, the one tree every
    /// input is spent from; slots 1..4 are all zero.
    pub tree_slots: [TreeSlot; INPUT_TREES],
    /// Index into `input_tree`'s UTXO root cache, shared by every input.
    pub utxo_tree_root_index: u16,
    /// Index into `input_tree`'s nullifier root cache, shared by every input.
    pub nullifier_tree_root_index: u16,
}

pub(crate) struct AssembledOutputs {
    pub outputs: Vec<TransferOutput>,
    pub output_hashes: Vec<[u8; 32]>,
    pub private_tx_output_hashes: Vec<[u8; 32]>,
    /// Per-output public owner identity: `signing_pubkey.owner_pk_field()` for
    /// a real output, `solana_owner_identity` of the builder's random tag for a
    /// dummy. Folded into the confidential public-input hash and matches the
    /// program's `solana_owner_identity(view_tag)` reconstruction.
    pub output_owner_pk_hashes: Vec<[u8; 32]>,
}

pub(crate) fn validate_output_blindings(
    outputs: &[SppProofOutputUtxo],
    first_nullifier: &[u8; 32],
    seed: &[u8; 32],
) -> Result<(), ClientError> {
    for (index, output) in outputs.iter().enumerate() {
        let output_index = u32::try_from(index).map_err(|_| ClientError::TooManyOutputs {
            got: outputs.len(),
            max: u32::MAX as usize,
        })?;
        let expected = derive_transact_output_blinding(first_nullifier, seed, output_index)?;
        if output.blinding != expected {
            return Err(ClientError::OutputBlindingMismatch { index });
        }
    }
    Ok(())
}

/// Derive the public per-slot owner vector for owner-signed custom-ring
/// circuits. Only structurally confidential-encrypted slots publish the Solana
/// owner identity of their resolved owner tag; every other slot contributes
/// zero.
pub(crate) fn confidential_marked_output_owner_pk_hashes(
    external_data: &ExternalData,
) -> Result<Vec<[u8; 32]>, ClientError> {
    if external_data.outputs.len() != external_data.resolved_owner_tags.len() {
        return Err(ClientError::OutputOwnerTagCountMismatch {
            outputs: external_data.outputs.len(),
            owner_tags: external_data.resolved_owner_tags.len(),
        });
    }
    external_data
        .outputs
        .iter()
        .zip(external_data.resolved_owner_tags.iter())
        .map(|(output, owner_tag)| {
            if output
                .data
                .as_deref()
                .is_some_and(is_confidential_encrypted_output)
            {
                Ok(solana_owner_identity(owner_tag)?)
            } else {
                Ok([0u8; 32])
            }
        })
        .collect()
}

/// Selects how each input's private owner `pk_field` is derived for the witness.
/// A P256-owned input is treated differently per mode; an
/// ed25519-owned input always uses its own `owner_pk_field()`.
pub(crate) enum OwnerMode {
    /// Confidential Solana-only rail: P256-owned inputs are rejected (the rail has
    /// no P256 gadget); ed25519 uses its `pk_field`.
    ConfidentialEddsa,
    /// Custom-ring P256 rail: P256-owned inputs contribute the zero sentinel
    /// consumed by the circuit's shared P256 authorization; ed25519 inputs keep
    /// their normal public owner hash.
    RingP256,
    /// Merge: the circuit uses a single shared owner, so a P256 input contributes
    /// the `0` sentinel here (the per-input value is ignored); ed25519 uses its
    /// `pk_field`.
    Merge,
    /// Ring authority (anonymous, pubkey-agnostic): every owner uses its own
    /// `owner_pk_field()` as a private witness, regardless of scheme.
    RingAuthority,
}

/// The one tree a set of padded inputs is spent from (SPP's `input_tree`) and
/// the roots every input is proven against. It fills circuit tree slot 0; the
/// other slots stay zero.
struct InputTree {
    tree_id: u16,
    utxo_root: [u8; 32],
    utxo_root_index: u16,
    nullifier_root: [u8; 32],
    nullifier_root_index: u16,
}

impl InputTree {
    fn tree_slots(&self) -> [TreeSlot; INPUT_TREES] {
        let mut slots = [TreeSlot::ZERO; INPUT_TREES];
        if let Some(first) = slots.first_mut() {
            *first = TreeSlot::new(self.tree_id, self.utxo_root, self.nullifier_root);
        }
        slots
    }
}

/// Resolve the single input tree and its two roots. SPP resolves roots from
/// one `input_tree` per instruction, so every real input must come from the
/// same tree and share the tree id, UTXO root and root index its state proof
/// was fetched against, and every non-inclusion proof (dummies included) must
/// share one nullifier root and root index.
fn resolve_input_tree(spends: &[TransferSpendInput]) -> Result<InputTree, ClientError> {
    let mut trees: Vec<Address> = Vec::with_capacity(1);
    let mut state: Option<(u16, [u8; 32], u16)> = None;
    let mut nullifier: Option<([u8; 32], u16)> = None;

    for spend in spends {
        let nullifier_proof = match &spend.proof {
            Some(proof) => Some(&proof.nullifier),
            None => spend.nullifier_proof.as_ref(),
        };
        if let Some(nf) = nullifier_proof {
            match nullifier {
                Some(known) if known != (nf.root, nf.root_index) => {
                    return Err(ClientError::NullifierRootMismatch)
                }
                Some(_) => {}
                None => nullifier = Some((nf.root, nf.root_index)),
            }
        }

        let Some(proof) = &spend.proof else {
            continue;
        };
        let tree = proof.state.merkle_context.tree;
        if !trees.contains(&tree) {
            trees.push(tree);
        }
        if trees.first() != Some(&tree) {
            // A foreign tree is reported after the pass, with the full count.
            continue;
        }
        let current = (spend.tree_id, proof.state.root, proof.state.root_index);
        match state {
            Some(known) if known != current => return Err(ClientError::InputTreeRootMismatch),
            Some(_) => {}
            None => state = Some(current),
        }
    }

    if trees.len() > 1 {
        return Err(ClientError::MultipleInputTreesUnsupported { got: trees.len() });
    }
    // The input tree supplies the tree id every dummy is hashed under, so a
    // proof without a real spend has nothing to anchor its padding to.
    let (Some((tree_id, utxo_root, utxo_root_index)), Some((nullifier_root, nullifier_root_index))) =
        (state, nullifier)
    else {
        return Err(ClientError::NoInputs);
    };

    Ok(InputTree {
        tree_id,
        utxo_root,
        utxo_root_index,
        nullifier_root,
        nullifier_root_index,
    })
}

/// Convert the already-padded inputs into circuit witness fields. Makes no
/// padding decisions: each slot with a [`SpendProof`] is a real spend hashed
/// under the input tree's id; each slot without one is a dummy hashed under
/// the same id that uses a zero private owner hash and its own nullifier
/// non-inclusion witness. Every input points at tree slot 0. A transaction
/// must spend at least one real input, because the input tree comes from it.
pub(crate) fn assemble_inputs(
    spends: &[TransferSpendInput],
    owner_mode: &OwnerMode,
) -> Result<AssembledInputs, ClientError> {
    let input_tree = resolve_input_tree(spends)?;

    let mut inputs = Vec::with_capacity(spends.len());
    let mut input_hashes = Vec::with_capacity(spends.len());
    let mut nullifiers = Vec::with_capacity(spends.len());

    for (index, spend) in spends.iter().enumerate() {
        let Some(proof) = &spend.proof else {
            let (mut input, nullifier) =
                TransferInput::new_dummy(&spend.utxo.blinding, input_tree.tree_id, &[0u8; 32])?;
            if let Some(nf) = &spend.nullifier_proof {
                check_path_length(nf.path.len(), NULLIFIER_TREE_HEIGHT)?;
                input.nullifier_low_value = be(&nf.low_element);
                input.nullifier_next_value = be(&nf.high_element);
                input.nullifier_low_path_elements = nf.path.iter().map(be).collect();
                input.nullifier_low_path_index = BigUint::from(nf.low_element_index);
            }
            inputs.push(input);
            input_hashes.push([0u8; 32]);
            nullifiers.push(nullifier);
            continue;
        };

        let data_hash = spend.data_hash.unwrap_or([0u8; 32]);
        let ring_data_hash = spend.ring_data_hash.unwrap_or([0u8; 32]);

        let nullifier_pubkey = spend.nullifier_key.pubkey()?;
        let utxo_inputs = spend.utxo.proof_input(
            &nullifier_pubkey,
            &data_hash,
            &ring_data_hash,
            spend.tree_id,
        )?;
        let utxo_hash = utxo_inputs.hash()?;
        let nullifier = spend
            .nullifier_key
            .nullifier(&utxo_hash, &spend.utxo.blinding)?;

        let is_p256 = spend.utxo.owner.curve()? == Curve::P256;
        // Per-input owner pk_field, selected by mode. A P256 owner's value
        // depends on the mode (see OwnerMode); an ed25519 owner always uses
        // its own pk_field.
        let owner_pk_hash = match (owner_mode, is_p256) {
            (OwnerMode::Merge | OwnerMode::RingP256, true) => [0u8; 32],
            (OwnerMode::ConfidentialEddsa, true) => {
                return Err(ClientError::EddsaInputNotSolanaOwned { index })
            }
            (OwnerMode::RingAuthority, true) => spend.utxo.owner.owner_proof_input_hash()?,
            (_, false) => spend.utxo.owner.owner_proof_input_hash()?,
        };

        let nullifier_secret = right_align_slice(&*spend.nullifier_key.secret())?;

        let state = &proof.state;
        let nf = &proof.nullifier;
        check_path_length(state.path.len(), STATE_TREE_HEIGHT)?;
        check_path_length(nf.path.len(), NULLIFIER_TREE_HEIGHT)?;

        inputs.push(TransferInput {
            utxo: utxo_inputs,
            is_dummy: BigUint::ZERO,
            state_path_elements: state.path.iter().map(be).collect(),
            state_path_index: BigUint::from(state.leaf_index),
            nullifier_low_value: be(&nf.low_element),
            nullifier_next_value: be(&nf.high_element),
            nullifier_low_path_elements: nf.path.iter().map(be).collect(),
            nullifier_low_path_index: BigUint::from(nf.low_element_index),
            tree_slot: BigUint::ZERO,
            nullifier: be(&nullifier),
            owner_pk_hash: be(&owner_pk_hash),
            nullifier_secret: be(&nullifier_secret),
        });
        input_hashes.push(utxo_hash);
        nullifiers.push(nullifier);
    }

    Ok(AssembledInputs {
        inputs,
        input_hashes,
        nullifiers,
        tree_slots: input_tree.tree_slots(),
        utxo_tree_root_index: input_tree.utxo_root_index,
        nullifier_tree_root_index: input_tree.nullifier_root_index,
    })
}

/// Convert the already-padded outputs into circuit witness fields. A dummy output
/// (`owner_hash == 0`: empty change or tail padding) still puts its real hash in the
/// public `output_hashes` but contributes `0` to the private-tx hash chain.
pub(crate) fn assemble_outputs(
    outputs: &[SppProofOutputUtxo],
    output_tree_id: u16,
) -> Result<AssembledOutputs, ClientError> {
    let mut assembled = Vec::with_capacity(outputs.len());
    let mut hashes = Vec::with_capacity(outputs.len());
    let mut private_tx_hashes = Vec::with_capacity(outputs.len());
    let mut output_owner_pk_hashes = Vec::with_capacity(outputs.len());

    for output in outputs {
        let is_dummy = output.is_dummy();
        let hash = output.hash(output_tree_id)?;
        // Confidential owner tag: a real output exposes its owner's `pk_field`
        // (`signing_pubkey.owner_pk_field()`, the tagged Solana identity) and witnesses
        // the `nullifier_pk`, so the circuit recomputes `owner_hash` and binds the
        // tag. A dummy slot folds `solana_owner_identity` of the builder's random
        // `view_tag` so its public tag matches the program's reconstruction
        // and is indistinguishable from a real one; the circuit requires the
        // tag to identify a real input signer or output owner, while
        // `nullifier_pk` is unused (0).
        let (owner_pk_field, nullifier_pk) = match &output.owner_address {
            Some(address) => (
                address.signing_pubkey.owner_proof_input_hash()?,
                address.nullifier_pubkey,
            ),
            None => (
                solana_owner_identity(&output.owner_tag.unwrap_or([0u8; 32]))?,
                [0u8; 32],
            ),
        };
        assembled.push(TransferOutput {
            utxo: ProofInputUtxo::try_from((output, output_tree_id))?,
            is_dummy: if is_dummy {
                BigUint::from(1u8)
            } else {
                BigUint::ZERO
            },
            hash: be(&hash),
            owner_pk_hash: be(&owner_pk_field),
            nullifier_pk: be(&nullifier_pk),
        });
        hashes.push(hash);
        private_tx_hashes.push(if is_dummy { [0u8; 32] } else { hash });
        output_owner_pk_hashes.push(owner_pk_field);
    }

    Ok(AssembledOutputs {
        outputs: assembled,
        output_hashes: hashes,
        private_tx_output_hashes: private_tx_hashes,
        output_owner_pk_hashes,
    })
}

pub struct PublicInputs<'a> {
    pub nullifiers: &'a [[u8; 32]],
    pub output_hashes: &'a [[u8; 32]],
    /// The trees the inputs may be spent from. They enter the preimage as one
    /// element, the right fold over every slot's hash.
    pub tree_slots: &'a [TreeSlot; INPUT_TREES],
    /// Raw `u16` id of the tree every output is appended to.
    pub output_tree_id: u16,
    pub private_tx: &'a [u8; 32],
    pub external_data_hash: &'a [u8; 32],
    pub public_transfers: &'a PublicTransfers,
    /// Per-tx ring program (pk_field-encoded); 0 on default transact.
    pub ring_program_id: &'a [u8; 32],
    pub allow_dummy_inputs: &'a [u8; 32],
    /// Payer first, then unique appended owner signers, then zero padding.
    pub signer_pk_hashes: &'a [[u8; 32]],
    /// Appended by owner-signed rails. The default rail publishes every slot;
    /// custom-ring rails publish only confidential-encryption-marked slots.
    pub output_owner_pk_hashes: Option<&'a [[u8; 32]]>,
}

impl PublicInputs<'_> {
    pub fn hash(&self) -> Result<[u8; 32], ClientError> {
        self.hash_with_after_private_tx(&[])
    }

    /// The P256 rail's layout: the shared authorization's message hash and the
    /// default-ring P256 owner-tag hash sit directly after `private_tx`, ahead
    /// of `external_data_hash` (see the program's `public_input_hash`).
    pub fn hash_with_p256_authorization(
        &self,
        message_proof_input_hash: &[u8; 32],
        default_p256_owner_pk_hash: &[u8; 32],
    ) -> Result<[u8; 32], ClientError> {
        self.hash_with_after_private_tx(&[*message_proof_input_hash, *default_p256_owner_pk_hash])
    }

    pub(crate) fn hash_with_after_private_tx(
        &self,
        after_private_tx: &[[u8; 32]],
    ) -> Result<[u8; 32], ClientError> {
        let slots = self.public_transfers.interleaved();
        let mut elements = Vec::with_capacity(12 + after_private_tx.len() + slots.len());
        elements.extend([
            create_hash_chain_from_slice(self.nullifiers)?,
            create_hash_chain_from_slice(self.output_hashes)?,
            tree_slots_hash_chain(self.tree_slots)?,
            tree_id_field(self.output_tree_id),
            *self.private_tx,
        ]);
        elements.extend_from_slice(after_private_tx);
        elements.push(*self.external_data_hash);
        elements.extend(slots);
        elements.extend([
            *self.ring_program_id,
            create_right_hash_chain_from_slice(self.signer_pk_hashes)?,
            *self.allow_dummy_inputs,
        ]);
        if let Some(output_owner_pk_hashes) = self.output_owner_pk_hashes {
            elements.push(create_hash_chain_from_slice(output_owner_pk_hashes)?);
        }
        Ok(create_hash_chain_from_slice(&elements)?)
    }
}

pub(crate) fn bool_field(value: bool) -> [u8; 32] {
    let mut field = [0u8; 32];
    field[31] = u8::from(value);
    field
}
fn check_path_length(got: usize, expected: usize) -> Result<(), ClientError> {
    if got == expected {
        Ok(())
    } else {
        Err(ClientError::ProofPathLength { got, expected })
    }
}

#[cfg(test)]
mod tests {
    use borsh::to_vec;
    use zolana_interface::{
        instruction::{OwnerTag, TransactOutput},
        output_data::{
            OutputDataEncoding, CONFIDENTIAL_ENCRYPTED_SCHEME_TAG,
            RING_CONFIDENTIAL_ENCRYPTED_SCHEME_TAG,
        },
    };
    use zolana_keypair::{ShieldedKeypair, SigningKey};
    use zolana_transaction::Data;

    use crate::rpc::{MerkleContext, MerkleProof};

    use super::*;

    fn keypair(seed: u8) -> ShieldedKeypair {
        ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[seed; 32]))
            .expect("eddsa keypair")
    }

    fn merkle_proof(tree: u8, root: u8, root_index: u16) -> MerkleProof {
        MerkleProof {
            leaf: [0u8; 32],
            merkle_context: MerkleContext {
                tree_type: 0,
                tree: Address::new_from_array([tree; 32]),
            },
            path: vec![[0u8; 32]; STATE_TREE_HEIGHT],
            leaf_index: 0,
            root: [root; 32],
            root_seq: 0,
            root_index,
        }
    }

    fn non_inclusion_proof(root: u8, root_index: u16) -> NonInclusionProof {
        NonInclusionProof {
            leaf: [0u8; 32],
            merkle_context: MerkleContext {
                tree_type: 0,
                tree: Address::new_from_array([9u8; 32]),
            },
            path: vec![[0u8; 32]; NULLIFIER_TREE_HEIGHT],
            low_element: [0u8; 32],
            low_element_index: 0,
            high_element: [u8::MAX; 32],
            high_element_index: 1,
            root: [root; 32],
            root_seq: 0,
            root_index,
        }
    }

    /// A real spend of `amount` from the tree named by `tree`, proven against
    /// `(state_root, state_root_index)` and `(nullifier_root, 7)`.
    fn spend(
        seed: u8,
        tree: u8,
        state_root: u8,
        state_root_index: u16,
        nullifier_root: u8,
    ) -> TransferSpendInput {
        let owner = keypair(seed);
        TransferSpendInput {
            utxo: Utxo {
                owner: owner.signing_pubkey(),
                asset: zolana_transaction::SOL_MINT,
                amount: 0,
                blinding: [0u8; 32],
                ring_program_id: None,
                data: Data::default(),
            },
            nullifier_key: owner.nullifier_key.clone(),
            data_hash: None,
            ring_data_hash: None,
            tree_id: 0,
            proof: Some(SpendProof {
                state: merkle_proof(tree, state_root, state_root_index),
                nullifier: non_inclusion_proof(nullifier_root, 7),
            }),
            nullifier_proof: None,
        }
    }

    /// A padding slot; `nullifier_proof` is the dummy's own non-inclusion
    /// witness against `(nullifier_root, nullifier_root_index)` when given.
    fn dummy(nullifier_proof: Option<(u8, u16)>) -> TransferSpendInput {
        TransferSpendInput {
            utxo: Utxo {
                owner: zolana_keypair::PublicKey::zeroed(),
                asset: zolana_transaction::SOL_MINT,
                amount: 0,
                blinding: [1u8; 32],
                ring_program_id: None,
                data: Data::default(),
            },
            nullifier_key: zolana_keypair::NullifierKey::from_secret([0u8; 31]),
            data_hash: None,
            ring_data_hash: None,
            tree_id: 0,
            proof: None,
            nullifier_proof: nullifier_proof
                .map(|(root, root_index)| non_inclusion_proof(root, root_index)),
        }
    }

    #[test]
    fn inputs_fill_tree_slot_zero_from_the_one_input_tree() {
        let spends = [
            spend(1, 0xAA, 0x11, 3, 0x33),
            dummy(Some((0x33, 7))),
            spend(2, 0xAA, 0x11, 3, 0x33),
        ];

        let assembled =
            assemble_inputs(&spends, &OwnerMode::ConfidentialEddsa).expect("assemble inputs");

        assert_eq!(assembled.utxo_tree_root_index, 3);
        assert_eq!(assembled.nullifier_tree_root_index, 7);
        assert_eq!(
            assembled.tree_slots,
            [
                TreeSlot::new(0, [0x11; 32], [0x33; 32]),
                TreeSlot::ZERO,
                TreeSlot::ZERO,
                TreeSlot::ZERO,
                TreeSlot::ZERO,
            ]
        );
        // Every input, the dummy included, selects slot 0.
        assert!(assembled
            .inputs
            .iter()
            .all(|input| input.tree_slot == BigUint::ZERO));
    }

    #[test]
    fn inputs_from_two_trees_are_rejected() {
        let spends = [
            spend(1, 0xAA, 0x11, 3, 0x33),
            spend(2, 0xBB, 0x11, 3, 0x33),
            spend(3, 0xCC, 0x11, 3, 0x33),
        ];

        assert!(matches!(
            assemble_inputs(&spends, &OwnerMode::ConfidentialEddsa),
            Err(ClientError::MultipleInputTreesUnsupported { got: 3 })
        ));
    }

    #[test]
    fn one_tree_with_two_utxo_roots_is_rejected() {
        let spends = [spend(1, 0xAA, 0x11, 3, 0x33), spend(2, 0xAA, 0x12, 3, 0x33)];

        assert!(matches!(
            assemble_inputs(&spends, &OwnerMode::ConfidentialEddsa),
            Err(ClientError::InputTreeRootMismatch)
        ));
    }

    #[test]
    fn one_tree_with_two_utxo_root_indexes_is_rejected() {
        let spends = [spend(1, 0xAA, 0x11, 3, 0x33), spend(2, 0xAA, 0x11, 4, 0x33)];

        assert!(matches!(
            assemble_inputs(&spends, &OwnerMode::ConfidentialEddsa),
            Err(ClientError::InputTreeRootMismatch)
        ));
    }

    #[test]
    fn one_tree_with_two_tree_ids_is_rejected() {
        let mut other = spend(2, 0xAA, 0x11, 3, 0x33);
        other.tree_id = 1;
        let spends = [spend(1, 0xAA, 0x11, 3, 0x33), other];

        assert!(matches!(
            assemble_inputs(&spends, &OwnerMode::ConfidentialEddsa),
            Err(ClientError::InputTreeRootMismatch)
        ));
    }

    #[test]
    fn disagreeing_nullifier_roots_are_rejected() {
        let spends = [spend(1, 0xAA, 0x11, 3, 0x33), spend(2, 0xAA, 0x11, 3, 0x34)];

        assert!(matches!(
            assemble_inputs(&spends, &OwnerMode::ConfidentialEddsa),
            Err(ClientError::NullifierRootMismatch)
        ));
    }

    #[test]
    fn a_dummy_with_a_different_nullifier_root_index_is_rejected() {
        let spends = [spend(1, 0xAA, 0x11, 3, 0x33), dummy(Some((0x33, 8)))];

        assert!(matches!(
            assemble_inputs(&spends, &OwnerMode::ConfidentialEddsa),
            Err(ClientError::NullifierRootMismatch)
        ));
    }

    #[test]
    fn padding_without_a_real_spend_has_no_slot_zero() {
        assert!(matches!(
            assemble_inputs(&[dummy(Some((0x33, 7)))], &OwnerMode::ConfidentialEddsa),
            Err(ClientError::NoInputs)
        ));
    }

    #[test]
    fn ring_output_marker_masks_the_published_owner() {
        let default_tag = [1u8; 32];
        let ring_tag = [2u8; 32];
        let output = |scheme, tag| TransactOutput {
            utxo_hash: [0u8; 32],
            owner_tag: OwnerTag::Inline(tag),
            data: Some(
                to_vec(&OutputDataEncoding::Encrypted(vec![scheme, 9])).expect("output encoding"),
            ),
        };
        let external_data = ExternalData {
            instruction_discriminator: 0,
            expiry_unix_ts: 0,
            interface_transfers: Vec::new(),
            data_hash: None,
            ring_data_hash: None,
            tx_viewing_pk: [0u8; 33],
            salt: [0u8; 16],
            outputs: vec![
                output(CONFIDENTIAL_ENCRYPTED_SCHEME_TAG, default_tag),
                output(RING_CONFIDENTIAL_ENCRYPTED_SCHEME_TAG, ring_tag),
            ],
            resolved_owner_tags: vec![default_tag, ring_tag],
            messages: Vec::new(),
        };

        assert_eq!(
            confidential_marked_output_owner_pk_hashes(&external_data).expect("published owners"),
            vec![
                solana_owner_identity(&default_tag).expect("owner hash"),
                [0u8; 32],
            ]
        );
    }
}
