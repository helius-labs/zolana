use num_bigint::BigUint;
use zolana_event::is_confidential_encrypted_output;
use zolana_hasher::{
    hash_chain::{create_hash_chain_4_from_slice, create_right_hash_chain_from_slice},
    primitives::solana_owner_identity,
};
use zolana_interface::{
    instruction::instruction_data::transact::{InputUtxo, TreeContext},
    tree_slot::{pack_input_flags, tree_id_field, tree_slots_hash_chain, TreeSlot},
    INPUT_TREES, MAX_INPUT_TREES,
};
use zolana_keypair::Curve;
use zolana_transaction::{
    instructions::transact::{
        validate_input_tree_order, PrivateTxHash, PublicTransfers, Shape, SPP_SUPPORTED_SHAPES,
    },
    utxo::SppProofInputUtxo,
    utxo::{
        derive_output_blinding_seed, derive_private_tx_blinding, derive_transact_output_blinding,
    },
    ExternalData, SppProofOutputUtxo,
};

use crate::{
    error::ClientError,
    prover::{
        field::be,
        transact::witness::{validate_nullifier_proof, SpendProof},
        ProofInputUtxo, TransferInput, TransferOutput,
    },
    rpc::{NonInclusionProof, STATE_TREE_HEIGHT},
};

/// One input ready for the witness: the input UTXO the builder produced and the
/// witnesses fetched for it.
///
/// The input UTXO itself is not copied field by field. It arrives complete, and
/// the two values added here are the ones only the client has, both fetched
/// from the indexer. No secret: a real input leaves assembly with its
/// [`TransferInput::nullifier_secret`](crate::prover::TransferInput) absent,
/// and the owner's
/// [`ProofAuthority`](crate::authority::ProofAuthority) fills it in when it
/// proves.
#[derive(Clone)]
pub struct TransferInputUtxo {
    pub utxo: SppProofInputUtxo,
    /// `Some` for a real input, `None` for a padding (dummy) slot. A dummy has
    /// no state proof of its own; it takes the tree slot of the tree whose raw
    /// id its `tree_id` names.
    pub proof: Option<SpendProof>,
    /// Padding slots only: the fetched non-inclusion proof for the dummy's own
    /// nullifier. The circuit checks non-inclusion for every slot, dummies
    /// included, so a dummy needs a real low-element witness.
    pub nullifier_proof: Option<NonInclusionProof>,
}

pub(crate) struct AssembledInputs {
    pub inputs: Vec<TransferInput>,
    pub input_hashes: Vec<[u8; 32]>,
    pub nullifiers: Vec<[u8; 32]>,
    /// The circuit's tree slots: one populated slot per input tree, in the
    /// order the tree accounts are passed; the remaining slots are all zero.
    pub tree_slots: [TreeSlot; INPUT_TREES],
    /// One root-index pair per input tree, in the same order as `tree_slots`.
    pub tree_contexts: Vec<TreeContext>,
    /// The declared trees' raw ids, parallel to `tree_contexts`. The `Transact`
    /// builder takes one tree account per context entry in the same order, and
    /// this is where those accounts are derived from.
    pub tree_ids: Vec<u16>,
    /// Each assembled input's index into `tree_contexts`, in slot order.
    /// Non-decreasing, so every tree owns one contiguous run of inputs.
    pub input_tree_indexes: Vec<u8>,
}

impl AssembledInputs {
    /// The one input tree of a single-tree spend. Merge resolves roots from one
    /// tree per instruction, so it rejects anything wider here.
    pub fn single_tree_context(&self) -> Result<TreeContext, ClientError> {
        match self.tree_contexts.as_slice() {
            [context] => Ok(*context),
            contexts => Err(ClientError::TooManyInputTrees {
                got: contexts.len(),
                max: 1,
            }),
        }
    }
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

/// One tree a set of padded inputs is spent from: the raw id its UTXOs are
/// hashed under, and the two roots every input in its run is proven against.
/// It fills one circuit tree slot.
///
/// The tree account is `pda::tree(tree_id)` and is not carried: the id is what
/// every input names, and the caller derives the account where SPP needs one.
struct InputTree {
    tree_id: u16,
    utxo_root: [u8; 32],
    utxo_root_index: u16,
    nullifier_root: [u8; 32],
    nullifier_root_index: u16,
}

/// The input trees a transaction declares, in first-use order. A tree's position here
/// is both its circuit tree slot and the `tree_index` its inputs carry in the
/// instruction, so the proof and the program route every input to the same
/// tree.
struct InputTrees {
    trees: Vec<InputTree>,
}

impl InputTrees {
    fn get(&self, tree_index: u8) -> Result<&InputTree, ClientError> {
        self.trees
            .get(usize::from(tree_index))
            .ok_or(ClientError::TooManyInputTrees {
                got: usize::from(tree_index).saturating_add(1),
                max: MAX_INPUT_TREES,
            })
    }

    /// The slot an input selects: the tree whose raw id it was hashed under.
    /// Real inputs and padding pick the same way, because the id is the only
    /// thing either of them names.
    fn index_of(&self, input_utxo: &TransferInputUtxo) -> Option<u8> {
        let position = self
            .trees
            .iter()
            .position(|tree| tree.tree_id == input_utxo.utxo.tree_id)?;
        u8::try_from(position).ok()
    }

    /// The declared trees' raw ids, in the order their slots and their
    /// `tree_contexts` entries are in. The `Transact` builder takes one tree
    /// account per context entry in this order.
    fn tree_ids(&self) -> Vec<u16> {
        self.trees.iter().map(|tree| tree.tree_id).collect()
    }

    fn tree_slots(&self) -> [TreeSlot; INPUT_TREES] {
        let mut slots = [TreeSlot::ZERO; INPUT_TREES];
        for (slot, tree) in slots.iter_mut().zip(self.trees.iter()) {
            *slot = TreeSlot::new(tree.tree_id, tree.utxo_root, tree.nullifier_root);
        }
        slots
    }

    fn tree_contexts(&self) -> Vec<TreeContext> {
        self.trees
            .iter()
            .map(|tree| TreeContext {
                utxo_tree_root_index: tree.utxo_root_index,
                nullifier_tree_root_index: tree.nullifier_root_index,
            })
            .collect()
    }
}

/// Resolve the input trees and their roots, in first-use order. A tree is the
/// raw id its inputs are hashed under, which is the only name either a real
/// input or a dummy carries. SPP resolves one root pair per declared tree, so
/// every real input from a tree must share its UTXO root and root index, and
/// every non-inclusion proof of that tree's run (its padding included) must
/// share its nullifier root and root index.
fn resolve_input_trees(input_utxos: &[TransferInputUtxo]) -> Result<InputTrees, ClientError> {
    let mut trees: Vec<InputTree> = Vec::with_capacity(1);

    for input_utxo in input_utxos {
        let Some(proof) = &input_utxo.proof else {
            continue;
        };
        let tree_id = input_utxo.utxo.tree_id;
        let nullifier_proof = &proof.nullifier;
        match trees.iter().find(|tree| tree.tree_id == tree_id) {
            Some(tree) => {
                if (tree.utxo_root, tree.utxo_root_index)
                    != (proof.state.root, proof.state.root_index)
                {
                    return Err(ClientError::InputTreeRootMismatch);
                }
                if (tree.nullifier_root, tree.nullifier_root_index)
                    != (nullifier_proof.root, nullifier_proof.root_index)
                {
                    return Err(ClientError::NullifierRootMismatch);
                }
            }
            None => {
                trees.push(InputTree {
                    tree_id,
                    utxo_root: proof.state.root,
                    utxo_root_index: proof.state.root_index,
                    nullifier_root: nullifier_proof.root,
                    nullifier_root_index: nullifier_proof.root_index,
                });
            }
        }
    }

    if trees.len() > MAX_INPUT_TREES {
        return Err(ClientError::TooManyInputTrees {
            got: trees.len(),
            max: MAX_INPUT_TREES,
        });
    }
    // The input trees supply the ids every dummy is hashed under, so a proof
    // without a real input has nothing to anchor its padding to.
    if trees.is_empty() {
        return Err(ClientError::NoInputs);
    }
    let trees = InputTrees { trees };

    for input_utxo in input_utxos {
        if input_utxo.proof.is_some() {
            continue;
        }
        let tree_index = trees
            .index_of(input_utxo)
            .ok_or(ClientError::InputTreeUnresolved {
                tree_id: input_utxo.utxo.tree_id,
            })?;
        let tree = trees.get(tree_index)?;
        if let Some(nullifier_proof) = &input_utxo.nullifier_proof {
            if (tree.nullifier_root, tree.nullifier_root_index)
                != (nullifier_proof.root, nullifier_proof.root_index)
            {
                return Err(ClientError::NullifierRootMismatch);
            }
        }
    }

    Ok(trees)
}

/// Convert the already-padded inputs into circuit witness fields. Makes no
/// padding decisions: each slot with a [`SpendProof`] is a real input hashed
/// under its own tree's id; each slot without one is a dummy hashed under the
/// tree it was assigned, with a zero private owner hash and its own nullifier
/// non-inclusion witness. Inputs must already be grouped tree by tree in
/// first-use order, including padding. Assembly preserves the order committed
/// by the signing hash. A transaction must spend at least one real input, because
/// the input trees come from the real ones.
pub(crate) fn assemble_inputs(
    input_utxos: &[TransferInputUtxo],
    owner_mode: &OwnerMode,
) -> Result<AssembledInputs, ClientError> {
    for (index, input) in input_utxos.iter().enumerate() {
        input.validate(index)?;
    }
    let trees = resolve_input_trees(input_utxos)?;
    validate_input_tree_order(input_utxos.iter().map(|input_utxo| input_utxo.utxo.tree_id))?;

    let mut inputs = Vec::with_capacity(input_utxos.len());
    let mut input_hashes = Vec::with_capacity(input_utxos.len());
    let mut nullifiers = Vec::with_capacity(input_utxos.len());
    let mut input_tree_indexes = Vec::with_capacity(input_utxos.len());

    for (index, input_utxo) in input_utxos.iter().enumerate() {
        let tree_index = trees
            .index_of(input_utxo)
            .ok_or(ClientError::InputTreeUnresolved {
                tree_id: input_utxo.utxo.tree_id,
            })?;
        input_tree_indexes.push(tree_index);
        if input_utxo.utxo.is_dummy() {
            let nf = input_utxo
                .nullifier_proof
                .as_ref()
                .ok_or(ClientError::MissingDummyNullifierProof { index })?;
            inputs.push(TransferInput {
                utxo: ProofInputUtxo::try_from(&input_utxo.utxo)?,
                is_dummy: BigUint::from(1u8),
                state_path_elements: vec![BigUint::ZERO; STATE_TREE_HEIGHT],
                state_path_index: BigUint::ZERO,
                nullifier_low_value: be(&nf.low_element),
                nullifier_next_value: be(&nf.high_element),
                nullifier_low_path_elements: nf.path.iter().map(be).collect(),
                nullifier_low_path_index: BigUint::from(nf.low_element_index),
                tree_slot: BigUint::from(tree_index),
                nullifier: be(&input_utxo.utxo.nullifier),
                owner_pk_hash: BigUint::ZERO,
                nullifier_secret: Some(BigUint::ZERO),
            });
            input_hashes.push([0u8; 32]);
            nullifiers.push(input_utxo.utxo.nullifier);
            continue;
        }
        let proof = input_utxo
            .proof
            .as_ref()
            .ok_or(ClientError::MissingInputMerkleProof { index })?;

        let utxo_inputs = ProofInputUtxo::try_from(&input_utxo.utxo)?;
        // Both arrive computed on the input UTXO. Recomputing them would give a
        // second source for one value, and a disagreement would only surface as
        // a proof that does not verify.
        let utxo_hash = input_utxo.utxo.utxo_hash;
        let nullifier = input_utxo.utxo.nullifier;

        let is_p256 = input_utxo.utxo.utxo.owner.curve()? == Curve::P256;
        // Per-input owner pk_field, selected by mode. A P256 owner's value
        // depends on the mode (see OwnerMode); an ed25519 owner always uses
        // its own pk_field.
        let owner_pk_hash = match (owner_mode, is_p256) {
            (OwnerMode::Merge | OwnerMode::RingP256, true) => [0u8; 32],
            (OwnerMode::ConfidentialEddsa, true) => {
                return Err(ClientError::EddsaInputNotSolanaOwned { index })
            }
            (OwnerMode::RingAuthority, true) => {
                input_utxo.utxo.utxo.owner.owner_proof_input_hash()?
            }
            (_, false) => input_utxo.utxo.utxo.owner.owner_proof_input_hash()?,
        };

        let state = &proof.state;
        let nf = &proof.nullifier;

        inputs.push(TransferInput {
            utxo: utxo_inputs,
            is_dummy: BigUint::ZERO,
            state_path_elements: state.path.iter().map(be).collect(),
            state_path_index: BigUint::from(state.leaf_index),
            nullifier_low_value: be(&nf.low_element),
            nullifier_next_value: be(&nf.high_element),
            nullifier_low_path_elements: nf.path.iter().map(be).collect(),
            nullifier_low_path_index: BigUint::from(nf.low_element_index),
            tree_slot: BigUint::from(tree_index),
            nullifier: be(&nullifier),
            owner_pk_hash: be(&owner_pk_hash),
            // A real input proves ownership from the secret itself, and this is
            // the one witness field no input UTXO carries. It stays absent
            // until the owner's authority completes the witness, so assembly
            // never touches key material.
            nullifier_secret: None,
        });
        input_hashes.push(utxo_hash);
        nullifiers.push(nullifier);
    }

    Ok(AssembledInputs {
        inputs,
        input_hashes,
        nullifiers,
        tree_slots: trees.tree_slots(),
        tree_contexts: trees.tree_contexts(),
        tree_ids: trees.tree_ids(),
        input_tree_indexes,
    })
}

/// Convert the already-padded outputs into circuit witness fields. A dummy output
/// (`owner_hash == 0`: empty change or tail padding) still puts its real hash in the
/// public `output_hashes` but contributes `0` to the private-tx hash chain.
/// The private transaction hash, from the vectors one assembly pass produced.
///
/// Every rail folds the same four values in the same order, and the two hash
/// vectors are the ones `assemble_inputs` and `assemble_outputs` emit -- not a
/// second selection of them. A rail that picked `output_hashes` where this
/// picks `private_tx_output_hashes` would publish a hash the circuit does not
/// agree with, and nothing would report it until the proof failed to verify.
/// One construction site is what stops the two vectors being confused rail by
/// rail.
pub(crate) fn private_tx_hash(
    inputs: &AssembledInputs,
    outputs: &AssembledOutputs,
    external_data_hash: &[u8; 32],
    private_tx_blinding: &[u8; 32],
) -> Result<[u8; 32], ClientError> {
    Ok(PrivateTxHash::new(
        &inputs.input_hashes,
        &outputs.private_tx_output_hashes,
        external_data_hash,
        private_tx_blinding,
    )
    .hash()?)
}

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
    /// The transaction's dummy-input policy packed with every input's tree
    /// index, built by [`zolana_interface::tree_slot::pack_input_flags`]. It
    /// occupies the element the plain dummy-input boolean used to.
    pub input_flags: &'a [u8; 32],
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

    pub(crate) fn hash_with_after_private_tx(
        &self,
        after_private_tx: &[[u8; 32]],
    ) -> Result<[u8; 32], ClientError> {
        let slots = self.public_transfers.interleaved();
        let mut elements = Vec::with_capacity(12 + after_private_tx.len() + slots.len());
        elements.extend([
            create_hash_chain_4_from_slice(self.nullifiers)?,
            create_hash_chain_4_from_slice(self.output_hashes)?,
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
            *self.input_flags,
        ]);
        if let Some(output_owner_pk_hashes) = self.output_owner_pk_hashes {
            elements.push(create_hash_chain_4_from_slice(output_owner_pk_hashes)?);
        }
        Ok(create_hash_chain_4_from_slice(&elements)?)
    }
}

/// Pair each published nullifier with the index of the tree its input is
/// nullified in, in slot order. The two vectors come from one
/// [`assemble_inputs`] pass, so a length mismatch is a builder bug.
pub fn input_utxos_from_nullifiers(
    nullifiers: &[[u8; 32]],
    tree_indexes: &[u8],
) -> Result<Vec<InputUtxo>, ClientError> {
    if nullifiers.len() != tree_indexes.len() {
        return Err(ClientError::WitnessInputCountMismatch {
            got: tree_indexes.len(),
            expected: nullifiers.len(),
        });
    }
    Ok(nullifiers
        .iter()
        .zip(tree_indexes)
        .map(|(nullifier_hash, tree_index)| InputUtxo {
            nullifier_hash: *nullifier_hash,
            tree_index: *tree_index,
        })
        .collect())
}

impl TransferInputUtxo {
    pub(crate) fn validate(&self, index: usize) -> Result<(), ClientError> {
        let input = &self.utxo;
        if ProofInputUtxo::try_from(input)?.hash()? != input.utxo_hash {
            return Err(
                zolana_transaction::TransactionError::InputCommitmentMismatch { index }.into(),
            );
        }
        if input.is_dummy() {
            if self.proof.is_some() {
                return Err(ClientError::UnexpectedInputProof { index });
            }
            let proof = self
                .nullifier_proof
                .as_ref()
                .ok_or(ClientError::MissingDummyNullifierProof { index })?;
            validate_nullifier_proof(proof, input, index)
        } else {
            if self.nullifier_proof.is_some() {
                return Err(ClientError::UnexpectedInputProof { index });
            }
            self.proof
                .as_ref()
                .ok_or(ClientError::MissingInputMerkleProof { index })?
                .validate(input, index)
        }
    }
}

pub(crate) fn validate_shape(shape: Shape, n_in: usize, n_out: usize) -> Result<(), ClientError> {
    if !SPP_SUPPORTED_SHAPES.contains(&shape)
        || shape.n_inputs() != n_in
        || shape.n_outputs() != n_out
    {
        return Err(ClientError::UnsupportedShape { n_in, n_out });
    }
    Ok(())
}

pub(crate) struct AssembledTransaction {
    pub inputs: AssembledInputs,
    pub outputs: AssembledOutputs,
    pub external_data_hash: [u8; 32],
    pub private_tx_hash: [u8; 32],
    pub input_flags: [u8; 32],
}

pub(crate) fn assemble_transaction(
    inputs: &[TransferInputUtxo],
    outputs: &[SppProofOutputUtxo],
    blinding_seed: &[u8; 32],
    output_tree_id: u16,
    external_data: &ExternalData,
    owner_mode: &OwnerMode,
    allow_dummy_inputs: bool,
) -> Result<AssembledTransaction, ClientError> {
    if !allow_dummy_inputs {
        if let Some(index) = inputs.iter().position(|input| input.utxo.is_dummy()) {
            return Err(ClientError::NonSpendInputNotAllowed { index });
        }
    }
    let inputs = assemble_inputs(inputs, owner_mode)?;
    let input_flags = pack_input_flags(
        allow_dummy_inputs,
        inputs.input_tree_indexes.iter().copied(),
    )?;
    let first_nullifier = inputs.nullifiers.first().ok_or(ClientError::NoInputs)?;
    let output_seed = derive_output_blinding_seed(first_nullifier, blinding_seed)?;
    for (index, output) in outputs.iter().enumerate() {
        let output_index = u32::try_from(index).map_err(|_| ClientError::TooManyOutputs {
            got: outputs.len(),
            max: u32::MAX as usize,
        })?;
        let expected =
            derive_transact_output_blinding(first_nullifier, &output_seed, output_index)?;
        if output.blinding != expected {
            return Err(ClientError::OutputBlindingMismatch { index });
        }
    }
    let outputs = assemble_outputs(outputs, output_tree_id)?;
    let external_data_hash = external_data.hash()?;
    let blinding = derive_private_tx_blinding(first_nullifier, blinding_seed)?;
    let private_tx_hash = private_tx_hash(&inputs, &outputs, &external_data_hash, &blinding)?;
    Ok(AssembledTransaction {
        inputs,
        outputs,
        external_data_hash,
        private_tx_hash,
        input_flags,
    })
}

#[cfg(test)]
mod tests {

    fn wallet_input(
        utxo: Utxo,
        key: &zolana_keypair::NullifierKey,
        tree_id: u16,
    ) -> zolana_transaction::WalletUtxo {
        let nullifier_pubkey = key.pubkey().unwrap();
        let utxo_hash = utxo
            .hash(&nullifier_pubkey, &[0; 32], &[0; 32], tree_id)
            .unwrap();
        let nullifier = key.nullifier(&utxo_hash, &utxo.blinding).unwrap();
        zolana_transaction::WalletUtxo {
            utxo,
            nullifier_pubkey,
            utxo_hash,
            nullifier,
            data_hash: None,
            ring_data_hash: None,
            tree_id,
            leaf_index: 0,
            slot: 0,
            tx_signature: Default::default(),
            slot_index: 0,
        }
    }

    use borsh::to_vec;
    use zolana_keypair::{ShieldedKeypair, SigningKey};
    use zolana_transaction::{utxo::SppProofInputUtxo, Data, Utxo};

    use crate::rpc::{MerkleContext, MerkleProof, NULLIFIER_TREE_HEIGHT};
    use zolana_event::{
        OutputDataEncoding, CONFIDENTIAL_ENCRYPTED_SCHEME_TAG,
        RING_CONFIDENTIAL_ENCRYPTED_SCHEME_TAG,
    };
    use zolana_interface::instruction::{OwnerTag, TransactOutput};

    use super::*;

    fn keypair(seed: u8) -> ShieldedKeypair {
        ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[seed; 32]))
            .expect("eddsa keypair")
    }

    fn merkle_proof(tree_id: u16, root: u8, root_index: u16) -> MerkleProof {
        MerkleProof {
            leaf: [0u8; 32],
            merkle_context: MerkleContext {
                tree_type: 0,
                tree: zolana_interface::pda::tree(tree_id),
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
                tree: zolana_interface::pda::tree(9),
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

    /// A real input hashed under `tree_id`, proven against
    /// `(state_root, state_root_index)` and `(nullifier_root, 7)`. The tree is
    /// the id and nothing else: its account is `pda::tree(tree_id)`, which the
    /// proof names because that is what the fetch asked for.
    fn input_utxo_in(
        seed: u8,
        tree_id: u16,
        state_root: u8,
        state_root_index: u16,
        nullifier_root: u8,
    ) -> TransferInputUtxo {
        let owner = keypair(seed);
        let utxo: SppProofInputUtxo = wallet_input(
            Utxo {
                owner: owner.signing_pubkey(),
                asset: zolana_transaction::Mint::SOL,
                amount: 0,
                blinding: [0u8; 32],
                ring_program_id: None,
                data: Data::default(),
            },
            &owner.nullifier_key,
            tree_id,
        )
        .into();
        let mut state = merkle_proof(tree_id, state_root, state_root_index);
        state.leaf = utxo.utxo_hash;
        let mut nullifier = non_inclusion_proof(nullifier_root, 7);
        nullifier.leaf = utxo.nullifier;
        nullifier.merkle_context.tree = zolana_interface::pda::tree(tree_id);
        TransferInputUtxo {
            utxo,
            proof: Some(SpendProof { state, nullifier }),
            nullifier_proof: None,
        }
    }

    /// A real input under tree id 0.
    fn input_utxo(
        seed: u8,
        state_root: u8,
        state_root_index: u16,
        nullifier_root: u8,
    ) -> TransferInputUtxo {
        input_utxo_in(seed, 0, state_root, state_root_index, nullifier_root)
    }

    /// A padding slot hashed under tree id `tree_id`; `nullifier_proof` is the
    /// dummy's own non-inclusion witness against
    /// `(nullifier_root, nullifier_root_index)` when given.
    fn dummy_in(tree_id: u16, nullifier_proof: Option<(u8, u16)>) -> TransferInputUtxo {
        let utxo = SppProofInputUtxo::dummy_with_blinding([1u8; 32], tree_id).unwrap();
        let nullifier_proof = nullifier_proof.map(|(root, root_index)| {
            let mut proof = non_inclusion_proof(root, root_index);
            proof.leaf = utxo.nullifier;
            proof.merkle_context.tree = zolana_interface::pda::tree(tree_id);
            proof
        });
        TransferInputUtxo {
            utxo,
            proof: None,
            nullifier_proof,
        }
    }

    /// A padding slot under tree id 0.
    fn dummy(nullifier_proof: Option<(u8, u16)>) -> TransferInputUtxo {
        dummy_in(0, nullifier_proof)
    }

    #[test]
    fn inputs_fill_tree_slot_zero_from_the_one_input_tree() {
        let input_utxos = [
            input_utxo(1, 0x11, 3, 0x33),
            dummy(Some((0x33, 7))),
            input_utxo(2, 0x11, 3, 0x33),
        ];

        let assembled =
            assemble_inputs(&input_utxos, &OwnerMode::ConfidentialEddsa).expect("assemble inputs");

        assert_eq!(
            assembled.tree_contexts,
            vec![TreeContext {
                utxo_tree_root_index: 3,
                nullifier_tree_root_index: 7,
            }]
        );
        assert_eq!(assembled.input_tree_indexes, vec![0, 0, 0]);
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

    /// Two input trees each populate their own slot without changing input order.
    #[test]
    fn inputs_from_two_trees_fill_two_slots_grouped_by_tree() {
        let input_utxos = [
            input_utxo_in(1, 0, 0x11, 3, 0x33),
            input_utxo_in(3, 0, 0x11, 3, 0x33),
            input_utxo_in(2, 1, 0x12, 4, 0x34),
            dummy_in(1, Some((0x34, 7))),
        ];

        let assembled =
            assemble_inputs(&input_utxos, &OwnerMode::ConfidentialEddsa).expect("assemble inputs");

        assert_eq!(
            assembled.tree_contexts,
            vec![
                TreeContext {
                    utxo_tree_root_index: 3,
                    nullifier_tree_root_index: 7,
                },
                TreeContext {
                    utxo_tree_root_index: 4,
                    nullifier_tree_root_index: 7,
                },
            ]
        );
        assert_eq!(assembled.input_tree_indexes, vec![0, 0, 1, 1]);
        assert_eq!(
            assembled.tree_slots,
            [
                TreeSlot::new(0, [0x11; 32], [0x33; 32]),
                TreeSlot::new(1, [0x12; 32], [0x34; 32]),
                TreeSlot::ZERO,
                TreeSlot::ZERO,
                TreeSlot::ZERO,
            ]
        );
        let slots: Vec<BigUint> = assembled
            .inputs
            .iter()
            .map(|input| input.tree_slot.clone())
            .collect();
        assert_eq!(
            slots,
            vec![
                BigUint::ZERO,
                BigUint::ZERO,
                BigUint::from(1u8),
                BigUint::from(1u8),
            ]
        );
    }

    #[test]
    fn interleaved_inputs_are_rejected_without_reordering() {
        for last in [
            input_utxo_in(3, 4, 0x11, 3, 0x33),
            dummy_in(4, Some((0x33, 7))),
        ] {
            let input_utxos = [
                input_utxo_in(1, 4, 0x11, 3, 0x33),
                input_utxo_in(2, 1, 0x12, 4, 0x34),
                last,
            ];
            assert!(matches!(
                assemble_inputs(&input_utxos, &OwnerMode::RingP256),
                Err(ClientError::Transaction(
                    zolana_transaction::TransactionError::InterleavedInputTrees {
                        index: 2,
                        tree_id: 4
                    }
                ))
            ));
        }
    }

    #[test]
    fn more_input_trees_than_the_program_limit_are_rejected() {
        let input_utxos: Vec<TransferInputUtxo> = (0..=MAX_INPUT_TREES)
            .map(|index| {
                let marker = u8::try_from(index).expect("tree marker");
                let tree_id = u16::try_from(index).expect("tree id");
                input_utxo_in(marker, tree_id, 0x11, 3, 0x33)
            })
            .collect();

        assert!(matches!(
            assemble_inputs(&input_utxos, &OwnerMode::ConfidentialEddsa),
            Err(ClientError::TooManyInputTrees { got, max }) if got == MAX_INPUT_TREES + 1 && max == MAX_INPUT_TREES
        ));
    }

    #[test]
    fn padding_hashed_under_an_undeclared_tree_is_rejected() {
        let input_utxos = [input_utxo(1, 0x11, 3, 0x33), dummy_in(9, Some((0x33, 7)))];

        assert!(matches!(
            assemble_inputs(&input_utxos, &OwnerMode::ConfidentialEddsa),
            Err(ClientError::InputTreeUnresolved { tree_id: 9 })
        ));
    }

    #[test]
    fn one_tree_with_two_utxo_roots_is_rejected() {
        let input_utxos = [input_utxo(1, 0x11, 3, 0x33), input_utxo(2, 0x12, 3, 0x33)];

        assert!(matches!(
            assemble_inputs(&input_utxos, &OwnerMode::ConfidentialEddsa),
            Err(ClientError::InputTreeRootMismatch)
        ));
    }

    #[test]
    fn one_tree_with_two_utxo_root_indexes_is_rejected() {
        let input_utxos = [input_utxo(1, 0x11, 3, 0x33), input_utxo(2, 0x11, 4, 0x33)];

        assert!(matches!(
            assemble_inputs(&input_utxos, &OwnerMode::ConfidentialEddsa),
            Err(ClientError::InputTreeRootMismatch)
        ));
    }

    #[test]
    fn disagreeing_nullifier_roots_are_rejected() {
        let input_utxos = [input_utxo(1, 0x11, 3, 0x33), input_utxo(2, 0x11, 3, 0x34)];

        assert!(matches!(
            assemble_inputs(&input_utxos, &OwnerMode::ConfidentialEddsa),
            Err(ClientError::NullifierRootMismatch)
        ));
    }

    #[test]
    fn a_dummy_with_a_different_nullifier_root_index_is_rejected() {
        let input_utxos = [input_utxo(1, 0x11, 3, 0x33), dummy(Some((0x33, 8)))];

        assert!(matches!(
            assemble_inputs(&input_utxos, &OwnerMode::ConfidentialEddsa),
            Err(ClientError::NullifierRootMismatch)
        ));
    }

    #[test]
    fn padding_without_a_real_input_has_no_slot_zero() {
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
