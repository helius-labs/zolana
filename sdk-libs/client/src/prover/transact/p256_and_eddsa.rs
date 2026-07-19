use num_bigint::BigUint;
use zolana_hasher::hash_chain::create_hash_chain_from_slice;
use zolana_keypair::{
    hash::{hash_field, sha256, split_be_128},
    NullifierKey, P256Pubkey, PublicKey, SignatureType,
};
use zolana_transaction::{
    instructions::transact::PrivateTxHash, ExternalData, ProofInputUtxo, SppProofOutputUtxo, Utxo,
};

use crate::{
    error::ClientError,
    prover::{
        field::{be, right_align_slice},
        resolve_shape,
        transact::witness::SpendProof,
        Shape, TransferInput, TransferOutput, TransferP256Inputs,
    },
    rpc::{NULLIFIER_TREE_HEIGHT, STATE_TREE_HEIGHT},
};

#[derive(Clone)]
pub struct TransferSpendInput {
    pub utxo: Utxo,
    pub nullifier_key: NullifierKey,
    pub data_hash: Option<[u8; 32]>,
    pub zone_data_hash: Option<[u8; 32]>,
    /// `Some` for a real spend, `None` for a padding (dummy) slot. A dummy mirrors
    /// the first real input's roots, so it has no proof of its own.
    pub proof: Option<SpendProof>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicAmounts {
    pub sol: [u8; 32],
    pub spl: [u8; 32],
    pub asset: [u8; 32],
}

impl PublicAmounts {
    pub fn transfer() -> Self {
        Self {
            sol: [0u8; 32],
            spl: [0u8; 32],
            asset: [0u8; 32],
        }
    }
}
/// The P256 ownership signature, computed once over the finalized transaction in
/// [`zolana_transaction::instructions::transact::Transaction::sign`]. The prover only converts it
/// into witness coordinates; it never signs.
#[derive(Clone)]
pub struct P256Owner {
    pub pubkey: P256Pubkey,
    pub sig_r: [u8; 32],
    pub sig_s: [u8; 32],
}

pub struct TransferP256Prover {
    pub inputs: Vec<TransferSpendInput>,
    pub outputs: Vec<SppProofOutputUtxo>,
    pub external_data: ExternalData,
    pub public_amounts: PublicAmounts,
    pub payer_pubkey_hash: [u8; 32],
    pub p256_owner: P256Owner,
    pub shape: Option<Shape>,
}

#[derive(Debug, Clone)]
pub struct TransferP256ProofResult {
    pub inputs: TransferP256Inputs,
    pub public_input_hash: [u8; 32],
    pub nullifiers: Vec<[u8; 32]>,
    pub output_hashes: Vec<[u8; 32]>,
    pub private_tx_hash: [u8; 32],
    pub input_root_indices: Vec<(u16, u16)>,
    /// The shared P256 owner `pk_field` (big-endian) carried in the prover
    /// witness and folded into the confidential public-input hash. Prover-side
    /// value only; never sent as instruction data.
    pub p256_signing_pk_field: [u8; 32],
    /// The raw x-coordinate of the shared P256 signing key (the pre-hash
    /// `confidential_view_tag`), carried in the `Transact` instruction's
    /// `p256_signing_pk_x`; the program hashes it on-chain to `pk_field`.
    pub p256_signing_pk_x: [u8; 32],
}

impl TransferP256Prover {
    pub fn build(self) -> Result<TransferP256ProofResult, ClientError> {
        resolve_shape(self.shape, self.inputs.len(), self.outputs.len())?;
        // The shared P256 signing key's pk_field: the value every P256-owned input
        // exposes as its owner tag and that the circuit asserts equals its in-circuit
        // P256 pk_field. Folded into the confidential public-input hash. The raw
        // x-coordinate is the pre-hash value the instruction carries so the program
        // reproduces `pk_field` on-chain.
        let signing_pubkey = PublicKey::from_p256(&self.p256_owner.pubkey);
        let p256_signing_pk_x = signing_pubkey.confidential_view_tag()?;
        let p256_signing_pk_field = signing_pubkey.owner_pk_field()?;
        let assembled_inputs = assemble_inputs(
            &self.inputs,
            &OwnerMode::ConfidentialP256(p256_signing_pk_field),
        )?;
        let assembled_outputs = assemble_outputs(&self.outputs)?;
        let external_data_hash = self.external_data.hash()?;
        let private_tx = PrivateTxHash::new(
            &assembled_inputs.input_hashes,
            &assembled_outputs.private_tx_output_hashes,
            &external_data_hash,
        )
        .hash()?;
        let p256_message_hash = sha256(&private_tx);
        let signature = self.p256_owner.witness()?;
        let (p256_message_low, p256_message_high) = split_be_128(&p256_message_hash);
        let public_input = PublicInputs {
            nullifiers: &assembled_inputs.nullifiers,
            output_hashes: &assembled_outputs.output_hashes,
            utxo_roots: &assembled_inputs.utxo_roots,
            nullifier_tree_roots: &assembled_inputs.nullifier_tree_roots,
            private_tx: &private_tx,
            p256_message_hash: &p256_message_hash,
            external_data_hash: &external_data_hash,
            public_amounts: &self.public_amounts,
            zone_program_id: &[0u8; 32],
            payer_pubkey_hash: &self.payer_pubkey_hash,
            input_owner_pk_hashes: &assembled_inputs.input_owner_pk_hashes,
            output_owner_pk_hashes: &assembled_outputs.output_owner_pk_hashes,
            p256_signing_pk_field: &p256_signing_pk_field,
        }
        .hash()?;

        let inputs = TransferP256Inputs {
            inputs: assembled_inputs.inputs,
            outputs: assembled_outputs.outputs,
            external_data_hash: be(&external_data_hash),
            p256_pub_x: be(&signature.pub_x),
            p256_pub_y: be(&signature.pub_y),
            p256_sig_r: be(&signature.sig_r),
            p256_sig_s: be(&signature.sig_s),
            private_tx_hash: be(&private_tx),
            p256_message_hash_low: be(&p256_message_low),
            p256_message_hash_high: be(&p256_message_high),
            public_sol_amount: be(&self.public_amounts.sol),
            public_spl_amount: be(&self.public_amounts.spl),
            public_spl_asset_pubkey: be(&self.public_amounts.asset),
            zone_program_id: BigUint::ZERO,
            payer_pubkey_hash: be(&self.payer_pubkey_hash),
            p256_signing_pk_field: be(&p256_signing_pk_field),
            public_input_hash: be(&public_input),
        };

        Ok(TransferP256ProofResult {
            inputs,
            public_input_hash: public_input,
            nullifiers: assembled_inputs.nullifiers,
            output_hashes: assembled_outputs.output_hashes,
            private_tx_hash: private_tx,
            input_root_indices: assembled_inputs.root_indices,
            p256_signing_pk_field,
            p256_signing_pk_x,
        })
    }
}

pub(crate) struct P256SignatureWitness {
    pub pub_x: [u8; 32],
    pub pub_y: [u8; 32],
    pub sig_r: [u8; 32],
    pub sig_s: [u8; 32],
}

impl P256Owner {
    pub(crate) fn witness(&self) -> Result<P256SignatureWitness, ClientError> {
        let (pub_x, pub_y) = self.pubkey.xy()?;
        Ok(P256SignatureWitness {
            pub_x,
            pub_y,
            sig_r: self.sig_r,
            sig_s: self.sig_s,
        })
    }
}

pub(crate) struct AssembledInputs {
    pub inputs: Vec<TransferInput>,
    pub input_hashes: Vec<[u8; 32]>,
    pub nullifiers: Vec<[u8; 32]>,
    pub utxo_roots: Vec<[u8; 32]>,
    pub nullifier_tree_roots: Vec<[u8; 32]>,
    pub input_owner_pk_hashes: Vec<[u8; 32]>,
    /// Per-slot `(utxo_tree_root_index, nullifier_tree_root_index)`, length
    /// `n_inputs`. Real slots take the index from their `SpendProof`; padded
    /// dummy slots mirror the first real input so the on-chain root lookup
    /// reproduces the witness root.
    pub root_indices: Vec<(u16, u16)>,
}

pub(crate) struct AssembledOutputs {
    pub outputs: Vec<TransferOutput>,
    pub output_hashes: Vec<[u8; 32]>,
    pub private_tx_output_hashes: Vec<[u8; 32]>,
    /// Per-output public owner tag: `signing_pubkey.owner_pk_field()`
    /// (`hash_field(view_tag)`) for a real output, `hash_field(view_tag)` of the
    /// builder's random tag for a dummy. Folded into the confidential
    /// public-input hash and matches the program's `hash_field(view_tag)`
    /// reconstruction.
    pub output_owner_pk_hashes: Vec<[u8; 32]>,
}

/// Selects how each input's owner `pk_field` is derived for the witness and the
/// public-input chain. A P256-owned input is treated differently per mode; an
/// ed25519-owned input always uses its own `owner_pk_field()`.
pub(crate) enum OwnerMode {
    /// Confidential P256 rail: a P256 owner exposes the shared signing `pk_field`
    /// (so the circuit routes ownership by equality); ed25519 uses its `pk_field`.
    ConfidentialP256([u8; 32]),
    /// Confidential Solana-only rail: P256-owned inputs are rejected (the rail has
    /// no P256 gadget); ed25519 uses its `pk_field`.
    ConfidentialEddsa,
    /// Merge: the circuit uses a single shared owner, so a P256 input contributes
    /// the `0` sentinel here (the per-input value is ignored); ed25519 uses its
    /// `pk_field`.
    Merge,
    /// Zone authority (anonymous, pubkey-agnostic): every owner uses its own
    /// `owner_pk_field()` as a private witness, regardless of scheme.
    ZoneAuthority,
    /// Zone P256 rail (anonymous): a P256-owned input contributes the `0`
    /// sentinel (its identity stays hidden behind the shared zone proof); an
    /// ed25519 owner uses its own `owner_pk_field()`.
    Zone,
}

/// Convert the already-padded inputs into circuit witness fields. Makes no padding
/// decisions: each slot with a [`SpendProof`] is a real spend; each slot without one
/// is a dummy that mirrors the first real input's roots, indices, and owner hash so
/// the public-input chain and the on-chain root lookup agree. A transaction must
/// spend at least one real input to supply those roots.
pub(crate) fn assemble_inputs(
    spends: &[TransferSpendInput],
    owner_mode: &OwnerMode,
) -> Result<AssembledInputs, ClientError> {
    let mut inputs = Vec::with_capacity(spends.len());
    let mut input_hashes = Vec::with_capacity(spends.len());
    let mut nullifiers = Vec::with_capacity(spends.len());
    let mut utxo_roots = Vec::with_capacity(spends.len());
    let mut nullifier_tree_roots = Vec::with_capacity(spends.len());
    let mut input_owner_pk_hashes = Vec::with_capacity(spends.len());
    let mut root_indices = Vec::with_capacity(spends.len());

    for (index, spend) in spends.iter().enumerate() {
        let Some(proof) = &spend.proof else {
            let utxo_root = *utxo_roots.first().ok_or(ClientError::NoInputs)?;
            let nf_root = *nullifier_tree_roots.first().ok_or(ClientError::NoInputs)?;
            let owner = *input_owner_pk_hashes.first().ok_or(ClientError::NoInputs)?;
            let &(ur_index, nr_index) = root_indices.first().ok_or(ClientError::NoInputs)?;
            let (input, nullifier) =
                TransferInput::new_dummy(&spend.utxo.blinding, &utxo_root, &nf_root, &owner)?;
            inputs.push(input);
            input_hashes.push([0u8; 32]);
            nullifiers.push(nullifier);
            utxo_roots.push(utxo_root);
            nullifier_tree_roots.push(nf_root);
            input_owner_pk_hashes.push(owner);
            root_indices.push((ur_index, nr_index));
            continue;
        };

        let data_hash = spend.data_hash.unwrap_or([0u8; 32]);
        let zone_data_hash = spend.zone_data_hash.unwrap_or([0u8; 32]);

        let nullifier_pubkey = spend.nullifier_key.pubkey()?;
        let utxo_inputs = spend
            .utxo
            .proof_input(&nullifier_pubkey, &data_hash, &zone_data_hash)?;
        let utxo_hash = utxo_inputs.hash()?;
        let nullifier = spend
            .nullifier_key
            .nullifier(&utxo_hash, &spend.utxo.blinding)?;

        let is_p256 = spend.utxo.owner.signature_type()? == SignatureType::P256;
        // Per-input owner pk_field, selected by mode. A P256 owner's value
        // depends on the mode (see OwnerMode); an ed25519 owner always uses
        // its own pk_field.
        let owner_pk_hash = match (owner_mode, is_p256) {
            (OwnerMode::ConfidentialP256(signing_pk_field), true) => *signing_pk_field,
            (OwnerMode::Merge, true) => [0u8; 32],
            (OwnerMode::Zone, true) => [0u8; 32],
            (OwnerMode::ConfidentialEddsa, true) => {
                return Err(ClientError::EddsaInputNotSolanaOwned { index })
            }
            (OwnerMode::ZoneAuthority, true) => spend.utxo.owner.owner_pk_field()?,
            (_, false) => spend.utxo.owner.owner_pk_field()?,
        };

        let nullifier_secret = right_align_slice(spend.nullifier_key.secret())?;

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
            utxo_tree_root: be(&state.root),
            nullifier_tree_root: be(&nf.root),
            nullifier: be(&nullifier),
            owner_pk_hash: be(&owner_pk_hash),
            nullifier_secret: be(&nullifier_secret),
        });
        input_hashes.push(utxo_hash);
        nullifiers.push(nullifier);
        utxo_roots.push(state.root);
        nullifier_tree_roots.push(nf.root);
        input_owner_pk_hashes.push(owner_pk_hash);
        root_indices.push((state.root_index, nf.root_index));
    }

    Ok(AssembledInputs {
        inputs,
        input_hashes,
        nullifiers,
        utxo_roots,
        nullifier_tree_roots,
        input_owner_pk_hashes,
        root_indices,
    })
}

/// Convert the already-padded outputs into circuit witness fields. A dummy output
/// (`owner_hash == 0`: empty change or tail padding) still puts its real hash in the
/// public `output_hashes` but contributes `0` to the private-tx hash chain.
pub(crate) fn assemble_outputs(
    outputs: &[SppProofOutputUtxo],
) -> Result<AssembledOutputs, ClientError> {
    let mut assembled = Vec::with_capacity(outputs.len());
    let mut hashes = Vec::with_capacity(outputs.len());
    let mut private_tx_hashes = Vec::with_capacity(outputs.len());
    let mut output_owner_pk_hashes = Vec::with_capacity(outputs.len());

    for output in outputs {
        let is_dummy = output.is_dummy();
        let hash = output.hash()?;
        // Confidential owner tag: a real output exposes its owner's `pk_field`
        // (`signing_pubkey.owner_pk_field()` == `hash_field(view_tag)`) and witnesses
        // the `nullifier_pk`, so the circuit recomputes `owner_hash` and binds the
        // tag. A dummy slot folds `hash_field` of the builder's random `view_tag` so
        // its public tag matches the program's `hash_field(view_tag)` reconstruction
        // and is indistinguishable from a real one; the circuit leaves it
        // unconstrained and `nullifier_pk` is unused (0).
        let (owner_pk_field, nullifier_pk) = match &output.owner_address {
            Some(address) => (
                address.signing_pubkey.owner_pk_field()?,
                address.nullifier_pubkey,
            ),
            None => (
                hash_field(&output.owner_tag.unwrap_or([0u8; 32]))?,
                [0u8; 32],
            ),
        };
        assembled.push(TransferOutput {
            utxo: ProofInputUtxo::try_from(output)?,
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

pub(crate) struct PublicInputs<'a> {
    pub nullifiers: &'a [[u8; 32]],
    pub output_hashes: &'a [[u8; 32]],
    pub utxo_roots: &'a [[u8; 32]],
    pub nullifier_tree_roots: &'a [[u8; 32]],
    pub private_tx: &'a [u8; 32],
    pub p256_message_hash: &'a [u8; 32],
    pub external_data_hash: &'a [u8; 32],
    pub public_amounts: &'a PublicAmounts,
    /// Per-tx zone program (pk_field-encoded); 0 on default transact.
    pub zone_program_id: &'a [u8; 32],
    pub payer_pubkey_hash: &'a [u8; 32],
    pub input_owner_pk_hashes: &'a [[u8; 32]],
    /// Confidential variant only: appended after the anonymous chain as
    /// `HashChain(output_owner_pk_hashes)` then `p256_signing_pk_field`. Mirrors
    /// `prover/server/prover-test/spp/protocol/public_inputs.go` (PublicInputHash).
    pub output_owner_pk_hashes: &'a [[u8; 32]],
    pub p256_signing_pk_field: &'a [u8; 32],
}

impl PublicInputs<'_> {
    pub(crate) fn hash(&self) -> Result<[u8; 32], ClientError> {
        let elements = [
            create_hash_chain_from_slice(self.nullifiers)?,
            create_hash_chain_from_slice(self.output_hashes)?,
            create_hash_chain_from_slice(self.utxo_roots)?,
            create_hash_chain_from_slice(self.nullifier_tree_roots)?,
            *self.private_tx,
            hash_field(self.p256_message_hash)?,
            *self.external_data_hash,
            self.public_amounts.sol,
            self.public_amounts.spl,
            self.public_amounts.asset,
            *self.zone_program_id,
            *self.payer_pubkey_hash,
            create_hash_chain_from_slice(self.input_owner_pk_hashes)?,
            // Confidential appendix (the client always uses the confidential variant).
            create_hash_chain_from_slice(self.output_owner_pk_hashes)?,
            *self.p256_signing_pk_field,
        ];
        Ok(create_hash_chain_from_slice(&elements)?)
    }
}
fn check_path_length(got: usize, expected: usize) -> Result<(), ClientError> {
    if got == expected {
        Ok(())
    } else {
        Err(ClientError::ProofPathLength { got, expected })
    }
}
