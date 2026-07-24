//! High-level builder for the 8-in/1-out merge proof. It reuses the spp transfer
//! input/output assembly verbatim ([`assemble_inputs`]/[`assemble_outputs`]);
//! only the verifiable encryption and the public-input-hash element set are
//! merge-specific.

use num_bigint::BigUint;
use p256::{elliptic_curve::sec1::ToEncodedPoint, SecretKey};
use zolana_hasher::hash_chain::create_hash_chain_from_slice;
use zolana_interface::instruction::instruction_data::{
    merge_transact::{MergeExternalDataHash, MergeTransactIxData},
    merge_zone::MergeZoneIxData,
    transact::P256Proof,
};
use zolana_keypair::{
    merge::{encrypt_verifiable, merge_public_contribution, MergeCiphertextPublicInputs},
    NullifierKey, P256Pubkey, PublicKey, SignatureType,
};
use zolana_transaction::{
    instructions::{
        merge::PreparedMerge,
        transact::{spp_proof_inputs::asset_field, PrivateTxHash},
    },
    EncryptedScheme, SppProofOutputUtxo,
};

use crate::{
    error::ClientError,
    prover::{
        field::be,
        transact::{
            p256_and_eddsa::{assemble_inputs, assemble_outputs, OwnerMode, TransferSpendInput},
            witness::{attach_input_proofs, SpendProof},
        },
        MergeInputs, TransferInput, TransferOutput,
    },
};

/// Merge consolidates up to 8 inputs sharing one owner, asset, and nullifier
/// secret into one output, verifiably encrypted to the owner's viewing key. The
/// owner is either rail: a P256 signing key recomputes its pk_field from the
/// witnessed point, a Solana (ed25519) signing key feeds its pk_field directly.
/// The input slots reuse [`TransferSpendInput`] (a `None` proof is a dummy);
/// there is exactly one real output.
pub struct MergeProver {
    pub inputs: Vec<TransferSpendInput>,
    pub output: SppProofOutputUtxo,
    /// Validity deadline; bound into `external_data_hash`, which the circuit treats
    /// as opaque and `merge_transact` recomputes from the instruction.
    pub expiry_unix_ts: u64,
    /// Owner identity shared by every input: the scheme-tagged signing pubkey
    /// (recomputes `user_owner_hash`) and the nullifier key (recomputes the shared
    /// `nullifier_pk` and every input nullifier).
    pub signing_pubkey: PublicKey,
    pub nullifier_key: NullifierKey,
    /// Owner viewing key (encryption recipient) and the ephemeral scalar. The
    /// scalar must be < BN254 modulus so it is a valid circuit witness.
    pub user_viewing_pk: P256Pubkey,
    pub tx_viewing_sk: SecretKey,
}

/// The built merge witness and the instruction-data ingredients, produced by
/// both [`MergeProver`] (default) and
/// [`crate::prover::merge_zone::MergeZoneProver`] (policy zone); the two rails
/// differ only in their public-input tail and the zone binding inside `inputs`.
#[derive(Debug, Clone)]
pub struct MergeProofResult {
    pub inputs: MergeInputs,
    pub public_input_hash: [u8; 32],
    pub nullifiers: Vec<[u8; 32]>,
    /// Per-input references into the tree's root caches (length 8; dummy slots
    /// mirror the first real input), for the `merge_transact` instruction data.
    pub utxo_tree_root_indices: Vec<u16>,
    pub nullifier_tree_root_indices: Vec<u16>,
    pub output_hash: [u8; 32],
    pub private_tx_hash: [u8; 32],
    /// Recomputed on-chain from the instruction; surfaced so the caller need not
    /// re-derive it.
    pub external_data_hash: [u8; 32],
    pub expiry_unix_ts: u64,
    /// The published merge ciphertext and the ephemeral `tx_viewing_pk` the owner
    /// uses to decrypt it back to the merged output's `(amount, asset, blinding)`.
    pub ciphertext: Vec<u8>,
    pub tx_viewing_pk: P256Pubkey,
    /// True when the owner is a Solana (ed25519) signer, so `merge_transact` derives
    /// `signing_pk_field` from the registry account owner instead of `owner_p256`.
    pub eddsa_owner: bool,
}

impl MergeProofResult {
    /// Assemble the `merge_transact` instruction data from this proof result and
    /// the P256-rail proof (`ProofCompressed::to_merge_proof`). The caller passes
    /// the result to the `MergeTransact` builder with the tree / protocol_config /
    /// user_record accounts.
    pub fn instruction_data(&self, proof: P256Proof) -> MergeTransactIxData {
        MergeTransactIxData {
            expiry_unix_ts: self.expiry_unix_ts,
            proof,
            output_utxo_hash: self.output_hash,
            nullifiers: self.nullifiers.clone(),
            utxo_tree_root_index: self.utxo_tree_root_indices.clone(),
            nullifier_tree_root_index: self.nullifier_tree_root_indices.clone(),
            private_tx_hash: self.private_tx_hash,
            encrypted_utxo: merge_encrypted_utxo(&self.tx_viewing_pk, &self.ciphertext),
            eddsa_owner: self.eddsa_owner,
        }
    }

    /// Assemble the `merge_zone` instruction data: the same `merge_transact`
    /// body wrapped in a [`MergeZoneIxData`] with the single-use
    /// `merge_view_tag` indexing the merged output. The caller passes the
    /// result to the `MergeZone` builder with the tree / zone_config accounts.
    pub fn zone_instruction_data(
        &self,
        proof: P256Proof,
        merge_view_tag: [u8; 32],
    ) -> MergeZoneIxData {
        MergeZoneIxData {
            merge_view_tag,
            merge: self.instruction_data(proof),
        }
    }
}

impl MergeProver {
    pub fn build(self) -> Result<MergeProofResult, ClientError> {
        let merge = self.common(zolana_interface::instruction::tag::MERGE_TRANSACT)?;

        // Owner identity public inputs (pk_field of the signing and viewing keys).
        // SPP checks both against the owner's registry record; the owner recombines
        // the signing pk_field with their nullifier_pk to get user_owner_hash, so
        // the owner need not be carried in the ciphertext.
        let user_viewing_pk_hash = PublicKey::from_p256(&self.user_viewing_pk).hash()?;
        let mut elements = merge.head.to_vec();
        elements.extend([
            merge.user_signing_pk_hash,
            user_viewing_pk_hash,
            merge.tx_pk_lo,
            merge.tx_pk_hi,
            merge.ct_hash,
        ]);
        let public_input = create_hash_chain_from_slice(&elements)?;

        // Default merge is non-zone; the merge-zone builder sets the zone binding.
        Ok(merge.finish(public_input, BigUint::ZERO))
    }
}

/// Everything the default ([`MergeProver`]) and policy-zone
/// ([`crate::prover::merge_zone::MergeZoneProver`]) merges compute identically:
/// input/output assembly, the verifiable encryption, the shared public-input
/// prefix, and the owner-rail witness select. Each rail appends its own
/// public-input tail to [`Self::head`] and calls [`Self::finish`].
pub(crate) struct CommonMerge {
    inputs: Vec<TransferInput>,
    output: TransferOutput,
    nullifiers: Vec<[u8; 32]>,
    utxo_tree_root_indices: Vec<u16>,
    nullifier_tree_root_indices: Vec<u16>,
    /// The public-input prefix both merge circuits share:
    /// `[nullifiers_chain, output_hash, utxo_roots_chain,
    /// nullifier_tree_roots_chain, private_tx_hash, external_data_hash]`.
    pub head: [[u8; 32]; 6],
    output_hash: [u8; 32],
    private_tx_hash: [u8; 32],
    external_data_hash: [u8; 32],
    expiry_unix_ts: u64,
    ciphertext: Vec<u8>,
    tx_viewing_pk: P256Pubkey,
    pub tx_pk_lo: [u8; 32],
    pub tx_pk_hi: [u8; 32],
    pub ct_hash: [u8; 32],
    pub user_signing_pk_hash: [u8; 32],
    eddsa_owner: bool,
    p256_pub_x: [u8; 32],
    p256_pub_y: [u8; 32],
    owner_pk_hash: BigUint,
    user_nullifier_pk: [u8; 32],
    user_nullifier_secret: [u8; 32],
    tx_viewing_sk_bytes: [u8; 32],
    user_viewing_pubkey: Vec<BigUint>,
}

impl MergeProver {
    /// The computation both merge rails share, parameterized only by the
    /// instruction tag (`merge_transact` or `merge_zone`) bound into
    /// `external_data_hash`. Callers append their rail's public-input tail to
    /// [`CommonMerge::head`] and call [`CommonMerge::finish`].
    pub(crate) fn common(
        &self,
        spp_instruction_discriminator: u8,
    ) -> Result<CommonMerge, ClientError> {
        let assembled_inputs = assemble_inputs(&self.inputs, &OwnerMode::Merge)?;

        let utxo_tree_root_indices: Vec<u16> = assembled_inputs
            .root_indices
            .iter()
            .map(|(u, _)| *u)
            .collect();
        let nullifier_tree_root_indices: Vec<u16> = assembled_inputs
            .root_indices
            .iter()
            .map(|(_, n)| *n)
            .collect();

        let assembled_outputs = assemble_outputs(std::slice::from_ref(&self.output))?;
        let output_hash = *assembled_outputs
            .output_hashes
            .first()
            .ok_or(ClientError::NoInputs)?;

        // Verifiable encryption of the merged output to the owner's viewing key.
        let plaintext = merge_plaintext(&self.output)?;
        let (ciphertext, tx_viewing_pk) =
            encrypt_verifiable(&self.tx_viewing_sk, &self.user_viewing_pk, &plaintext)?;
        let MergeCiphertextPublicInputs {
            tx_viewing_pk_lo: tx_pk_lo,
            tx_viewing_pk_hi: tx_pk_hi,
            ciphertext_hash: ct_hash,
        } = merge_public_contribution(&tx_viewing_pk, &ciphertext)?;

        // external_data_hash binds the published ciphertext blob and expiry to the
        // proof; the program recomputes it identically from the instruction.
        let encrypted_utxo = merge_encrypted_utxo(&tx_viewing_pk, &ciphertext);
        let external_data_hash = MergeExternalDataHash {
            spp_instruction_discriminator,
            expiry_unix_ts: self.expiry_unix_ts,
            output_utxo_hash: &output_hash,
            encrypted_utxo: &encrypted_utxo,
        }
        .hash()?;

        let private_tx = PrivateTxHash::new(
            &assembled_inputs.input_hashes,
            &assembled_outputs.private_tx_output_hashes,
            &external_data_hash,
        )
        .hash()?;

        let user_signing_pk_hash = self.signing_pubkey.owner_pk_field()?;
        let head = [
            create_hash_chain_from_slice(&assembled_inputs.nullifiers)?,
            output_hash,
            create_hash_chain_from_slice(&assembled_inputs.utxo_roots)?,
            create_hash_chain_from_slice(&assembled_inputs.nullifier_tree_roots)?,
            private_tx,
            external_data_hash,
        ];

        // Owner rail select, mirroring the merge circuit: a P256 owner witnesses its
        // real point (pk_field recomputed in-circuit, owner_pk_hash = 0); a
        // Solana owner witnesses a discarded dummy point and feeds its pk_field
        // through owner_pk_hash.
        let eddsa_owner = self.signing_pubkey.signature_type()? == SignatureType::Ed25519;
        let (p256_pub_x, p256_pub_y, owner_pk_hash) = if eddsa_owner {
            let (x, y) = dummy_p256_xy()?;
            (x, y, BigUint::from_bytes_be(&user_signing_pk_hash))
        } else {
            let (x, y) = signing_xy(&self.signing_pubkey.as_p256()?)?;
            (x, y, BigUint::ZERO)
        };
        let user_nullifier_pk = self.nullifier_key.pubkey()?;
        let user_nullifier_secret = right_align(self.nullifier_key.secret());
        let tx_viewing_sk_bytes: [u8; 32] = self.tx_viewing_sk.to_bytes().into();
        let user_viewing_pubkey = uncompressed(&self.user_viewing_pk)?
            .iter()
            .map(|b| BigUint::from(*b))
            .collect();

        let output = assembled_outputs
            .outputs
            .into_iter()
            .next()
            .ok_or(ClientError::NoInputs)?;

        Ok(CommonMerge {
            inputs: assembled_inputs.inputs,
            output,
            nullifiers: assembled_inputs.nullifiers,
            utxo_tree_root_indices,
            nullifier_tree_root_indices,
            head,
            output_hash,
            private_tx_hash: private_tx,
            external_data_hash,
            expiry_unix_ts: self.expiry_unix_ts,
            ciphertext,
            tx_viewing_pk,
            tx_pk_lo,
            tx_pk_hi,
            ct_hash,
            user_signing_pk_hash,
            eddsa_owner,
            p256_pub_x,
            p256_pub_y,
            owner_pk_hash,
            user_nullifier_pk,
            user_nullifier_secret,
            tx_viewing_sk_bytes,
            user_viewing_pubkey,
        })
    }
}

impl CommonMerge {
    /// Fold the rail's completed public-input hash and zone binding (zero for the
    /// default merge) into the final witness and proof result.
    pub(crate) fn finish(
        self,
        public_input: [u8; 32],
        zone_program_id: BigUint,
    ) -> MergeProofResult {
        let inputs = MergeInputs {
            inputs: self.inputs,
            output: self.output,
            p256_pub_x: be(&self.p256_pub_x),
            p256_pub_y: be(&self.p256_pub_y),
            owner_pk_hash: self.owner_pk_hash,
            user_nullifier_pk: be(&self.user_nullifier_pk),
            user_nullifier_secret: be(&self.user_nullifier_secret),
            tx_viewing_sk: BigUint::from_bytes_be(&self.tx_viewing_sk_bytes),
            user_viewing_pubkey: self.user_viewing_pubkey,
            external_data_hash: be(&self.external_data_hash),
            private_tx_hash: be(&self.private_tx_hash),
            public_input_hash: be(&public_input),
            zone_program_id,
        };
        MergeProofResult {
            inputs,
            public_input_hash: public_input,
            nullifiers: self.nullifiers,
            utxo_tree_root_indices: self.utxo_tree_root_indices,
            nullifier_tree_root_indices: self.nullifier_tree_root_indices,
            output_hash: self.output_hash,
            private_tx_hash: self.private_tx_hash,
            external_data_hash: self.external_data_hash,
            expiry_unix_ts: self.expiry_unix_ts,
            ciphertext: self.ciphertext,
            tx_viewing_pk: self.tx_viewing_pk,
            eddsa_owner: self.eddsa_owner,
        }
    }
}

/// Assembles the on-instruction `encrypted_utxo` payload in the unified output
/// encoding `borsh(MessageData::VerifiablyEncrypted([EncryptedScheme::Merge,
/// tx_viewing_pk(33), ciphertext]))`, the same form transact emits and
/// `Wallet::sync` decodes.
pub fn merge_encrypted_utxo(tx_viewing_pk: &P256Pubkey, ciphertext: &[u8]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(1 + 33 + ciphertext.len());
    blob.push(EncryptedScheme::Merge.as_byte());
    blob.extend_from_slice(tx_viewing_pk.as_bytes());
    blob.extend_from_slice(ciphertext);
    zolana_event::encode_verifiably_encrypted(blob)
}

/// The merge bundle plaintext: amount (u64, 8 BE bytes) || asset field (32 BE
/// bytes) || blinding (31 BE bytes), all read from the merged output.
pub(crate) fn merge_plaintext(output: &SppProofOutputUtxo) -> Result<Vec<u8>, ClientError> {
    let mut pt = Vec::with_capacity(8 + 32 + 31);
    pt.extend_from_slice(&output.amount.to_be_bytes());
    pt.extend_from_slice(&asset_field(&output.asset)?);
    pt.extend_from_slice(&output.blinding);
    Ok(pt)
}

pub(crate) fn uncompressed(pk: &P256Pubkey) -> Result<[u8; 65], ClientError> {
    let point = pk.to_p256()?.to_encoded_point(false);
    let bytes = point.as_bytes();
    let mut out = [0u8; 65];
    if bytes.len() != 65 {
        return Err(ClientError::P256Signature(
            "uncompressed P256 point must be 65 bytes".into(),
        ));
    }
    out.copy_from_slice(bytes);
    Ok(out)
}

pub(crate) fn signing_xy(pk: &P256Pubkey) -> Result<([u8; 32], [u8; 32]), ClientError> {
    let bytes = uncompressed(pk)?;
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(&bytes[1..33]);
    y.copy_from_slice(&bytes[33..65]);
    Ok((x, y))
}

/// The P256 generator coordinates, used as the discarded dummy `P256Pub` on the
/// Solana rail: the circuit always asserts the point is on the curve even though
/// the rail select discards its pk_field, so it must be a valid point.
pub(crate) fn dummy_p256_xy() -> Result<([u8; 32], [u8; 32]), ClientError> {
    let mut one = [0u8; 32];
    one[31] = 1;
    let sk = SecretKey::from_slice(&one).map_err(|e| ClientError::P256Signature(e.to_string()))?;
    let point = sk.public_key().to_encoded_point(false);
    let bytes = point.as_bytes();
    if bytes.len() != 65 {
        return Err(ClientError::P256Signature(
            "P256 generator point must be 65 bytes".into(),
        ));
    }
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(&bytes[1..33]);
    y.copy_from_slice(&bytes[33..65]);
    Ok((x, y))
}

pub(crate) fn right_align(bytes: &[u8; 31]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[1..].copy_from_slice(bytes);
    out
}
/// A prepared merge plus the owner nullifier key and the fetched Merkle proofs,
/// ready to fold into a [`MergeProver`]. The nullifier key is the secret the merge
/// circuit proves ownership from; it is not carried on [`PreparedMerge`], so the
/// caller supplies it from the keypair.
pub struct MergeWitness {
    pub prepared: PreparedMerge,
    pub nullifier_key: NullifierKey,
    pub proofs: Vec<SpendProof>,
}

impl TryFrom<MergeWitness> for MergeProver {
    type Error = ClientError;

    fn try_from(witness: MergeWitness) -> Result<Self, Self::Error> {
        let MergeWitness {
            prepared,
            nullifier_key,
            proofs,
        } = witness;
        let PreparedMerge {
            inputs,
            output,
            expiry_unix_ts,
            signing_pubkey,
            user_viewing_pk,
            tx_viewing_sk,
        } = prepared;

        let mut spends = attach_input_proofs(inputs, &proofs, &[])?;
        // Default-merge inputs are plain utxos; no data hashes ride along.
        for spend in &mut spends {
            spend.data_hash = None;
            spend.zone_data_hash = None;
        }

        Ok(MergeProver {
            inputs: spends,
            output,
            expiry_unix_ts,
            signing_pubkey,
            nullifier_key,
            user_viewing_pk,
            tx_viewing_sk,
        })
    }
}
