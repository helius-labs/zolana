//! Submit a prepared merge: validate the owner's registry opt-in, fetch input
//! Merkle proofs, prove on the 8-in/1-out merge circuit, and send `merge_transact`.
//!
//! Merge proves ownership in-circuit and encrypts its single output to the owner's
//! viewing key, so there is no authority signing step here — only the fee payer
//! signs the on-chain transaction.

use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_interface::instruction::MergeTransact;
use zolana_keypair::{NullifierKey, P256Pubkey, PublicKey, ShieldedKeypair, SignatureType};
use zolana_transaction::{instructions::merge::PreparedMerge, Address};
use zolana_user_registry_interface::{user_record_pda, UserRecord};

use zolana_client::{
    error::ClientError,
    prover::{
        merge::{MergeProver, MergeWitness},
        ProofCompressed, ProverClient,
    },
    rpc::Rpc,
    SpendProof,
};

use crate::user_registry::fetch_user_record_checked;

/// Compute-unit ceiling for a `merge_transact`: it verifies an 8-in/1-out Groth16
/// proof on-chain, which does not fit the default per-instruction budget.
const MERGE_CU_LIMIT: u32 = 1_400_000;

/// The minimal owner material the merge submit boundary needs: the public
/// identity to check against the registry record, plus the nullifier secret that
/// proves ownership in-circuit and receives the merged output under the owner's
/// viewing key. It deliberately omits the signing secret, the viewing secret,
/// and (on the ed25519 rail) the funding secret that a full [`ShieldedKeypair`]
/// holds, so no spending authority crosses the submit API.
pub struct MergeMaterial {
    pub signing_pubkey: PublicKey,
    pub viewing_pubkey: P256Pubkey,
    pub nullifier_key: NullifierKey,
}

impl MergeMaterial {
    /// Extract only the public identity and nullifier secret a merge submit needs
    /// from a wallet keypair, leaving every signing/viewing/funding secret behind.
    pub fn from_keypair(keypair: &ShieldedKeypair) -> Self {
        Self {
            signing_pubkey: keypair.signing_pubkey(),
            viewing_pubkey: keypair.viewing_pubkey(),
            nullifier_key: keypair.nullifier_key.clone(),
        }
    }
}

/// Everything needed to prove and submit a prepared merge. `rpc` sends the
/// transaction and reads the owner's registry record; `indexer` resolves the
/// input Merkle proofs (both may point at the same [`zolana_client::ZolanaClient`]). The
/// fee `payer` signs; `material` carries the owner's public identity plus the
/// nullifier secret that proves the merge and whose viewing key receives the
/// encrypted output.
pub struct SubmitMergeTransaction<'a, R: Rpc, I: Rpc + ?Sized> {
    pub rpc: &'a R,
    pub indexer: &'a I,
    pub owner: Pubkey,
    pub payer: &'a Keypair,
    pub material: &'a MergeMaterial,
    pub tree: Pubkey,
    pub prover_url: &'a str,
    pub prepared: PreparedMerge,
}

/// The result of a submitted merge: the transaction signature and the commitment
/// hash of the consolidated output (to wait for it to be indexed).
pub struct SubmittedMerge {
    pub signature: Signature,
    pub output_hash: [u8; 32],
}

/// Prove and submit a prepared merge. Returns once the transaction is sent; the
/// caller waits for the output leaf to be indexed (`merge_transact` output is not
/// on the confirm-by-tags path a transfer uses).
pub fn submit_merge_transaction<R: Rpc, I: Rpc + ?Sized>(
    request: SubmitMergeTransaction<'_, R, I>,
) -> Result<SubmittedMerge, ClientError> {
    let SubmitMergeTransaction {
        rpc,
        indexer,
        owner,
        payer,
        material,
        tree,
        prover_url,
        prepared,
    } = request;

    let record = fetch_user_record_checked(rpc, owner)?;
    validate_merge_submission(&record, owner, material)?;

    // Real-input commitments -> per-input spend proofs (state inclusion + nullifier
    // non-inclusion), fetched before `prepared` is folded into the witness. The
    // indexer resolves the tree from the commitments; the proofs name it in their
    // merkle context, checked against the ix tree before paying for a proof that
    // could never verify on-chain.
    let commitments = prepared.input_utxo_hashes()?;
    let proofs = indexer.get_input_merkle_proofs(&commitments, None)?;
    ensure_proofs_match_submit_tree(&proofs, Address::new_from_array(tree.to_bytes()))?;

    let result = MergeProver::try_from(MergeWitness {
        prepared,
        nullifier_key: material.nullifier_key.clone(),
        proofs,
    })?
    .build()?;

    let proof = ProverClient::new(prover_url.to_string()).prove_merge(&result.inputs)?;
    let packed = ProofCompressed::try_from(proof)?.to_merge_proof()?;
    let data = result.instruction_data(packed);

    let merge_ix = MergeTransact {
        tree,
        payer: payer.pubkey(),
        user_record: user_record_pda(&owner).0,
        data,
    }
    .instruction();
    let instructions = [
        ComputeBudgetInstruction::set_compute_unit_limit(MERGE_CU_LIMIT),
        merge_ix,
    ];
    let signature = rpc.create_and_send_transaction(
        &instructions,
        Address::new_from_array(payer.pubkey().to_bytes()),
        &[payer],
    )?;

    Ok(SubmittedMerge {
        signature,
        output_hash: result.output_hash,
    })
}

/// Reject spend proofs resolved against a different tree than the submit ix
/// targets: a merge proof only verifies against the tree its input proofs were
/// fetched from, so a mismatch would fail on-chain after proving.
fn ensure_proofs_match_submit_tree(
    proofs: &[SpendProof],
    submit_tree: Address,
) -> Result<(), ClientError> {
    for proof in proofs {
        for proof_tree in [
            proof.state.merkle_context.tree,
            proof.nullifier.merkle_context.tree,
        ] {
            if proof_tree != submit_tree {
                return Err(ClientError::MergeTreeMismatch {
                    proof_tree: proof_tree.to_bytes(),
                    submit_tree: submit_tree.to_bytes(),
                });
            }
        }
    }
    Ok(())
}

/// Check the owner opted into merging and that the submitted material is the
/// identity the registry record commits, per rail. The on-chain program verifies
/// the same keys against the record, so a mismatch would only fail after proving;
/// catching it here avoids a wasted proof.
fn validate_merge_submission(
    record: &UserRecord,
    owner: Pubkey,
    material: &MergeMaterial,
) -> Result<(), ClientError> {
    if !record.merging_enabled {
        return Err(ClientError::MergeDisabled { owner });
    }
    let signing = material.signing_pubkey;
    match signing.signature_type()? {
        SignatureType::P256 => {
            if record.owner_p256 != Some(*signing.as_p256()?.as_bytes()) {
                return Err(ClientError::MergeSigningKeyMismatch);
            }
        }
        SignatureType::Ed25519 => {
            // The ed25519 rail derives the signing identity from the record's
            // Solana `owner`, which carries no P256 key.
            if record.owner_p256.is_some() || signing.as_ed25519()? != owner.to_bytes() {
                return Err(ClientError::MergeSigningKeyMismatch);
            }
        }
    }
    if record.nullifier_pubkey != material.nullifier_key.pubkey()? {
        return Err(ClientError::MergeNullifierKeyMismatch);
    }
    if record.viewing_pubkey != *material.viewing_pubkey.as_bytes() {
        return Err(ClientError::MergeViewingKeyMismatch { owner });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use zolana_client::{MerkleContext, MerkleProof, NonInclusionProof};
    use zolana_keypair::ViewingKey;

    use super::*;

    fn ed25519_owner() -> (Pubkey, ShieldedKeypair) {
        let mut seed = [0u8; 32];
        seed[1..].copy_from_slice(&zolana_keypair::random_blinding());
        let keypair =
            ShieldedKeypair::from_ed25519(&seed, ViewingKey::new()).expect("ed25519 keypair");
        let owner = Pubkey::new_from_array(
            keypair
                .signing_pubkey()
                .as_ed25519()
                .expect("ed25519 signing pubkey"),
        );
        (owner, keypair)
    }

    fn record_for(owner: Pubkey, keypair: &ShieldedKeypair, merging_enabled: bool) -> UserRecord {
        UserRecord {
            owner: owner.to_bytes().into(),
            bump: 255,
            owner_p256: None,
            nullifier_pubkey: keypair.nullifier_key.pubkey().unwrap(),
            viewing_pubkey: *keypair.viewing_pubkey().as_bytes(),
            sync_delegate: None,
            entries: Vec::new(),
            merging_enabled,
        }
    }

    #[test]
    fn validate_accepts_a_matching_enabled_ed25519_record() {
        let (owner, keypair) = ed25519_owner();
        let record = record_for(owner, &keypair, true);

        validate_merge_submission(&record, owner, &MergeMaterial::from_keypair(&keypair))
            .expect("matching record");
    }

    #[test]
    fn validate_rejects_a_disabled_record() {
        let (owner, keypair) = ed25519_owner();
        let record = record_for(owner, &keypair, false);

        let error =
            validate_merge_submission(&record, owner, &MergeMaterial::from_keypair(&keypair))
                .expect_err("disabled merge service");

        assert!(matches!(error, ClientError::MergeDisabled { owner: got } if got == owner));
    }

    #[test]
    fn validate_rejects_a_viewing_key_mismatch() {
        let (owner, keypair) = ed25519_owner();
        let mut record = record_for(owner, &keypair, true);
        record.viewing_pubkey = [0xffu8; 33];

        let error =
            validate_merge_submission(&record, owner, &MergeMaterial::from_keypair(&keypair))
                .expect_err("viewing key mismatch");

        assert!(
            matches!(error, ClientError::MergeViewingKeyMismatch { owner: got } if got == owner)
        );
    }

    #[test]
    fn validate_rejects_a_nullifier_key_mismatch() {
        let (owner, keypair) = ed25519_owner();
        let mut record = record_for(owner, &keypair, true);
        record.nullifier_pubkey = [0xffu8; 32];

        let error =
            validate_merge_submission(&record, owner, &MergeMaterial::from_keypair(&keypair))
                .expect_err("nullifier key mismatch");

        assert!(matches!(error, ClientError::MergeNullifierKeyMismatch));
    }

    #[test]
    fn validate_rejects_a_signing_rail_mismatch() {
        // A P256 record cannot back an ed25519 merging keypair.
        let (owner, keypair) = ed25519_owner();
        let mut record = record_for(owner, &keypair, true);
        record.owner_p256 = Some([2u8; 33]);

        let error =
            validate_merge_submission(&record, owner, &MergeMaterial::from_keypair(&keypair))
                .expect_err("signing rail mismatch");

        assert!(matches!(error, ClientError::MergeSigningKeyMismatch));
    }

    fn spend_proof_on(state_tree: Address, nullifier_tree: Address) -> SpendProof {
        SpendProof {
            state: MerkleProof {
                leaf: [1u8; 32],
                merkle_context: MerkleContext {
                    tree_type: 0,
                    tree: state_tree,
                },
                path: Vec::new(),
                leaf_index: 0,
                root: [2u8; 32],
                root_seq: 0,
                root_index: 0,
            },
            nullifier: NonInclusionProof {
                leaf: [3u8; 32],
                merkle_context: MerkleContext {
                    tree_type: 0,
                    tree: nullifier_tree,
                },
                path: Vec::new(),
                low_element: [0u8; 32],
                low_element_index: 0,
                high_element: [4u8; 32],
                high_element_index: 0,
                root: [5u8; 32],
                root_seq: 0,
                root_index: 0,
            },
        }
    }

    #[test]
    fn proofs_on_the_submit_tree_pass_the_tree_check() {
        let tree = Address::new_from_array([7u8; 32]);

        ensure_proofs_match_submit_tree(&[spend_proof_on(tree, tree)], tree)
            .expect("proofs on the submit tree");
    }

    #[test]
    fn a_state_proof_from_another_tree_fails_the_tree_check() {
        let submit_tree = Address::new_from_array([7u8; 32]);
        let other_tree = Address::new_from_array([8u8; 32]);

        let error = ensure_proofs_match_submit_tree(
            &[spend_proof_on(other_tree, submit_tree)],
            submit_tree,
        )
        .expect_err("state proof tree mismatch");

        assert!(matches!(
            error,
            ClientError::MergeTreeMismatch {
                proof_tree,
                submit_tree: got,
            } if proof_tree == other_tree.to_bytes() && got == submit_tree.to_bytes()
        ));
    }

    #[test]
    fn a_nullifier_proof_from_another_tree_fails_the_tree_check() {
        let submit_tree = Address::new_from_array([7u8; 32]);
        let other_tree = Address::new_from_array([8u8; 32]);

        let error = ensure_proofs_match_submit_tree(
            &[spend_proof_on(submit_tree, other_tree)],
            submit_tree,
        )
        .expect_err("nullifier proof tree mismatch");

        assert!(matches!(
            error,
            ClientError::MergeTreeMismatch {
                proof_tree,
                submit_tree: got,
            } if proof_tree == other_tree.to_bytes() && got == submit_tree.to_bytes()
        ));
    }
}
