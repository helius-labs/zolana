//! Policy-zone merge proof builder for a Squads-vault-owned shielded account
//! (gated under the `prover` feature).
//!
//! A merge consolidates 1..=8 of one owner's same-asset, same-zone UTXOs into a
//! single output of the same owner and total value, verifiably encrypted to the
//! owner's shared viewing key. Unlike the transfer / withdrawal rails there is no
//! paired zone proof and no signature: the squads zone's `merge_transact` verifies
//! only its merge-authority access control and forwards the single SPP `merge_zone`
//! proof, which the SPP verifies (it also covers the verifiable encryption).
//!
//! The owner is a Squads vault addressed only by its shielded owner field element
//! (`owner_pk_field`), never a signable key. The builder wraps that field in a
//! precomputed-owner-field [`PublicKey`] ([`PublicKey::from_owner_pk_field`]) so the
//! merge circuit takes its pass-through (`eddsa_owner`) rail: the owner field is fed
//! through `owner_pk_hash` and no P256/ed25519 signature is witnessed.

use p256::SecretKey;
use zolana_client::{
    prover::merge::merge_encrypted_utxo, MergeZoneProofResult, MergeZoneProver, ProverClient,
    TransferSpendInput,
};
use zolana_interface::instruction::instruction_data::merge_transact::MERGE_INPUT_COUNT;
use zolana_keypair::{random_blinding, NullifierKey, P256Pubkey, PublicKey, ShieldedAddress};
use zolana_transaction::{Address, Data, OutputUtxo, Utxo};

use zolana_squads_interface::{
    instruction::instruction_data::InputContext, types::ProofBytes, SQUADS_ZONE_PROGRAM_ID,
};

use crate::prover::{error::SquadsProverError, withdrawal::pack_proof};

/// One spendable zone UTXO the owner consolidates, plus its Photon inclusion /
/// non-inclusion proofs. Reuses the transfer input shape so the crank assembles
/// merge and transfer inputs identically.
pub use crate::prover::transfer::SquadsTransferInput as SquadsMergeInput;

/// Everything the merge-proof builder needs to consolidate 1..=8 of a
/// Squads-vault-owned account's same-asset UTXOs into one output.
pub struct SquadsMergeRequest {
    /// The owner's shielded owner field element (the viewing-key account `owner`, a
    /// precomputed-owner-field value). The merged output binds to this field via
    /// [`PublicKey::from_owner_pk_field`] and every input's owner hash reuses it.
    pub owner_field: [u8; 32],
    /// Nullifier secret (31 bytes); `NullifierKey::from_secret(..)` recomputes the
    /// account's `nullifier_pubkey` and every input nullifier.
    pub nullifier_secret: [u8; 31],
    /// The account's shared viewing secret (auditor-recovered); its public key is the
    /// verifiable-encryption recipient and equals the account `shared_viewing_key`.
    pub viewing_secret: SecretKey,
    /// The account's `nullifier_pubkey`, stamped on the merged output's owner
    /// address so the owner hash matches the inputs'.
    pub nullifier_pubkey: [u8; 32],
    /// The 1..=8 spendable inputs to consolidate; all must share `asset`. Real input
    /// 0 seeds the ephemeral-viewing-key KDF, so it must be present.
    pub inputs: Vec<SquadsMergeInput>,
    /// The asset mint shared by every input and the merged output.
    pub asset: Address,
    /// Validity deadline; bound into the merge `external_data_hash` and forwarded
    /// verbatim into the SPP `merge_zone` instruction.
    pub expiry_unix_ts: u64,
    /// Opaque tag SPP indexes the merged output under. SPP treats it as bytes (never
    /// a tree leaf), so the crank passes the owner's static account view tag.
    pub merge_view_tag: [u8; 32],
    /// The prover server URL.
    pub prover_url: String,
}

/// The merge proof and every field the crank needs to assemble the squads
/// `MergeTransactIxData`.
pub struct SquadsMergeProof {
    /// The 192-byte BSB22-committed SPP `merge_zone` proof, forwarded to SPP.
    pub spp_proof: ProofBytes,
    /// Forwarded verbatim into the SPP `merge_zone` instruction.
    pub expiry_unix_ts: u64,
    /// The opaque tag SPP indexes the merged output under (echoed from the request).
    pub merge_view_tag: [u8; 32],
    /// Public input shared with the SPP proof.
    pub private_tx_hash: [u8; 32],
    /// Hash of the consolidated output UTXO.
    pub output_utxo_hash: [u8; 32],
    /// Exactly [`MERGE_INPUT_COUNT`] entries (real inputs first, then dummy slots
    /// mirroring the first real input's roots); SPP's `merge_zone` requires all 8.
    pub input_contexts: Vec<InputContext>,
    /// The consolidated output encrypted to the owner's shared viewing key, in SPP's
    /// serialized `OutputData::VerifiablyEncrypted` form; checked by the merge proof.
    pub encrypted_utxo: Vec<u8>,
    /// The merged output amount (`sum(input amounts)`).
    pub output_amount: u64,
    /// The spent inputs' nullifiers, in slot order (length [`MERGE_INPUT_COUNT`]).
    pub nullifiers: Vec<[u8; 32]>,
    /// The single public input hash the SPP merge proof commits to; SPP recomputes
    /// it from the forwarded instruction and verifies the proof against it.
    pub public_input_hash: [u8; 32],
}

/// Build the SPP `merge_zone` proof consolidating a Squads-vault-owned account's
/// same-asset UTXOs into one owner-field-owned output.
pub fn prove_squads_merge(req: SquadsMergeRequest) -> Result<SquadsMergeProof, SquadsProverError> {
    let SquadsMergeRequest {
        owner_field,
        nullifier_secret,
        viewing_secret,
        nullifier_pubkey,
        inputs,
        asset,
        expiry_unix_ts,
        merge_view_tag,
        prover_url,
    } = req;

    let real_count = inputs.len();
    if real_count == 0 || real_count > MERGE_INPUT_COUNT {
        return Err(SquadsProverError::UnsupportedShape(real_count, 1));
    }
    if inputs.iter().any(|input| input.asset != asset) {
        return Err(SquadsProverError::InputAssetMismatch);
    }

    let squads = Address::new_from_array(SQUADS_ZONE_PROGRAM_ID);
    let owner_public = PublicKey::from_owner_pk_field(owner_field);
    let nullifier_key = NullifierKey::from_secret(nullifier_secret);
    let viewing_pubkey = P256Pubkey::from_p256(&viewing_secret.public_key());

    let output_amount = inputs
        .iter()
        .try_fold(0u64, |acc, input| acc.checked_add(input.amount))
        .ok_or(SquadsProverError::InvalidAmount)?;

    // Real spend inputs first (real input 0 seeds the KDF), then dummy padding to
    // the fixed 8-input merge shape; a dummy carries no proof of its own.
    let mut spend_inputs: Vec<TransferSpendInput> = Vec::with_capacity(MERGE_INPUT_COUNT);
    for input in &inputs {
        spend_inputs.push(TransferSpendInput {
            utxo: Utxo {
                owner: owner_public,
                asset,
                amount: input.amount,
                blinding: input.blinding,
                zone_program_id: Some(squads),
                data: Data::default(),
            },
            nullifier_key: nullifier_key.clone(),
            data_hash: None,
            zone_data_hash: None,
            proof: Some(input.spend_proof.clone()),
        });
    }
    while spend_inputs.len() < MERGE_INPUT_COUNT {
        spend_inputs.push(TransferSpendInput {
            utxo: Utxo {
                owner: owner_public,
                asset,
                amount: 0,
                blinding: random_blinding(),
                zone_program_id: None,
                data: Data::default(),
            },
            nullifier_key: nullifier_key.clone(),
            data_hash: None,
            zone_data_hash: None,
            proof: None,
        });
    }

    // The consolidated output, owned by the same identity (known only by its owner
    // field). Its random blinding is recovered by the owner from the merge
    // ciphertext; `MergeZoneProver::build` stamps the shared zone on it.
    let output = OutputUtxo {
        owner_address: Some(ShieldedAddress {
            signing_pubkey: owner_public,
            nullifier_pubkey,
            viewing_pubkey,
        }),
        asset,
        amount: output_amount,
        blinding: random_blinding(),
        zone_program_id: None,
        zone_data_hash: None,
        data_hash: None,
        owner_tag: None,
        data: Data::default(),
    };

    // Ephemeral viewing scalar: 31 random bytes are < the BN254 modulus, so the
    // value is both a valid P-256 scalar and a valid circuit witness.
    let mut sk_bytes = [0u8; 32];
    sk_bytes
        .get_mut(1..)
        .ok_or(SquadsProverError::InvalidScalar)?
        .copy_from_slice(&random_blinding());
    let tx_viewing_sk =
        SecretKey::from_slice(&sk_bytes).map_err(|_| SquadsProverError::InvalidScalar)?;

    let result = MergeZoneProver {
        inputs: spend_inputs,
        output,
        expiry_unix_ts,
        signing_pubkey: owner_public,
        nullifier_key: nullifier_key.clone(),
        user_viewing_pk: viewing_pubkey,
        tx_viewing_sk,
        zone_program_id: squads,
    }
    .build()
    .map_err(merge_err)?;

    let proof = ProverClient::new(prover_url)
        .prove_merge_zone(&result.inputs)
        .map_err(merge_err)?;
    let spp_proof: ProofBytes = pack_proof(&proof)?;

    let input_contexts = build_input_contexts(&result)?;
    let encrypted_utxo = merge_encrypted_utxo(&result.tx_viewing_pk, &result.ciphertext);

    Ok(SquadsMergeProof {
        spp_proof,
        expiry_unix_ts,
        merge_view_tag,
        private_tx_hash: result.private_tx_hash,
        output_utxo_hash: result.output_hash,
        input_contexts,
        encrypted_utxo,
        output_amount,
        nullifiers: result.nullifiers,
        public_input_hash: result.public_input_hash,
    })
}

/// Assemble the [`MERGE_INPUT_COUNT`] input contexts SPP's `merge_zone` requires,
/// 1:1 with the proof result's per-slot nullifiers and root indices (real slots
/// followed by dummy slots that mirror the first real input's roots). All inputs
/// live in one tree, so `tree_index` is always 0.
fn build_input_contexts(
    result: &MergeZoneProofResult,
) -> Result<Vec<InputContext>, SquadsProverError> {
    if result.nullifiers.len() != MERGE_INPUT_COUNT
        || result.utxo_tree_root_indices.len() != MERGE_INPUT_COUNT
        || result.nullifier_tree_root_indices.len() != MERGE_INPUT_COUNT
    {
        return Err(SquadsProverError::InvalidProofEncoding);
    }
    let contexts = result
        .nullifiers
        .iter()
        .zip(result.utxo_tree_root_indices.iter())
        .zip(result.nullifier_tree_root_indices.iter())
        .map(
            |((nullifier, utxo_root_index), nullifier_root_index)| InputContext {
                nullifier: *nullifier,
                tree_index: 0,
                utxo_root_index: *utxo_root_index,
                nullifier_root_index: *nullifier_root_index,
            },
        )
        .collect();
    Ok(contexts)
}

fn merge_err(e: zolana_client::ClientError) -> SquadsProverError {
    SquadsProverError::ProofParse(format!("merge_zone prover: {e}"))
}

#[cfg(test)]
mod tests {
    use groth16_solana_interface::{
        decompression::{decompress_g1, decompress_g2},
        groth16::Groth16Verifier,
    };
    use num_bigint::BigUint;
    use p256::{elliptic_curve::rand_core::OsRng, SecretKey};
    use zolana_client::{
        prover::{spawn_prover, SERVER_ADDRESS},
        MerkleContext, MerkleProof, NonInclusionProof, SpendProof, NULLIFIER_TREE_HEIGHT,
        STATE_TREE_HEIGHT,
    };
    use zolana_hasher::Poseidon;
    use zolana_interface::verifying_keys::merge_zone_8_1;
    use zolana_keypair::{hash::owner_hash, hash::poseidon, NullifierKey, PublicKey};
    use zolana_merkle_tree::{indexed::IndexedMerkleTree, MerkleTree};
    use zolana_transaction::{
        instructions::transact::signed_transaction::BN254_MODULUS_DEC, Address, Data, Utxo,
        SOL_MINT,
    };

    use super::*;

    fn prover_url() -> String {
        std::env::var("ZOLANA_PROVER_URL").unwrap_or_else(|_| SERVER_ADDRESS.to_string())
    }

    fn start_prover() {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            std::env::set_var(
                "ZOLANA_PROVER_KEYS_DIR",
                concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../../prover/server/proving-keys"
                ),
            );
        });
        spawn_prover().expect("prover server must be available");
    }

    fn random_field() -> [u8; 32] {
        use p256::elliptic_curve::rand_core::RngCore;
        let mut b = [0u8; 32];
        OsRng.fill_bytes(&mut b);
        b[0] = 0;
        b
    }

    fn random_blinding_31() -> [u8; 31] {
        let f = random_field();
        let mut b = [0u8; 31];
        b.copy_from_slice(&f[1..]);
        b
    }

    /// A minimal in-memory indexer that appends UTXO hashes to a Poseidon state tree
    /// and answers inclusion / nullifier-non-inclusion proofs, mirroring the client's
    /// `TestIndexer` so real `SpendProof`s can be built with no live chain.
    struct MiniIndexer {
        state_tree: MerkleTree<Poseidon>,
        nullifier_tree: IndexedMerkleTree<Poseidon, usize>,
    }

    impl MiniIndexer {
        fn new() -> Self {
            let upper =
                BigUint::parse_bytes(BN254_MODULUS_DEC.as_bytes(), 10).expect("modulus") - 1u32;
            Self {
                state_tree: MerkleTree::<Poseidon>::new(STATE_TREE_HEIGHT, 0),
                nullifier_tree: IndexedMerkleTree::<Poseidon, usize>::new_with_next_value(
                    NULLIFIER_TREE_HEIGHT,
                    0,
                    upper,
                )
                .expect("indexed nullifier tree"),
            }
        }

        fn add_utxo(&mut self, utxo_hash: [u8; 32]) -> usize {
            let index = self.state_tree.leaves().len();
            self.state_tree.append(&utxo_hash).expect("append leaf");
            index
        }

        fn spend_proof(
            &self,
            utxo_hash: [u8; 32],
            leaf_index: usize,
            nullifier: [u8; 32],
        ) -> SpendProof {
            let ctx = MerkleContext {
                tree_type: 0,
                tree: Address::default(),
            };
            let path = self
                .state_tree
                .get_proof_of_leaf(leaf_index, true)
                .expect("state proof")
                .to_vec();
            let state = MerkleProof {
                leaf: utxo_hash,
                merkle_context: ctx.clone(),
                path,
                leaf_index: leaf_index as u64,
                root: self.state_tree.root(),
                root_seq: 0,
                root_index: 0,
            };
            let ni = self
                .nullifier_tree
                .get_non_inclusion_proof(&BigUint::from_bytes_be(&nullifier))
                .expect("non-inclusion proof");
            let nullifier = NonInclusionProof {
                leaf: nullifier,
                merkle_context: ctx,
                path: ni.merkle_proof.to_vec(),
                low_element: ni.leaf_lower_range_value,
                low_element_index: ni.leaf_index as u64,
                high_element: ni.leaf_higher_range_value,
                high_element_index: 0,
                root: ni.root,
                root_seq: 0,
                root_index: 0,
            };
            SpendProof { state, nullifier }
        }
    }

    fn verify_committed(spp_proof: &[u8; 192], public_input: &[u8; 32]) -> bool {
        let a = decompress_g1(&to32(&spp_proof[0..32])).expect("a");
        let b = decompress_g2(&to64(&spp_proof[32..96])).expect("b");
        let c = decompress_g1(&to32(&spp_proof[96..128])).expect("c");
        let commitment = decompress_g1(&to32(&spp_proof[128..160])).expect("commitment");
        let commitment_pok = decompress_g1(&to32(&spp_proof[160..192])).expect("pok");
        let public_inputs = [*public_input];
        let mut verifier = Groth16Verifier::new_with_commitment(
            &a,
            &b,
            &c,
            &commitment,
            &commitment_pok,
            &public_inputs,
            &merge_zone_8_1::VERIFYINGKEY,
        )
        .expect("verifier");
        verifier.verify().is_ok()
    }

    fn to32(s: &[u8]) -> [u8; 32] {
        let mut o = [0u8; 32];
        o.copy_from_slice(s);
        o
    }

    fn to64(s: &[u8]) -> [u8; 64] {
        let mut o = [0u8; 64];
        o.copy_from_slice(s);
        o
    }

    #[test]
    fn squads_merge_2_inputs_verifies_end_to_end() {
        start_prover();

        let owner_field = random_field();
        let nullifier_secret = random_blinding_31();
        let viewing_secret = SecretKey::random(&mut OsRng);
        let nullifier_key = NullifierKey::from_secret(nullifier_secret);
        let nullifier_pubkey = nullifier_key.pubkey().expect("nullifier pubkey");
        let owner_public = PublicKey::from_owner_pk_field(owner_field);
        let squads = Address::new_from_array(SQUADS_ZONE_PROGRAM_ID);

        // Two zone-owned SOL inputs, indexed so their spend proofs can be served.
        let amounts = [400u64, 600u64];
        let mut indexer = MiniIndexer::new();
        let mut inputs = Vec::new();
        for amount in amounts {
            let blinding = random_blinding_31();
            let utxo = Utxo {
                owner: owner_public,
                asset: SOL_MINT,
                amount,
                blinding,
                zone_program_id: Some(squads),
                data: Data::default(),
            };
            let utxo_hash = utxo
                .hash(&nullifier_pubkey, &[0u8; 32], &[0u8; 32])
                .expect("utxo hash");
            let nullifier = nullifier_key
                .nullifier(&utxo_hash, &blinding)
                .expect("nullifier");
            let leaf_index = indexer.add_utxo(utxo_hash);
            inputs.push((utxo_hash, leaf_index, nullifier, amount, blinding));
        }

        let merge_inputs: Vec<SquadsMergeInput> = inputs
            .iter()
            .map(
                |(utxo_hash, leaf_index, nullifier, amount, blinding)| SquadsMergeInput {
                    asset: SOL_MINT,
                    amount: *amount,
                    blinding: *blinding,
                    spend_proof: indexer.spend_proof(*utxo_hash, *leaf_index, *nullifier),
                },
            )
            .collect();

        let proof = prove_squads_merge(SquadsMergeRequest {
            owner_field,
            nullifier_secret,
            viewing_secret: viewing_secret.clone(),
            nullifier_pubkey,
            inputs: merge_inputs,
            asset: SOL_MINT,
            expiry_unix_ts: u64::MAX,
            merge_view_tag: [0xFF; 32],
            prover_url: prover_url(),
        })
        .expect("merge proof");

        assert_eq!(proof.output_amount, amounts.iter().sum::<u64>());
        assert_eq!(proof.input_contexts.len(), MERGE_INPUT_COUNT);
        assert_eq!(proof.nullifiers.len(), MERGE_INPUT_COUNT);
        assert_eq!(proof.encrypted_utxo.first().copied(), Some(2u8));

        // The output owner hash is Poseidon(owner_field, nullifier_pubkey): the
        // owner-field key hashes to exactly the field it wraps.
        let expected_owner_hash =
            poseidon(&[&owner_field, &nullifier_pubkey]).expect("poseidon owner hash");
        assert_eq!(
            owner_hash(&owner_public, &nullifier_pubkey).expect("owner hash"),
            expected_owner_hash,
        );

        // The proof carries a BSB22 commitment and verifies against the merge_zone_8_1
        // verifying key on the single public input the circuit binds.
        assert!(
            verify_committed(&proof.spp_proof, &proof.public_input_hash),
            "merge_zone_8_1 host verification failed",
        );
        let mut tampered = proof.public_input_hash;
        tampered[1] ^= 1;
        assert!(
            !verify_committed(&proof.spp_proof, &tampered),
            "verification must fail for a tampered public input",
        );

        // The owner recovers the merged amount / asset / blinding from the published
        // ciphertext, proving the verifiable encryption yields a spendable output.
        let (tx_pk_bytes, ciphertext) = split_encrypted_utxo(&proof.encrypted_utxo);
        let tx_viewing_pk = P256Pubkey::from_bytes(tx_pk_bytes).expect("tx viewing pk");
        let recovered =
            zolana_keypair::merge::decrypt_verifiable(&viewing_secret, &tx_viewing_pk, &ciphertext)
                .expect("decrypt merged output");
        assert_eq!(recovered.len(), 8 + 32 + 31);
        let recovered_amount = u64::from_be_bytes(recovered.get(0..8).unwrap().try_into().unwrap());
        assert_eq!(recovered_amount, proof.output_amount);
    }

    fn split_encrypted_utxo(blob: &[u8]) -> ([u8; 33], Vec<u8>) {
        // borsh OutputData::VerifiablyEncrypted: 1-byte enum tag (2) + 4-byte LE len +
        // inner blob [scheme(1) | tx_viewing_pk(33) | ciphertext(71)].
        let inner = blob.get(5..).expect("encrypted_utxo body");
        let pk: [u8; 33] = inner
            .get(1..34)
            .expect("tx viewing pk")
            .try_into()
            .expect("33 bytes");
        let ciphertext = inner.get(34..).expect("ciphertext").to_vec();
        (pk, ciphertext)
    }
}
