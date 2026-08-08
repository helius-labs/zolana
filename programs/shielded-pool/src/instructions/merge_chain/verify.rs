use pinocchio::{error::ProgramError, ProgramResult};
use zolana_hasher::hash_chain::create_hash_chain_from_slice;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::instruction_data::merge_chain_transact::MergeChainTransactIxDataRef,
    verifying_keys::merge_chain::merge_chain_verifying_key,
};

use crate::instructions::verifier;

/// Derived public inputs the program resolves from the tree and the registry,
/// folded into the chain public-input hash alongside the instruction fields.
///
/// The roots are per tree-backed slot, in the same leg then slot order as
/// `nullifiers`. A chained slot has no entry. It spends a UTXO no tree holds
/// and the recursion attests it existed.
pub struct MergeChainProofInputs {
    pub utxo_roots: Vec<[u8; 32]>,
    pub nullifier_tree_roots: Vec<[u8; 32]>,
    pub external_data_hash: [u8; 32],
    pub allow_dummy_inputs: [u8; 32],
    pub signing_pk_field: [u8; 32],
}

pub struct MergeChainProof<'a> {
    ix: &'a MergeChainTransactIxDataRef<'a>,
    derived: MergeChainProofInputs,
}

impl<'a> MergeChainProof<'a> {
    pub fn new(ix: &'a MergeChainTransactIxDataRef<'a>, derived: MergeChainProofInputs) -> Self {
        Self { ix, derived }
    }

    /// A `vk-registry` build always goes through `verify_registered`, which
    /// falls back to the plain path itself.
    #[cfg(not(feature = "vk-registry"))]
    #[inline(never)]
    pub fn verify(&self) -> ProgramResult {
        self.statement()?.verify()
    }

    /// Registry-backed verification. `None` falls back to [`Self::verify`].
    /// The level shape names the outer key and the spec resolves from that
    /// key, so shape and registry cannot disagree.
    #[cfg(feature = "vk-registry")]
    #[inline(never)]
    pub fn verify_registered(&self, registry: Option<&pinocchio::AccountView>) -> ProgramResult {
        let statement = self.statement()?;
        let spec = zolana_interface::verifying_keys::registry_spec::vk_registry_spec_for(
            statement.verifying_key,
        )
        .ok_or(ShieldedPoolError::InvalidVkRegistryAccount)?;
        statement.verify_registered(registry, spec)
    }

    fn statement(&self) -> Result<verifier::Groth16Statement<'_>, ProgramError> {
        // The level shape is attacker-controlled and names the outer key, so an
        // unlisted shape is rejected before any pairing runs.
        let verifying_key = merge_chain_verifying_key(&self.ix.levels)
            .ok_or(ShieldedPoolError::UnsupportedMergeChainShape)?;
        let p = &self.ix.proof;
        Ok(verifier::Groth16Statement {
            proof: verifier::CompressedGroth16Proof {
                a: p.a,
                b: p.b,
                c: p.c,
                // Always present. Emulated arithmetic in the recursive verifier
                // range-checks its limbs, which produces the commitment.
                commitment: Some((
                    &self.ix.bsb22_commitment.commitment,
                    &self.ix.bsb22_commitment.commitment_pok,
                )),
            },
            public_input_hash: self.public_input_hash()?,
            verifying_key,
            encoding_err: ShieldedPoolError::InvalidTransactProofEncoding,
            verify_err: ShieldedPoolError::TransactProofVerificationFailed,
        })
    }

    /// The Poseidon hash chain the outer circuit folds into its single public
    /// input (`prover/server/circuits/spp_merge_chain/chain.go`).
    ///
    /// The eight elements are a single merge's, widened. The per-slot vectors
    /// run over every tree-backed slot of every leg, and the private tx hashes
    /// of the legs are chained where a merge carries one.
    pub fn public_input_hash(&self) -> Result<[u8; 32], ProgramError> {
        let fields = [
            create_hash_chain_from_slice(&self.ix.nullifiers)?,
            *self.ix.output_utxo_hash,
            create_hash_chain_from_slice(&self.derived.utxo_roots)?,
            create_hash_chain_from_slice(&self.derived.nullifier_tree_roots)?,
            create_hash_chain_from_slice(&self.ix.private_tx_hashes)?,
            self.derived.external_data_hash,
            self.derived.allow_dummy_inputs,
            self.derived.signing_pk_field,
        ];
        create_hash_chain_from_slice(&fields).map_err(Into::into)
    }
}
