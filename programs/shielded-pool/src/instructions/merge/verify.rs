use pinocchio::{error::ProgramError, ProgramResult};
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::instruction_data::merge_transact::{MergeTransactIxDataRef, MERGE_INPUT_COUNT},
    merge_utils::{ciphertext_hash, pack33, pk_field_compressed},
    verifying_keys::merge_8_1,
};

use crate::instructions::verifier;

const PROOF_ERR: ShieldedPoolError = ShieldedPoolError::TransactProofVerificationFailed;

/// Derived public inputs the program resolves from the tree and the registry,
/// folded into the merge public-input hash alongside the instruction fields.
pub struct MergeProofInputs {
    pub utxo_roots: [[u8; 32]; MERGE_INPUT_COUNT],
    pub nullifier_tree_roots: [[u8; 32]; MERGE_INPUT_COUNT],
    pub external_data_hash: [u8; 32],
    /// `pk_field(owner_p256)` from the registry record.
    pub signing_pk_field: [u8; 32],
    /// `pk_field(viewing_pubkey)` from the registry record.
    pub viewing_pk_field: [u8; 32],
}

pub struct MergeProof<'a> {
    ix: &'a MergeTransactIxDataRef<'a>,
    derived: MergeProofInputs,
}

impl<'a> MergeProof<'a> {
    pub fn new(ix: &'a MergeTransactIxDataRef<'a>, derived: MergeProofInputs) -> Self {
        Self { ix, derived }
    }

    #[inline(never)]
    pub fn verify(&self) -> ProgramResult {
        let public_input_hash = self.public_input_hash()?;
        verifier::verify_groth16(
            self.ix.proof,
            public_input_hash,
            &merge_8_1::VERIFYINGKEY,
            ShieldedPoolError::InvalidTransactProofEncoding,
            PROOF_ERR,
        )
    }

    /// The 11-element Poseidon hash chain the circuit folds into its single public
    /// input (`prover/server/circuits/spp_merge/circuit.go` `publicInputHash`).
    pub fn public_input_hash(&self) -> Result<[u8; 32], ProgramError> {
        let tx_viewing_pk = self
            .ix
            .tx_viewing_pk()
            .map_err(|_| ShieldedPoolError::InvalidMergeShape)?;
        let ciphertext = self
            .ix
            .ciphertext()
            .map_err(|_| ShieldedPoolError::InvalidMergeShape)?;
        let (tx_viewing_pk_lo, tx_viewing_pk_hi) = pack33(tx_viewing_pk);
        let ct_hash = ciphertext_hash(ciphertext).map_err(|_| PROOF_ERR)?;

        let chain = [
            hash_chain(&self.ix.nullifiers)?,
            *self.ix.output_utxo_hash,
            hash_chain(&self.derived.utxo_roots)?,
            hash_chain(&self.derived.nullifier_tree_roots)?,
            *self.ix.private_tx_hash,
            self.derived.external_data_hash,
            self.derived.signing_pk_field,
            self.derived.viewing_pk_field,
            tx_viewing_pk_lo,
            tx_viewing_pk_hi,
            ct_hash,
        ];
        hash_chain(&chain)
    }
}

/// `pk_field` of a compressed P256 key, used by the processor to derive the
/// registry-bound owner identity inputs.
pub fn pk_field(compressed: &[u8; 33]) -> Result<[u8; 32], ProgramError> {
    pk_field_compressed(compressed).map_err(|_| ShieldedPoolError::InvalidUserRecord.into())
}

fn hash_chain(items: &[[u8; 32]]) -> Result<[u8; 32], ProgramError> {
    verifier::hash_chain(items, PROOF_ERR)
}
