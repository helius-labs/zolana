use groth16_solana::{
    decompression::{decompress_g1, decompress_g2},
    groth16::Groth16Verifier,
};
use light_program_profiler::profile;
use pinocchio::{error::ProgramError, AccountView, ProgramResult};
use wincode::{SchemaRead, SchemaWrite};
use zolana_account_checks::AccountIterator;
use zolana_hasher::{Hasher, Poseidon};
use zolana_program::compression::{
    CompressedAccountData, CompressedAccountMeta, CompressedProof, DataUtxo, PdaOwner, ReadRoots,
};

use crate::{
    error::{compressed_account_error, CompressionError},
    instructions::shared::derive_pda,
    state::AccountState,
};

#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct ReadIxData {
    pub value: u64,
    pub version: u64,
    /// The UTXO being read: its address, blinding and root indexes.
    pub meta: CompressedAccountMeta,
    pub proof: CompressedProof,
}

pub struct ReadPublicInput<'a> {
    pub utxo_hash: &'a [u8; 32],
    pub utxo_root: &'a [u8; 32],
    pub nullifier: &'a [u8; 32],
    pub nullifier_root: &'a [u8; 32],
}

impl ReadPublicInput<'_> {
    pub fn hash(&self) -> Result<[u8; 32], ProgramError> {
        Poseidon::hashv(&[
            self.utxo_hash.as_slice(),
            self.utxo_root.as_slice(),
            self.nullifier.as_slice(),
            self.nullifier_root.as_slice(),
        ])
        .map_err(|_| CompressionError::HashingFailed.into())
    }
}

/// Proves the supplied state is the account's current version without
/// spending it, under the pool's own freshness rule:
/// 1. the state's UTXO hash is in the tree's state tree under any root in its
///    root history,
/// 2. its nullifier is absent from the nullifier tree under any root in its
///    root history,
/// 3. its nullifier PDA does not exist.
///
/// 2 alone misses a nullifier that is still queued; 3 alone misses a spend
/// whose PDA was closed. A nullifier PDA closes only once every root in the
/// history contains its nullifier, so 2 and 3 together cover every spend.
#[inline(never)]
#[profile]
pub fn process_read_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let ReadIxData {
        value,
        version,
        meta,
        proof,
    } = wincode::deserialize_exact(data).map_err(|_| CompressionError::InvalidInstructionData)?;

    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_account("authority")?;
    let tree = iter.next_account("tree")?;
    let nullifier_pda = iter.next_account("nullifier_pda")?;
    if !iter.iterator_is_empty() {
        return Err(CompressionError::InvalidAccounts.into());
    }

    let roots = ReadRoots::load(tree, &meta.tree_context).map_err(compressed_account_error)?;
    let (pda, _) = derive_pda(authority.address());
    let owner = PdaOwner::new(&pda).map_err(compressed_account_error)?;
    let state = AccountState {
        address: meta.address,
        authority: authority.address().to_bytes(),
        value,
        version,
        blinding: meta.blinding,
    };
    let key = roots
        .key(&DataUtxo {
            owner: &owner,
            data_hash: state.data_hash()?,
            blinding: meta.blinding,
        })
        .map_err(compressed_account_error)?;

    // 1. and 2.
    verify_read_proof(
        &proof,
        ReadPublicInput {
            utxo_hash: key.hash(),
            utxo_root: roots.utxo_root(),
            nullifier: key.nullifier(),
            nullifier_root: roots.nullifier_root(),
        }
        .hash()?,
    )?;

    // 3.
    roots
        .assert_unspent(nullifier_pda, &key)
        .map_err(compressed_account_error)
}

#[inline(never)]
fn verify_read_proof(proof: &CompressedProof, public_input_hash: [u8; 32]) -> ProgramResult {
    let err = CompressionError::ProofVerificationFailed;
    let proof_a = decompress_g1(&proof.proof_a).map_err(|_| err)?;
    let proof_b = decompress_g2(&proof.proof_b).map_err(|_| err)?;
    let proof_c = decompress_g1(&proof.proof_c).map_err(|_| err)?;
    Groth16Verifier::new(
        &proof_a,
        &proof_b,
        &proof_c,
        &[public_input_hash],
        &crate::verifying_keys::read::VERIFYINGKEY,
    )
    .map_err(|_| err)?
    .verify()
    .map_err(|_| err.into())
}
