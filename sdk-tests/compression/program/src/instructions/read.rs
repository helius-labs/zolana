use groth16_solana::{
    decompression::{decompress_g1, decompress_g2},
    groth16::Groth16Verifier,
};
use light_program_profiler::profile;
use pinocchio::{address::address_eq, error::ProgramError, AccountView, Address, ProgramResult};
use wincode::{SchemaRead, SchemaWrite};
use zolana_account_checks::AccountIterator;
use zolana_hasher::{Hasher, Poseidon};
use zolana_interface::state::discriminator::TREE_ACCOUNT_DISCRIMINATOR;
use zolana_tree::TreeAccount;

use crate::{
    error::CompressionError,
    instructions::shared::{derive_pda, SPP_PROGRAM},
    state::{nullifier, AccountState, PdaOwner},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct ReadProof {
    pub proof_a: [u8; 32],
    pub proof_b: [u8; 64],
    pub proof_c: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct ReadIxData {
    pub value: u64,
    pub version: u64,
    /// Blinding of the UTXO being read, as published with its state. A wrong
    /// value yields a UTXO hash the proof cannot show in the state tree.
    pub blinding: [u8; 32],
    pub nullifier_tree_root_index: u16,
    pub utxo_tree_root_index: u16,
    pub proof: ReadProof,
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
        blinding,
        nullifier_tree_root_index,
        utxo_tree_root_index,
        proof,
    } = wincode::deserialize_exact(data).map_err(|_| CompressionError::InvalidInstructionData)?;

    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_account("authority")?;
    let tree = iter.next_account("tree")?;
    let nullifier_pda = iter.next_account("nullifier_pda")?;
    if !iter.iterator_is_empty() {
        return Err(CompressionError::InvalidAccounts.into());
    }

    let (utxo_root, nullifier_root, tree_id) =
        load_tree_roots(tree, utxo_tree_root_index, nullifier_tree_root_index)?;
    let (pda, _) = derive_pda(authority.address());
    let owner = PdaOwner::new(pda.as_array())?;
    let state = AccountState {
        address: owner.address(tree_id)?,
        authority: authority.address().to_bytes(),
        value,
        version,
        blinding,
    };
    let utxo_hash = state.utxo_hash(&owner.owner_hash, tree_id)?;
    let nullifier_hash = nullifier(&utxo_hash, &blinding)?;

    // 1. and 2.
    verify_read_proof(
        &proof,
        ReadPublicInput {
            utxo_hash: &utxo_hash,
            utxo_root: &utxo_root,
            nullifier: &nullifier_hash,
            nullifier_root: &nullifier_root,
        }
        .hash()?,
    )?;

    // 3.
    if !address_eq(
        nullifier_pda.address(),
        &derive_nullifier_pda(tree.address(), &nullifier_hash),
    ) {
        return Err(CompressionError::InvalidNullifierPda.into());
    }
    if !nullifier_pda.owned_by(&Address::default()) || nullifier_pda.data_len() != 0 {
        return Err(CompressionError::StateSpent.into());
    }
    Ok(())
}

/// The roots at the client's history indices and the raw tree id, from a tree
/// account the pool owns. The tree is loaded read-only: nothing is written.
fn load_tree_roots(
    tree: &mut AccountView,
    utxo_tree_root_index: u16,
    nullifier_tree_root_index: u16,
) -> Result<([u8; 32], [u8; 32], u16), ProgramError> {
    if !tree.owned_by(&SPP_PROGRAM) {
        return Err(CompressionError::InvalidTreeAccount.into());
    }
    let pubkey = tree.address().to_bytes();
    let mut data = tree
        .try_borrow_mut()
        .map_err(|_| CompressionError::InvalidTreeAccount)?;
    if data.first() != Some(&TREE_ACCOUNT_DISCRIMINATOR) {
        return Err(CompressionError::InvalidTreeAccount.into());
    }
    let tree = TreeAccount::from_bytes(&mut data, pubkey)
        .map_err(|_| CompressionError::InvalidTreeAccount)?;
    let utxo_root = tree
        .get_utxo_tree_root(utxo_tree_root_index)
        .map_err(|_| CompressionError::InvalidRootIndex)?;
    let nullifier_root = tree
        .get_nullifier_tree_root(nullifier_tree_root_index)
        .map_err(|_| CompressionError::InvalidRootIndex)?;
    Ok((utxo_root, nullifier_root, tree.tree_id()))
}

#[inline(never)]
fn verify_read_proof(proof: &ReadProof, public_input_hash: [u8; 32]) -> ProgramResult {
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

#[cfg(any(target_os = "solana", target_arch = "bpf"))]
fn derive_nullifier_pda(tree: &Address, nullifier: &[u8; 32]) -> Address {
    Address::find_program_address(
        &[
            zolana_interface::NULLIFIER_PDA_SEED,
            tree.as_array(),
            nullifier,
        ],
        &SPP_PROGRAM,
    )
    .0
}

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
fn derive_nullifier_pda(_tree: &Address, _nullifier: &[u8; 32]) -> Address {
    unimplemented!("PDA derivation requires Solana runtime syscalls")
}
