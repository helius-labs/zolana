mod buffer;
mod commit;
mod prepare;

pub use buffer::process_buffer;
pub use commit::process_commit;
pub use prepare::process_prepare;

use borsh::BorshDeserialize;
use pinocchio::{error::ProgramError, AccountView, ProgramResult};
use zolana_hasher::hash_chain::create_hash_chain_4_from_slice;
use zolana_interface::{
    direct_spend::{Payload, Proof, Root},
    error::ShieldedPoolError,
    state::discriminator::TREE_ACCOUNT_DISCRIMINATOR,
};
use zolana_tree::{SppTreeLayout, TreeAccount, INITIALIZED};

pub fn load_payload(account: &AccountView, owner: &[u8; 32]) -> Result<Payload, ProgramError> {
    if !account.owned_by(&crate::ID) {
        return Err(ProgramError::IllegalOwner);
    }
    let bytes = account.try_borrow()?;
    let buffer = buffer::read(&bytes)?;
    if buffer.owner() != owner || buffer.status() == 2 {
        return Err(ProgramError::InvalidAccountData);
    }
    Payload::try_from_slice(buffer.payload()?).map_err(|_| ProgramError::InvalidAccountData)
}

fn tree_layout<'a>(
    account: &AccountView,
    bytes: &'a [u8],
) -> Result<&'a SppTreeLayout, ProgramError> {
    if !account.owned_by(&crate::ID) {
        return Err(ProgramError::IllegalOwner);
    }
    let tree = TreeAccount::read_layout(bytes).map_err(super::shared::tree_error)?;
    if tree.discriminator != TREE_ACCOUNT_DISCRIMINATOR
        || tree.state != INITIALIZED
        || tree._reserved[0] != 1
    {
        return Err(ShieldedPoolError::InvalidTreeAccounts.into());
    }
    Ok(tree)
}

fn check_freshness(tree: &SppTreeLayout, root: Root) -> ProgramResult {
    if tree.nullifier.root_by_index(root.index) != Some(root.value) {
        return Err(ShieldedPoolError::InvalidTreeAccounts.into());
    }
    Ok(())
}

fn verify(
    proof: &Proof,
    fields: &[[u8; 32]],
    key: &groth16_solana::groth16::Groth16Verifyingkey,
) -> ProgramResult {
    verify_with_commitment(proof, None, fields, key)
}

fn verify_with_commitment(
    proof: &Proof,
    commitment: Option<&zolana_interface::verifying_keys::Bsb22Commitment>,
    fields: &[[u8; 32]],
    key: &groth16_solana::groth16::Groth16Verifyingkey,
) -> ProgramResult {
    super::verifier::verify_groth16(
        super::verifier::Groth16Proof {
            a: &proof.a,
            b: &proof.b,
            c: &proof.c,
            commitment: commitment.map(|pair| (&pair.commitment, &pair.commitment_pok)),
        },
        create_hash_chain_4_from_slice(fields)?,
        key,
        ShieldedPoolError::InvalidTransactProofEncoding,
        ShieldedPoolError::TransactProofVerificationFailed,
    )
}
