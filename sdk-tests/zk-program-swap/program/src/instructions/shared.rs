use light_program_profiler::profile;
#[cfg(any(target_os = "solana", target_arch = "bpf"))]
use pinocchio::cpi::{invoke_signed_with_bounds, Seed, Signer};
use pinocchio::{
    cpi::invoke_with_bounds,
    error::ProgramError,
    instruction::{InstructionAccount, InstructionView},
    AccountView, Address, ProgramResult,
};
use zolana_hasher::{Hasher, Poseidon};
use zolana_interface::{instruction::tag::TRANSACT, SHIELDED_POOL_PROGRAM_ID};

use crate::error::SwapError;

// TODO: check whether we have this in the spp interface crate
pub fn u64_to_field(value: u64) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[24..32].copy_from_slice(&value.to_be_bytes());
    bytes
}

// TODO: check whether we have this in the spp interface crate
fn pack33(bytes: &[u8; 33]) -> ([u8; 32], [u8; 32]) {
    let mut lo = [0u8; 32];
    lo[1..32].copy_from_slice(&bytes[0..31]);
    let mut hi = [0u8; 32];
    hi[30] = bytes[31];
    hi[31] = bytes[32];
    (lo, hi)
}
// TODO: remove this is only used in a test
pub fn maker_address_fe(
    owner_hash: &[u8; 32],
    viewing_pk: &[u8; 33],
) -> Result<[u8; 32], ProgramError> {
    let (lo, hi) = pack33(viewing_pk);
    Poseidon::hashv(&[owner_hash.as_slice(), lo.as_slice(), hi.as_slice()])
        .map_err(|_| SwapError::ProofVerificationFailed.into())
}

/// `owner_pk_field` for an ed25519 owner: `Poseidon(value[16..32], value[0..16])`
/// with each half right-aligned into a field element. Matches
/// `zolana_keypair::hash::hash_field` so the maker's on-chain signer pubkey maps
/// to the `owner_pk_field` committed in the escrow's `maker_owner_hash`.
pub fn hash_field(value: &[u8; 32]) -> Result<[u8; 32], ProgramError> {
    let mut low = [0u8; 32];
    low[16..].copy_from_slice(&value[16..32]);
    let mut high = [0u8; 32];
    high[16..].copy_from_slice(&value[0..16]);
    Poseidon::hashv(&[low.as_slice(), high.as_slice()])
        .map_err(|_| SwapError::ProofVerificationFailed.into())
}

#[inline(never)]
#[profile]
pub fn cpi_spp_transact(spp_accounts: &[AccountView], transact_bytes: &[u8]) -> ProgramResult {
    let spp_program_account = spp_accounts
        .last()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let spp_id = Address::from(SHIELDED_POOL_PROGRAM_ID);
    if spp_program_account.address() != &spp_id {
        return Err(SwapError::InvalidPda.into());
    }

    let metas: Vec<InstructionAccount> = spp_accounts
        .iter()
        .map(|a| InstructionAccount::new(a.address(), a.is_writable(), a.is_signer()))
        .collect();

    let mut data = Vec::with_capacity(1 + transact_bytes.len());
    data.push(TRANSACT);
    data.extend_from_slice(transact_bytes);

    let instruction = InstructionView {
        program_id: &spp_id,
        accounts: &metas,
        data: &data,
    };
    invoke_with_bounds::<16, _>(&instruction, spp_accounts)
}

#[cfg(any(target_os = "solana", target_arch = "bpf"))]
#[inline(never)]
#[profile]
pub fn cpi_spp_transact_signed(
    spp_accounts: &[AccountView],
    transact_bytes: &[u8],
) -> ProgramResult {
    let (escrow_authority, bump) =
        Address::find_program_address(&[crate::ESCROW_AUTHORITY_PDA_SEED], &crate::ID);

    let spp_program_account = spp_accounts
        .last()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let spp_id = Address::from(SHIELDED_POOL_PROGRAM_ID);
    if spp_program_account.address() != &spp_id {
        return Err(SwapError::InvalidPda.into());
    }

    if !spp_accounts
        .iter()
        .any(|a| a.address() == &escrow_authority)
    {
        return Err(SwapError::MissingEscrowAuthority.into());
    }

    let metas: Vec<InstructionAccount> = spp_accounts
        .iter()
        .map(|a| {
            let is_signer = a.is_signer() || a.address() == &escrow_authority;
            InstructionAccount::new(a.address(), a.is_writable(), is_signer)
        })
        .collect();

    let mut data = Vec::with_capacity(1 + transact_bytes.len());
    data.push(TRANSACT);
    data.extend_from_slice(transact_bytes);

    let instruction = InstructionView {
        program_id: &spp_id,
        accounts: &metas,
        data: &data,
    };
    let bump = [bump];
    let seeds = [
        Seed::from(crate::ESCROW_AUTHORITY_PDA_SEED),
        Seed::from(&bump),
    ];
    let signer = Signer::from(&seeds);
    invoke_signed_with_bounds::<16, _>(&instruction, spp_accounts, core::slice::from_ref(&signer))
}

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
#[inline(never)]
pub fn cpi_spp_transact_signed(
    _spp_accounts: &[AccountView],
    _transact_bytes: &[u8],
) -> ProgramResult {
    unimplemented!("cpi_spp_transact_signed requires Solana runtime syscalls")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack33_layout() {
        let mut bytes = [0u8; 33];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = i as u8;
        }
        let (lo, hi) = pack33(&bytes);

        let mut expected_lo = [0u8; 32];
        expected_lo[1..32].copy_from_slice(&bytes[0..31]);
        let mut expected_hi = [0u8; 32];
        expected_hi[30] = bytes[31];
        expected_hi[31] = bytes[32];

        assert_eq!(lo, expected_lo);
        assert_eq!(hi, expected_hi);
    }

    #[test]
    fn maker_address_fe_matches_poseidon_of_packed_inputs() {
        let owner_hash = [7u8; 32];
        let mut viewing_pk = [0u8; 33];
        viewing_pk[0] = 2;
        viewing_pk[32] = 9;
        let (lo, hi) = pack33(&viewing_pk);
        let expected =
            Poseidon::hashv(&[owner_hash.as_slice(), lo.as_slice(), hi.as_slice()]).unwrap();
        assert_eq!(
            maker_address_fe(&owner_hash, &viewing_pk).unwrap(),
            expected
        );
    }
}
