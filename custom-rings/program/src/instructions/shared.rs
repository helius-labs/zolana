#[cfg(any(target_os = "solana", target_arch = "bpf"))]
use pinocchio::{
    cpi::{invoke_signed_with_slice, Seed, Signer, MAX_CPI_ACCOUNTS},
    instruction::{InstructionAccount, InstructionView},
    Address,
};
use pinocchio::{AccountView, ProgramResult};
#[cfg(any(target_os = "solana", target_arch = "bpf"))]
use zolana_interface::{RING_AUTH_PDA_SEED, SHIELDED_POOL_PROGRAM_ID};

#[cfg(any(target_os = "solana", target_arch = "bpf"))]
use crate::error::CustomRingError;

/// Split a 33-byte SEC1-compressed P256 key into the two BN254 field elements
/// the auditor circuit hashes.
///
/// Mirrors `Pack33To2FECircuit`
/// (`custom-rings/prover/circuits/auditor_key_encryption/pack.go`, the source
/// of truth) and the SDK's host copy in `custom-ring-sdk::encryption`:
///
/// ```text
/// lo = 0x00 || key[0..31]        (the SEC1 prefix is the most significant data byte)
/// hi = key[31] * 256 + key[32]
/// ```
///
/// A 33-byte key does not fit one field element, and the split is injective
/// because every input byte is 8 bits wide, so the pair binds the key uniquely.
#[inline(always)]
pub fn pack33_to_2fe(key: &[u8; 33]) -> ([u8; 32], [u8; 32]) {
    let mut lo = [0u8; 32];
    let mut hi = [0u8; 32];
    // Constant ranges over a fixed-size array: the compiler proves both fit.
    lo[1..32].copy_from_slice(&key[0..31]);
    hi[30] = key[31];
    hi[31] = key[32];
    (lo, hi)
}

/// Forward `data` to SPP with this ring's `ring_auth` PDA flipped to a signer.
///
/// `accounts` must already be ordered exactly as the target SPP instruction
/// expects: the CPI metas are rebuilt from it one-to-one, and pinocchio matches
/// account views to metas by position. `data` keeps its leading tag byte because
/// SPP's dispatcher strips it.
///
/// Only the `ring_auth` account gains a signature; every other privilege is
/// copied from the account view, so the ring cannot escalate an account the
/// caller passed as readonly or unsigned.
///
/// The generic account type lets callers either forward their whole account list
/// (`deposit`, `transact`) or hand-pick a reordered subset (`init_spp_ring_config`).
#[cfg(any(target_os = "solana", target_arch = "bpf"))]
#[inline(never)]
pub fn cpi_spp_signed<A: AsRef<AccountView>>(accounts: &[A], data: &[u8]) -> ProgramResult {
    let (ring_auth, bump) = Address::find_program_address(&[RING_AUTH_PDA_SEED], &crate::ID);
    if !accounts
        .iter()
        .any(|account| account.as_ref().address() == &ring_auth)
    {
        return Err(CustomRingError::MissingRingAuth.into());
    }

    // A ring transact with the maximum signers and settlement legs exceeds any
    // small static bound, so the CPI account table lives on the heap and the
    // only limit is the runtime's.
    if accounts.len() > MAX_CPI_ACCOUNTS {
        return Err(CustomRingError::TooManyAccounts.into());
    }
    let metas: Vec<InstructionAccount> = accounts
        .iter()
        .map(|account| {
            let account = account.as_ref();
            let is_signer = account.is_signer() || account.address() == &ring_auth;
            InstructionAccount::new(account.address(), account.is_writable(), is_signer)
        })
        .collect();

    let spp_id = Address::from(SHIELDED_POOL_PROGRAM_ID);
    let instruction = InstructionView {
        program_id: &spp_id,
        accounts: &metas,
        data,
    };
    let bump = [bump];
    let seeds = [Seed::from(RING_AUTH_PDA_SEED), Seed::from(bump.as_ref())];
    let signer = Signer::from(seeds.as_ref());
    invoke_signed_with_slice(&instruction, accounts, core::slice::from_ref(&signer))
}

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
#[inline(never)]
pub fn cpi_spp_signed<A: AsRef<AccountView>>(_accounts: &[A], _data: &[u8]) -> ProgramResult {
    unimplemented!("cpi_spp_signed requires Solana runtime syscalls")
}
