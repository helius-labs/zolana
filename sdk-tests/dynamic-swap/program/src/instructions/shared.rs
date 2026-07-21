use light_program_profiler::profile;
#[cfg(any(target_os = "solana", target_arch = "bpf"))]
use pinocchio::cpi::invoke_signed_with_bounds;
use pinocchio::{
    cpi::{invoke_with_bounds, Seed, Signer},
    error::ProgramError,
    instruction::{InstructionAccount, InstructionView},
    AccountView, Address, ProgramResult,
};
use zolana_hasher::{Hasher, Poseidon};
use zolana_interface::{instruction::tag::TRANSACT, SHIELDED_POOL_PROGRAM_ID};

use crate::error::DynamicSwapError;

pub fn u64_right_align(value: u64) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[24..32].copy_from_slice(&value.to_be_bytes());
    bytes
}

/// `owner_pk_field` for an ed25519 owner: `Poseidon(value[16..32], value[0..16])`
/// with each half right-aligned into a field element. Matches
/// `zolana_keypair::hash::hash_field` so a Solana signer pubkey maps to the
/// `owner_pk_field` committed by a circuit's owner-hash binding.
pub fn hash_field(value: &[u8; 32]) -> Result<[u8; 32], ProgramError> {
    let mut low = [0u8; 32];
    low[16..].copy_from_slice(&value[16..32]);
    let mut high = [0u8; 32];
    high[16..].copy_from_slice(&value[0..16]);
    Poseidon::hashv(&[low.as_slice(), high.as_slice()])
        .map_err(|_| DynamicSwapError::HashingFailed.into())
}

/// The escrow_authority PDA's owner-hash for `pair`, recomputed from the PDA
/// itself so the program never trusts a client value for the `escrow_open`
/// circuit's `EscrowAuthorityOwnerHash` public input. Mirrors the SDK's
/// `EscrowUtxo::order_utxo_owner_hash`: `Poseidon(owner_pk_field(pda),
/// nullifier_pubkey)`, where for an ed25519 owner `owner_pk_field ==
/// hash_field(pda_bytes)` and the constant zero-secret nullifier key's pubkey
/// is `Poseidon(fe_right_align([0u8; 31])) == Poseidon([0u8; 32])`.
#[cfg(any(target_os = "solana", target_arch = "bpf"))]
pub fn escrow_authority_owner_hash(pair: &Address) -> Result<[u8; 32], ProgramError> {
    let (pda, _bump) = derive_authority_pda(crate::ESCROW_AUTHORITY_PDA_SEED, pair);
    let owner_pk_field = hash_field(pda.as_array())?;
    let nullifier_pubkey =
        Poseidon::hashv(&[[0u8; 32].as_slice()]).map_err(|_| DynamicSwapError::HashingFailed)?;
    Poseidon::hashv(&[owner_pk_field.as_slice(), nullifier_pubkey.as_slice()])
        .map_err(|_| DynamicSwapError::HashingFailed.into())
}

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
pub fn escrow_authority_owner_hash(_pair: &Address) -> Result<[u8; 32], ProgramError> {
    unimplemented!("escrow_authority_owner_hash requires Solana runtime syscalls")
}

/// Create a program-derived account. Handles both the hot path (the account has
/// no lamports) and the cold path (an attacker pre-funded the address) via the
/// pinocchio system helper; a raw `CreateAccount` would fail on a donated
/// balance and let an attacker DoS the creation.
///
/// `signer_seeds` must NOT include the bump; it is appended automatically.
pub struct CreatePdaAccount<'a, const N: usize> {
    pub fee_payer: &'a AccountView,
    pub new_account: &'a mut AccountView,
    pub space: usize,
    pub owner: &'a Address,
    pub signer_seeds: [&'a [u8]; N],
    pub bump: u8,
}

impl<const N: usize> CreatePdaAccount<'_, N> {
    #[inline(always)]
    pub fn execute(self) -> ProgramResult {
        let bump_seed = [self.bump];
        let s = self.signer_seeds;
        match N {
            1 => {
                let s0 = s.first().ok_or(ProgramError::InvalidArgument)?;
                let seeds = [Seed::from(*s0), Seed::from(bump_seed.as_ref())];
                pinocchio_system::create_account_with_minimum_balance_signed(
                    self.new_account,
                    self.space,
                    self.owner,
                    self.fee_payer,
                    None,
                    &[Signer::from(seeds.as_ref())],
                )
            }
            2 => {
                let s0 = s.first().ok_or(ProgramError::InvalidArgument)?;
                let s1 = s.get(1).ok_or(ProgramError::InvalidArgument)?;
                let seeds = [
                    Seed::from(*s0),
                    Seed::from(*s1),
                    Seed::from(bump_seed.as_ref()),
                ];
                pinocchio_system::create_account_with_minimum_balance_signed(
                    self.new_account,
                    self.space,
                    self.owner,
                    self.fee_payer,
                    None,
                    &[Signer::from(seeds.as_ref())],
                )
            }
            3 => {
                let s0 = s.first().ok_or(ProgramError::InvalidArgument)?;
                let s1 = s.get(1).ok_or(ProgramError::InvalidArgument)?;
                let s2 = s.get(2).ok_or(ProgramError::InvalidArgument)?;
                let seeds = [
                    Seed::from(*s0),
                    Seed::from(*s1),
                    Seed::from(*s2),
                    Seed::from(bump_seed.as_ref()),
                ];
                pinocchio_system::create_account_with_minimum_balance_signed(
                    self.new_account,
                    self.space,
                    self.owner,
                    self.fee_payer,
                    None,
                    &[Signer::from(seeds.as_ref())],
                )
            }
            4 => {
                let s0 = s.first().ok_or(ProgramError::InvalidArgument)?;
                let s1 = s.get(1).ok_or(ProgramError::InvalidArgument)?;
                let s2 = s.get(2).ok_or(ProgramError::InvalidArgument)?;
                let s3 = s.get(3).ok_or(ProgramError::InvalidArgument)?;
                let seeds = [
                    Seed::from(*s0),
                    Seed::from(*s1),
                    Seed::from(*s2),
                    Seed::from(*s3),
                    Seed::from(bump_seed.as_ref()),
                ];
                pinocchio_system::create_account_with_minimum_balance_signed(
                    self.new_account,
                    self.space,
                    self.owner,
                    self.fee_payer,
                    None,
                    &[Signer::from(seeds.as_ref())],
                )
            }
            _ => Err(ProgramError::InvalidArgument),
        }
    }
}

/// Derive the canonical PDA from `seeds` and `program_id`, then verify it
/// matches `account_key`. Returns the canonical bump on success.
#[cfg(any(target_os = "solana", target_arch = "bpf"))]
pub fn verify_pda(
    account_key: &Address,
    seeds: &[&[u8]],
    program_id: &Address,
) -> Result<u8, ProgramError> {
    use pinocchio::address::address_eq;

    let (derived, bump) = Address::find_program_address(seeds, program_id);
    if !address_eq(account_key, &derived) {
        return Err(DynamicSwapError::InvalidPda.into());
    }
    Ok(bump)
}

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
pub fn verify_pda(
    _account_key: &Address,
    _seeds: &[&[u8]],
    _program_id: &Address,
) -> Result<u8, ProgramError> {
    unimplemented!("verify_pda requires Solana runtime syscalls")
}

/// Derive a named authority PDA from `[seed_label, pair]` without checking it
/// against an existing account -- used by `settle` to compute both
/// `escrow_authority` and `pool_authority` ahead of a single
/// [`cpi_spp_transact_signed_multi`] call. `verify_pda` fits the
/// account-creation path (an address to check); this fits the CPI-signer
/// path (an address to compute), which needs the bump but no account to
/// compare against.
#[cfg(any(target_os = "solana", target_arch = "bpf"))]
pub fn derive_authority_pda(seed_label: &'static [u8], pair: &Address) -> (Address, u8) {
    Address::find_program_address(&[seed_label, pair.as_array()], &crate::ID)
}

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
pub fn derive_authority_pda(_seed_label: &'static [u8], _pair: &Address) -> (Address, u8) {
    unimplemented!("derive_authority_pda requires Solana runtime syscalls")
}

#[inline(never)]
#[profile]
pub fn cpi_spp_transact(spp_accounts: &[AccountView], transact_bytes: &[u8]) -> ProgramResult {
    let spp_program_account = spp_accounts
        .last()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let spp_id = Address::from(SHIELDED_POOL_PROGRAM_ID);
    if spp_program_account.address() != &spp_id {
        return Err(DynamicSwapError::InvalidShieldedPoolProgram.into());
    }

    let metas: Vec<InstructionAccount> = spp_accounts
        .iter()
        .map(|account| {
            InstructionAccount::new(
                account.address(),
                account.is_writable(),
                account.is_signer(),
            )
        })
        .collect();

    let mut instruction_data = Vec::with_capacity(1 + transact_bytes.len());
    instruction_data.push(TRANSACT);
    instruction_data.extend_from_slice(transact_bytes);

    let instruction = InstructionView {
        program_id: &spp_id,
        accounts: &metas,
        data: &instruction_data,
    };
    invoke_with_bounds::<16, _>(&instruction, spp_accounts)
}

/// Flip every PDA in `pdas` to a signer for one `transact` CPI. Each tuple is
/// `(seed_label, pair_address, derived_pda_address, bump)`; the caller derives
/// each PDA beforehand (`[seed_label, pair.as_array()]` via [`verify_pda`]-style
/// `find_program_address`). Signing seeds must reconstruct from the *original*
/// `pair` address (what the PDA was actually derived from), not from the PDA's
/// own address -- `create_program_address` cannot derive a PDA from itself, so
/// `pair_address` is threaded through alongside the already-derived PDA purely
/// for the invoke-signed seeds; the presence/is-signer checks below still match
/// on `derived_pda_address`. `settle` needs both `pool_authority` and
/// `escrow_authority` flipped in the same CPI, unlike the single-PDA
/// instructions.
#[cfg(any(target_os = "solana", target_arch = "bpf"))]
#[inline(never)]
#[profile]
pub fn cpi_spp_transact_signed_multi(
    spp_accounts: &[AccountView],
    transact_bytes: &[u8],
    pdas: &[(&[u8], Address, Address, u8)],
) -> ProgramResult {
    let spp_program_account = spp_accounts
        .last()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let spp_id = Address::from(SHIELDED_POOL_PROGRAM_ID);
    if spp_program_account.address() != &spp_id {
        return Err(DynamicSwapError::InvalidShieldedPoolProgram.into());
    }

    for (seed_label, _pair_address, pda, _) in pdas {
        if !spp_accounts.iter().any(|account| account.address() == pda) {
            return Err(if *seed_label == crate::ESCROW_AUTHORITY_PDA_SEED {
                DynamicSwapError::MissingEscrowAuthority.into()
            } else {
                DynamicSwapError::MissingPoolAuthority.into()
            });
        }
    }

    let metas: Vec<InstructionAccount> = spp_accounts
        .iter()
        .map(|account| {
            let is_signer =
                account.is_signer() || pdas.iter().any(|(_, _, pda, _)| account.address() == pda);
            InstructionAccount::new(account.address(), account.is_writable(), is_signer)
        })
        .collect();

    let mut instruction_data = Vec::with_capacity(1 + transact_bytes.len());
    instruction_data.push(TRANSACT);
    instruction_data.extend_from_slice(transact_bytes);

    let instruction = InstructionView {
        program_id: &spp_id,
        accounts: &metas,
        data: &instruction_data,
    };

    let bump_bytes: Vec<[u8; 1]> = pdas.iter().map(|(_, _, _, bump)| [*bump]).collect();
    let seed_sets: Vec<[Seed; 3]> = pdas
        .iter()
        .zip(bump_bytes.iter())
        .map(|((seed_label, pair_address, _, _), bump)| {
            [
                Seed::from(*seed_label),
                Seed::from(pair_address.as_array().as_slice()),
                Seed::from(bump.as_ref()),
            ]
        })
        .collect();
    let signers: Vec<Signer> = seed_sets.iter().map(|seeds| Signer::from(seeds)).collect();

    invoke_signed_with_bounds::<16, _>(&instruction, spp_accounts, &signers)
}

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
#[inline(never)]
pub fn cpi_spp_transact_signed_multi(
    _spp_accounts: &[AccountView],
    _transact_bytes: &[u8],
    _pdas: &[(&[u8], Address, Address, u8)],
) -> ProgramResult {
    unimplemented!("cpi_spp_transact_signed_multi requires Solana runtime syscalls")
}

/// Thin wrapper over [`cpi_spp_transact_signed_multi`] for the common single-PDA
/// case (`deposit_liquidity`, `withdraw_liquidity`): derives `pool_authority`
/// (or another named PDA) from `[seed_label, pair]` and flips only it to a
/// signer.
#[inline(never)]
pub fn cpi_spp_transact_signed(
    pair: &Address,
    seed_label: &'static [u8],
    spp_accounts: &[AccountView],
    transact_bytes: &[u8],
) -> ProgramResult {
    #[cfg(any(target_os = "solana", target_arch = "bpf"))]
    {
        let (pda, bump) = Address::find_program_address(&[seed_label, pair.as_array()], &crate::ID);
        cpi_spp_transact_signed_multi(
            spp_accounts,
            transact_bytes,
            &[(seed_label, *pair, pda, bump)],
        )
    }
    #[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
    {
        let _ = (pair, seed_label, spp_accounts, transact_bytes);
        unimplemented!("cpi_spp_transact_signed requires Solana runtime syscalls")
    }
}
