use pinocchio::{
    address::address_eq,
    cpi::{Seed, Signer},
    error::ProgramError,
    AccountView, Address, ProgramResult,
};
use solana_address::address;
use zolana_account_checks::AccountIterator;
use zolana_interface::{state::tree::read_tree_id, PROGRAM_ID_PUBKEY};
use zolana_program::{compression::SppTransactCpi, cpi::SppTransactAccounts};

use crate::error::CompressionError;

pub const DEFAULT_TREE: Address = address!("33KVhbT4QtdQDrrrGwwThqD47Dh4Q6tA443t9jMNcWFN");

#[cfg(any(target_os = "solana", target_arch = "bpf"))]
pub fn derive_pda(authority: &Address) -> (Address, u8) {
    Address::find_program_address(&[crate::ACCOUNT_PDA_SEED, authority.as_array()], &crate::ID)
}

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
pub fn derive_pda(_authority: &Address) -> (Address, u8) {
    unimplemented!("PDA derivation requires Solana runtime syscalls")
}

pub struct TransitionAccounts<'a> {
    pub authority: &'a AccountView,
    pub payer: &'a AccountView,
    pub input_tree: &'a AccountView,
    pub output_tree: &'a AccountView,
    pub spp_program: &'a AccountView,
    pub system_program: &'a AccountView,
    pub nullifier_pda: &'a AccountView,
    pub owner_pda: &'a AccountView,
    pub pda: Address,
    pub bump: u8,
}

impl<'a> TransitionAccounts<'a> {
    pub fn validate_and_parse(accounts: &'a mut [AccountView]) -> Result<Self, ProgramError> {
        let mut iter = AccountIterator::new(accounts);
        let authority = iter.next_signer("authority")?;
        let (pda, bump) = derive_pda(authority.address());
        let payer = iter.next_account("payer")?;
        if !address_eq(payer.address(), authority.address()) {
            return Err(CompressionError::InvalidAuthority.into());
        }
        let output_tree = iter.next_account("output_tree")?;
        let spp_program = iter.next_account("spp_program")?;
        if !address_eq(spp_program.address(), &PROGRAM_ID_PUBKEY) {
            return Err(CompressionError::InvalidAccounts.into());
        }
        let system_program = iter.next_account("system_program")?;
        if system_program.address() != &Address::default() {
            return Err(CompressionError::InvalidAccounts.into());
        }
        let input_tree = iter.next_account("input_tree")?;
        let nullifier_pda = iter.next_mut("nullifier_pda")?;
        let owner_pda = iter.next_account("owner_pda")?;
        if !address_eq(owner_pda.address(), &pda) {
            return Err(CompressionError::InvalidPda.into());
        }
        if !iter.iterator_is_empty() {
            return Err(CompressionError::InvalidAccounts.into());
        }
        Ok(Self {
            authority,
            payer,
            input_tree,
            output_tree,
            spp_program,
            system_program,
            nullifier_pda,
            owner_pda,
            pda,
            bump,
        })
    }
}

/// Raw id of a pool tree, read from its account. Every UTXO commitment folds it
/// in as the second Poseidon element, so the program must use the same id the
/// circuit was proven against rather than assuming one.
pub fn tree_id(tree: &AccountView) -> Result<u16, ProgramError> {
    let data = tree
        .try_borrow()
        .map_err(|_| CompressionError::InvalidAccounts)?;
    read_tree_id(&data).ok_or_else(|| CompressionError::InvalidTree.into())
}

/// Invokes `cpi` through the transact accounts that follow the authority,
/// signing for the authority's PDA.
pub fn invoke_signed_by_pda(
    accounts: &[AccountView],
    authority: &Address,
    pda: &Address,
    bump: u8,
    cpi: SppTransactCpi,
) -> ProgramResult {
    let transact_accounts = accounts
        .get(1..)
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let signer_pdas = [pda];
    let spp = SppTransactAccounts::new(transact_accounts, &signer_pdas)?;
    let bump_seed = [bump];
    let seeds = [
        Seed::from(crate::ACCOUNT_PDA_SEED),
        Seed::from(authority.as_array().as_slice()),
        Seed::from(bump_seed.as_ref()),
    ];
    cpi.invoke::<8>(&spp, &[Signer::from(seeds.as_ref())])
}
