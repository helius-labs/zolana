use light_program_profiler::profile;
use pinocchio::{
    address::address_eq, cpi::Signer, error::ProgramError, AccountView, Address, ProgramResult,
};
use spr_hasher::{primitives::solana_owner_identity, Hasher, Poseidon};
use spr_program::cpi::{PdaSeeds, PdaSigner};

use crate::error::DynamicSwapError;

/// The escrow_authority PDA of `pair`, seeds `[ESCROW_AUTHORITY_PDA_SEED,
/// pair]`. It owns the pair's order and reservation UTXOs and signs their
/// transact CPIs.
pub fn escrow_authority(pair: &Address) -> PdaSigner<[&[u8]; 2]> {
    PdaSigner::find(
        [crate::ESCROW_AUTHORITY_PDA_SEED, pair.as_array()],
        &crate::ID,
    )
}

/// The escrow_authority PDA's owner-hash:
/// `Poseidon(solana_owner_identity(escrow_authority), nullifier_pubkey)` -- a
/// PDA is a Solana key, so its identity carries the Solana owner tag. The
/// caller passes the PDA it derived with [`escrow_authority`], so the program
/// never trusts a client value for the PDA binding of the `escrow_open`
/// circuit's `EscrowAuthorityOwnerHash` public input.
/// `nullifier_pubkey` is the value published in
/// `Pair::escrow_authority_nullifier_pubkey`: the maker derives the identity's
/// nullifier secret from its viewing key, so who can build spend proofs is
/// maker-chosen, while the order/reservation UTXOs stay bound to the
/// program-controlled PDA that only `settle` can sign for.
pub fn escrow_authority_owner_hash(
    escrow_authority: &Address,
    nullifier_pubkey: &[u8; 32],
) -> Result<[u8; 32], ProgramError> {
    let owner_pk_field =
        solana_owner_identity(escrow_authority.as_array()).map_err(DynamicSwapError::from)?;
    Poseidon::hashv(&[owner_pk_field.as_slice(), nullifier_pubkey.as_slice()])
        .map_err(|_| DynamicSwapError::HashingFailed.into())
}

/// Create the program-derived account `pda`. Handles both the hot path (the
/// account has no lamports) and the cold path (an attacker pre-funded the
/// address) via the pinocchio system helper; a raw `CreateAccount` would fail
/// on a donated balance and let an attacker DoS the creation.
pub struct CreatePdaAccount<'a, S> {
    pub fee_payer: &'a AccountView,
    pub new_account: &'a mut AccountView,
    pub space: usize,
    pub owner: &'a Address,
    pub pda: &'a PdaSigner<S>,
}

impl<S: PdaSeeds> CreatePdaAccount<'_, S> {
    #[inline(always)]
    pub fn execute(self) -> ProgramResult {
        let seeds = self.pda.signer_seeds();
        pinocchio_system::create_account_with_minimum_balance_signed(
            self.new_account,
            self.space,
            self.owner,
            self.fee_payer,
            None,
            &[Signer::from(seeds.as_ref())],
        )
    }
}

/// Derive the canonical PDA of `seeds` under this program and verify it
/// matches `account_key`.
pub fn verify_pda<S: PdaSeeds>(
    account_key: &Address,
    seeds: S,
) -> Result<PdaSigner<S>, ProgramError> {
    let pda = PdaSigner::find(seeds, &crate::ID);
    if !address_eq(account_key, pda.address()) {
        return Err(DynamicSwapError::InvalidPda.into());
    }
    Ok(pda)
}

/// Invokes transact through `spp_accounts`, signing for `escrow_authority`.
#[inline(never)]
#[profile]
pub fn cpi_spp_transact_signed(
    escrow_authority: &PdaSigner<[&[u8]; 2]>,
    spp_accounts: &[AccountView],
    transact_bytes: &[u8],
) -> ProgramResult {
    escrow_authority.invoke_transact::<16>(spp_accounts, transact_bytes)
}
