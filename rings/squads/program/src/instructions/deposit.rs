//! `deposit` (tag 1): public deposit into a new ring UTXO owned by the
//! recipient viewing key account, settled through SPP `ring_deposit`.

use pinocchio::{AccountView, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_squads_interface::{
    error::SquadsRingError, instruction::instruction_data::DepositIxData,
};

use crate::instructions::viewing_key_account::loader::load_viewing_key_account;
use crate::shared::{
    cpi::forward_to_spp,
    proof::poseidon2,
    spp_deposit::{build_spp_ring_deposit_data, SppRingDepositParams},
};

/// SPP `ring_deposit` account list position of the depositor.
const SPP_DEPOSITOR_INDEX: usize = 1;

/// `deposit` (tag 1).
///
/// Accounts: `[recipient_viewing_key_account (readonly), ..spp_accounts]`, where
/// `spp_accounts` is the SPP `ring_deposit` account list for `data.asset`:
/// `[tree, depositor (signer), ring_auth, spp_program, ..settlement group]`.
///
/// The output owner is the recipient account's owner, so the ring computes the
/// `owner_utxo_hash` itself from the account and the public `blinding`.
#[inline(never)]
pub fn process_deposit_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let ix =
        DepositIxData::deserialize(data).map_err(|_| SquadsRingError::InvalidInstructionData)?;

    let mut iter = AccountIterator::new(accounts);
    let recipient_vka = iter.next_account("recipient_viewing_key_account")?;
    let spp_accounts = iter.remaining_unchecked()?;

    let depositor = spp_accounts
        .get(SPP_DEPOSITOR_INDEX)
        .ok_or(SquadsRingError::InvalidDepositAccounts)?;
    if !depositor.is_signer() {
        return Err(SquadsRingError::MissingAuthoritySignature.into());
    }

    let vka = load_viewing_key_account(recipient_vka)?;
    let owner_hash = poseidon2(
        &vka.owner.to_bytes(),
        &vka.nullifier_pubkey,
        SquadsRingError::ProofHashingFailed,
    )?;

    let spp_data = build_spp_ring_deposit_data(SppRingDepositParams {
        view_tag: ix.view_tag,
        owner_hash,
        blinding: ix.blinding,
        amount: ix.amount,
        asset: ix.asset,
    })?;
    forward_to_spp(spp_accounts, &spp_data)
}
