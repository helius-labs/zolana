//! `merge_transact` (tag 2): a whitelisted merge authority consolidates one
//! owner's ring UTXOs through SPP `merge_ring`.

use pinocchio::{AccountView, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_interface::instruction::tag::RING_MERGE_TRANSACT;
use zolana_squads_interface::{
    error::SquadsRingError, instruction::instruction_data::MergeTransactIxData,
};

use crate::instructions::ring_config::loader::load_ring_config;
use crate::instructions::viewing_key_account::loader::load_viewing_key_account;
use crate::shared::cpi::forward_to_spp;

/// `merge_transact` (tag 2).
///
/// Accounts: `[merge_authority (signer), ring_config (readonly),
/// owner_viewing_key_account (readonly), ..spp_accounts]`, where `spp_accounts`
/// is the SPP `merge_ring` account list (its payer is the merge authority).
///
/// The ring only authorizes the caller; the SPP merge proof binds the inputs,
/// the owner and the output. Squads UTXOs carry no ring data, so the merged
/// output must not either.
#[inline(never)]
pub fn process_merge_transact_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let mut iter = AccountIterator::new(accounts);
    let merge_authority = iter.next_account("merge_authority")?;
    let ring_config = iter.next_account("ring_config")?;
    let owner_viewing_key_account = iter.next_account("owner_viewing_key_account")?;
    let spp_accounts = iter.remaining_unchecked()?;

    if !merge_authority.is_signer() {
        return Err(SquadsRingError::MissingMergeAuthoritySignature.into());
    }

    let config = load_ring_config(ring_config)?;
    if !config
        .merge_authorities
        .iter()
        .any(|authority| authority == merge_authority.address())
    {
        return Err(SquadsRingError::MergeAuthorityNotWhitelisted.into());
    }

    load_viewing_key_account(owner_viewing_key_account)?;

    let ix =
        MergeTransactIxData::deserialize(data).map_err(|_| SquadsRingError::Deserialization)?;
    if ix.spp.output_ring_data_hash != [0u8; 32] {
        return Err(SquadsRingError::InvalidInstructionData.into());
    }

    let mut instruction_data = Vec::with_capacity(1 + data.len());
    instruction_data.push(RING_MERGE_TRANSACT);
    instruction_data.extend_from_slice(data);
    forward_to_spp(spp_accounts, &instruction_data)
}
