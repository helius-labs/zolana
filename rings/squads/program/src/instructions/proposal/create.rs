//! `create_proposal` (tag 11): queue an async withdrawal/transfer proposal PDA.

use pinocchio::{
    cpi::{Seed, Signer},
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};
use zolana_squads_interface::{
    error::SquadsRingError,
    instruction::instruction_data::CreateProposalIxData,
    state::{proposal::Proposal, viewing_key_account::OwnerKind},
    PROPOSAL_PDA_SEED, RING_CONFIG_PDA_SEED,
};

use crate::instructions::{
    ring_config::loader::load_ring_config, viewing_key_account::loader::load_viewing_key_account,
};
use crate::shared::{owner::verify_owner_identity, pda::verify_pda};

/// Accounts: `[fee_payer (signer, writable, same address as owner), proposal (writable, the PDA),
/// viewing_key_account (readonly), ring_config (readonly), system_program
/// (readonly), owner (signer)]`.
///
/// The proposal PDA is derived at `[b"proposal", owner, cipher_text[0..32]]`.
/// The program stamps `discriminator`, sets `owner` to the viewing key
/// account's owner and `rent_payer` to the authenticated raw owner/vault, and
/// copies the remaining fields from the instruction data.
#[inline(never)]
pub fn process_create_proposal_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let [fee_payer, proposal, viewing_key_account, ring_config, system_program, owner] = accounts
    else {
        return Err(SquadsRingError::InvalidInstructionData.into());
    };

    if !fee_payer.is_signer() {
        return Err(SquadsRingError::MissingAuthoritySignature.into());
    }
    if !owner.is_signer() {
        return Err(SquadsRingError::MissingOwnerSignature.into());
    }
    // The crank treats the recorded rent payer as the raw sender vault. Binding
    // it to the authenticated owner prevents an unrelated payer from creating a
    // proposal that can be decrypted but can never be settled.
    if fee_payer.address() != owner.address() {
        return Err(SquadsRingError::ProposalPayerMismatch.into());
    }
    if !pinocchio_system::check_id(system_program.address()) {
        return Err(SquadsRingError::InvalidInstructionData.into());
    }

    // The owner identity is the pk-field-hash of the signer
    // (`hash_field(pubkey)` == the SDK `owner_pk_field`), so a Squads
    // smart-account vault whose hashed pubkey equals the stored field can sign
    // as the proposal owner.
    let vka = load_viewing_key_account(viewing_key_account)?;
    if vka.kind()? != OwnerKind::SmartAccount {
        return Err(SquadsRingError::InvalidOwnerKind.into());
    }
    verify_owner_identity(owner, vka.owner.to_bytes())?;

    verify_pda(ring_config.address(), &[RING_CONFIG_PDA_SEED], &crate::ID)?;
    let ring = load_ring_config(ring_config)?;

    let ix = CreateProposalIxData::deserialize(data)
        .map_err(|_| SquadsRingError::InvalidInstructionData)?;
    let now = Clock::get()?.unix_timestamp;
    validate_proposal_expiry(now, ring.max_proposal_lifetime, ix.expiry)?;

    // The fresh ephemeral public key lives in the ciphertext's first 33 bytes.
    // Solana caps each seed at 32 bytes, so the spec's `[0..33]` is clamped to
    // `[0..32]`. The PDA stays unique per proposal because the ephemeral key
    // is random.
    let owner_addr = vka.owner;
    let cipher_seed = ix
        .cipher_text
        .get(..32)
        .ok_or(SquadsRingError::InvalidInstructionData)?;

    let bump = verify_pda(
        proposal.address(),
        &[PROPOSAL_PDA_SEED, owner_addr.as_ref(), cipher_seed],
        &crate::ID,
    )?;

    let bump_seed = [bump];
    let signer_seeds = [
        Seed::from(PROPOSAL_PDA_SEED),
        Seed::from(owner_addr.as_ref()),
        Seed::from(cipher_seed),
        Seed::from(bump_seed.as_ref()),
    ];
    pinocchio_system::create_account_with_minimum_balance_signed(
        &mut *proposal,
        Proposal::SIZE,
        &crate::ID,
        fee_payer,
        None,
        &[Signer::from(signer_seeds.as_ref())],
    )
    .map_err(|_| SquadsRingError::InvalidProposal)?;

    let record = Proposal::new(
        owner_addr,
        ix.recipient,
        ix.asset,
        ix.proposal_hash,
        ix.cipher_text,
        ix.expiry,
        *fee_payer.address(),
    );
    write_proposal(proposal, &record)
}

fn validate_proposal_expiry(now: i64, max_lifetime: i64, expiry: i64) -> ProgramResult {
    if now > expiry {
        return Err(SquadsRingError::ProposalExpired.into());
    }
    let latest_expiry = now
        .checked_add(max_lifetime)
        .ok_or(SquadsRingError::ArithmeticOverflow)?;
    if expiry > latest_expiry {
        return Err(SquadsRingError::ProposalLifetimeExceeded.into());
    }
    Ok(())
}

/// The create path allocates the account to exactly `Proposal::SIZE`, so the
/// write covers the full serialized form.
#[inline(never)]
fn write_proposal(account: &mut AccountView, record: &Proposal) -> ProgramResult {
    let bytes = record
        .serialize()
        .map_err(|_| SquadsRingError::Serialization)?;
    let mut data = account
        .try_borrow_mut()
        .map_err(|_| SquadsRingError::InvalidProposal)?;
    let slot = data
        .get_mut(..bytes.len())
        .ok_or(SquadsRingError::InvalidAccountSize)?;
    slot.copy_from_slice(&bytes);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pinocchio::error::ProgramError;

    #[test]
    fn expiry_must_fit_configured_window() {
        assert!(validate_proposal_expiry(1_000, 300, 1_300).is_ok());
        assert_eq!(
            validate_proposal_expiry(1_000, 300, 999).unwrap_err(),
            ProgramError::Custom(SquadsRingError::ProposalExpired as u32)
        );
        assert_eq!(
            validate_proposal_expiry(1_000, 300, 1_301).unwrap_err(),
            ProgramError::Custom(SquadsRingError::ProposalLifetimeExceeded as u32)
        );
    }

    #[test]
    fn expiry_window_addition_is_checked() {
        assert_eq!(
            validate_proposal_expiry(i64::MAX, 1, i64::MAX).unwrap_err(),
            ProgramError::Custom(SquadsRingError::ArithmeticOverflow as u32)
        );
    }
}
