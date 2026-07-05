//! `create_proposal` (tag 11): queue an async withdrawal/transfer proposal PDA.

use pinocchio::{
    cpi::{Seed, Signer},
    AccountView, ProgramResult,
};
use zolana_squads_interface::{
    error::SquadsZoneError, instruction::instruction_data::CreateProposalIxData,
    state::proposal::Proposal, PROPOSAL_PDA_SEED,
};

use crate::instructions::viewing_key_account::loader::load_viewing_key_account;
use crate::shared::pda::verify_pda;
use crate::shared::proof::hash_field;

/// `create_proposal` (tag 11): queue an async withdrawal/transfer proposal PDA.
///
/// Accounts: `[fee_payer (signer, writable), proposal (writable, the PDA),
/// viewing_key_account (readonly), system_program (readonly), owner (signer)]`.
///
/// The proposal PDA is derived at `[b"proposal", owner, cipher_text[0..33]]`. The
/// program stamps `discriminator`, sets `owner` to the viewing key account's
/// owner and `rent_payer` to the fee payer, and copies the remaining fields from
/// the instruction data.
#[inline(never)]
pub fn process_create_proposal_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    if accounts.len() < 5 {
        return Err(SquadsZoneError::InvalidInstructionData.into());
    }
    let (fee_payer, rest) = accounts
        .split_first_mut()
        .ok_or(SquadsZoneError::InvalidInstructionData)?;
    let (proposal, rest) = rest
        .split_first_mut()
        .ok_or(SquadsZoneError::InvalidInstructionData)?;
    let (viewing_key_account, rest) = rest
        .split_first_mut()
        .ok_or(SquadsZoneError::InvalidInstructionData)?;
    // accounts[3] is the system program (read by the create CPI implicitly).
    let owner = rest.get(1).ok_or(SquadsZoneError::InvalidInstructionData)?;

    if !fee_payer.is_signer() {
        return Err(SquadsZoneError::MissingAuthoritySignature.into());
    }
    if !owner.is_signer() {
        return Err(SquadsZoneError::MissingOwnerSignature.into());
    }

    // Owner + discriminator are validated by the loader. The owner identity is the
    // pk-field-hash of the signer (`hash_field(pubkey)` == the SDK `owner_pk_field`),
    // so a Squads smart-account vault whose hashed pubkey equals the stored field can
    // sign as the proposal owner.
    let vka = load_viewing_key_account(viewing_key_account)?;
    let owner_field = hash_field(
        &owner.address().to_bytes(),
        SquadsZoneError::ProofHashingFailed,
    )?;
    if owner_field != vka.owner.to_bytes() {
        return Err(SquadsZoneError::OwnerMismatch.into());
    }

    let ix = CreateProposalIxData::deserialize(data)
        .map_err(|_| SquadsZoneError::InvalidInstructionData)?;

    // PDA seeds: `[b"proposal", owner, cipher_text[0..32]]`. The fresh ephemeral
    // public key lives in the ciphertext's first 33 bytes; its first 32 bytes
    // bind the PDA to this operation. (Solana caps each seed at 32 bytes, so the
    // spec's `[0..33]` is clamped to 32 -- still unique per proposal since the
    // ephemeral key is random.)
    let owner_addr = vka.owner;
    let cipher_seed = ix
        .cipher_text
        .get(..32)
        .ok_or(SquadsZoneError::InvalidInstructionData)?;

    let bump = verify_pda(
        proposal.address(),
        &[PROPOSAL_PDA_SEED, owner_addr.as_ref(), cipher_seed],
        &crate::ID,
    )?;

    // The Proposal PDA has three seeds; `CreatePdaAccount` only supports N=1/2, so
    // create the account inline with the explicit seed array (mirrors
    // `update_viewing_key_account`).
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
    .map_err(|_| SquadsZoneError::InvalidProposal)?;

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

/// Serialize `record` and overwrite the proposal account data in place. The
/// create path allocates the account to exactly `Proposal::SIZE`, so the write
/// always covers the full serialized form (mirrors
/// `zone_config::create::write_zone_config`).
#[inline(never)]
fn write_proposal(account: &mut AccountView, record: &Proposal) -> ProgramResult {
    let bytes = record
        .serialize()
        .map_err(|_| SquadsZoneError::Deserialization)?;
    let mut data = account
        .try_borrow_mut()
        .map_err(|_| SquadsZoneError::InvalidProposal)?;
    let slot = data
        .get_mut(..bytes.len())
        .ok_or(SquadsZoneError::InvalidAccountSize)?;
    slot.copy_from_slice(&bytes);
    Ok(())
}
