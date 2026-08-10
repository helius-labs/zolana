//! `merge_transact` (tag 2): a whitelisted merge authority consolidates one
//! owner's UTXOs into a single UTXO of the same owner and total value, settled
//! through the SPP.

use pinocchio::{AccountView, ProgramResult};
use zolana_squads_interface::{
    error::SquadsRingError, instruction::instruction_data::MergeTransactIxData, RING_AUTH_PDA_SEED,
};

use crate::instructions::ring_config::loader::load_ring_config;
use crate::instructions::viewing_key_account::loader::load_viewing_key_account;
use crate::shared::{
    cpi::spp_merge_transact,
    pda::verify_pda,
    spp_merge::{build_spp_ring_merge_data, SppRingMergeParams},
};

/// Accounts: `[merge_authority (signer, writable, fee payer), ring_config
/// (read), owner_viewing_key_account (read), ring_auth, spp_program,
/// ..tree_accounts (writable)]`.
///
/// The signer must be one of `ring_config.merge_authorities`. The merge proof is
/// not verified here because the squads interface does not carry the merge
/// verifying key. The SPP verifies the forwarded `spp_proof` (the merge circuit
/// proof, which also covers the verifiable encryption) during the settlement
/// CPI.
#[inline(never)]
pub fn process_merge_transact_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    if accounts.len() < 6 {
        return Err(SquadsRingError::InvalidInstructionData.into());
    }
    let merge_authority = accounts
        .first()
        .ok_or(SquadsRingError::InvalidInstructionData)?;
    let ring_config = accounts
        .get(1)
        .ok_or(SquadsRingError::InvalidInstructionData)?;
    let owner_viewing_key_account = accounts
        .get(2)
        .ok_or(SquadsRingError::InvalidInstructionData)?;
    let ring_auth = accounts
        .get(3)
        .ok_or(SquadsRingError::InvalidInstructionData)?;
    let spp_program = accounts
        .get(4)
        .ok_or(SquadsRingError::InvalidInstructionData)?;

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

    let owner_vka = load_viewing_key_account(owner_viewing_key_account)?;

    let ix =
        MergeTransactIxData::deserialize(data).map_err(|_| SquadsRingError::Deserialization)?;

    // The output UTXO hash is opaque to the ring, so the account is bound
    // through the index tag instead. A merge authority that supplies one
    // owner's account cannot index the consolidated output under another's
    // viewing key. Which UTXOs are consumed and who owns the output stay the
    // merge proof's job.
    if ix.output_ring_data_hash != owner_vka.view_tag() {
        return Err(SquadsRingError::MergeOutputTagMismatch.into());
    }

    let ring_auth_bump = verify_pda(ring_auth.address(), &[RING_AUTH_PDA_SEED], &crate::ID)?;

    // In SPP's `merge_ring` order `ring_auth` acts as SPP's ring config signer
    // and `merge_authority` forwards as SPP's payer and second signer. SPP's
    // `merge_ring` reads no `protocol_config` or `user_record`. Only one tree
    // is ever touched.
    let tree_accounts = accounts
        .get(5..)
        .ok_or(SquadsRingError::InvalidInstructionData)?;
    let tree = tree_accounts
        .first()
        .ok_or(SquadsRingError::InvalidInstructionData)?;
    let spp_data = build_spp_ring_merge_data(SppRingMergeParams {
        expiry_unix_ts: ix.expiry_unix_ts,
        output_ring_data_hash: ix.output_ring_data_hash,
        private_tx_hash: ix.private_tx_hash,
        output_utxo_hash: ix.output_utxo_hash,
        spp_proof: &ix.spp_proof,
        input_contexts: &ix.input_contexts,
    })?;
    let cpi_accounts: [&AccountView; 4] = [tree, ring_auth, merge_authority, spp_program];
    spp_merge_transact(spp_program, &cpi_accounts, &spp_data, ring_auth_bump)?;

    Ok(())
}
