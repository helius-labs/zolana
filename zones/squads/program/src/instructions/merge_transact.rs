//! `merge_transact` (tag 2): a whitelisted merge authority consolidates one
//! owner's UTXOs into a single UTXO of the same owner and total value, settled
//! through the SPP.

use pinocchio::{AccountView, ProgramResult};
use zolana_squads_interface::{
    error::SquadsZoneError, instruction::instruction_data::MergeTransactIxData, ZONE_AUTH_PDA_SEED,
};

use crate::instructions::viewing_key_account::loader::load_viewing_key_account;
use crate::instructions::zone_config::loader::load_zone_config;
use crate::shared::{
    cpi::spp_merge_transact,
    pda::verify_pda,
    spp_merge::{build_spp_zone_merge_data, SppZoneMergeParams},
};

/// `merge_transact` (tag 2): a whitelisted merge authority consolidates one
/// owner's UTXOs into a single UTXO of the same owner and total value, settled
/// through the SPP.
///
/// Accounts: `[merge_authority (signer, writable, fee payer), zone_config
/// (read), owner_viewing_key_account (read), zone_auth, spp_program,
/// ..tree_accounts (writable)]`.
///
/// Access control is the only zone-side gate: the signer must be one of
/// `zone_config.merge_authorities`. The merge proof is NOT verified here -- the
/// squads interface does not carry the merge verifying key -- so the forwarded
/// `spp_proof` (the merge circuit proof, which also covers the verifiable
/// encryption) is verified by the SPP during the settlement CPI.
#[inline(never)]
pub fn process_merge_transact_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    // merge_authority, zone_config, owner_viewing_key_account, zone_auth,
    // spp_program, then >=1 tree account.
    if accounts.len() < 6 {
        return Err(SquadsZoneError::InvalidInstructionData.into());
    }
    let merge_authority = accounts
        .first()
        .ok_or(SquadsZoneError::InvalidInstructionData)?;
    let zone_config = accounts
        .get(1)
        .ok_or(SquadsZoneError::InvalidInstructionData)?;
    let owner_viewing_key_account = accounts
        .get(2)
        .ok_or(SquadsZoneError::InvalidInstructionData)?;
    let zone_auth = accounts
        .get(3)
        .ok_or(SquadsZoneError::InvalidInstructionData)?;
    let spp_program = accounts
        .get(4)
        .ok_or(SquadsZoneError::InvalidInstructionData)?;

    if !merge_authority.is_signer() {
        return Err(SquadsZoneError::MissingMergeAuthoritySignature.into());
    }

    // Owner + discriminator are validated by the loader.
    let config = load_zone_config(zone_config)?;
    if !config
        .merge_authorities
        .iter()
        .any(|authority| authority == merge_authority.address())
    {
        return Err(SquadsZoneError::MergeAuthorityNotWhitelisted.into());
    }

    // The owner whose UTXOs are merged; loaded to validate ownership +
    // discriminator. The merge proof binds the consolidated output to this
    // owner's shared viewing key, so the zone does not parse the ciphertext.
    load_viewing_key_account(owner_viewing_key_account)?;

    // Parse to validate the instruction-data shape and forward it. No proof is
    // verified here: the merge verifying key lives in the SPP, not the zone.
    let ix =
        MergeTransactIxData::deserialize(data).map_err(|_| SquadsZoneError::Deserialization)?;

    // Derive the canonical zone-auth bump for the SPP CPI signer.
    let zone_auth_bump = verify_pda(zone_auth.address(), &[ZONE_AUTH_PDA_SEED], &crate::ID)?;

    // Forward to SPP's `merge_zone` in its own account order: tree,
    // zone_config (== zone_auth, signer), payer. SPP's `merge_zone` reads no
    // `protocol_config`/`user_record`: the zone identifies the owner through
    // its own viewing key account + merge proof instead, and `merge_authority`
    // (already a real transaction-level signer) forwards straight through as
    // SPP's second signer. Only one tree is ever touched.
    let tree_accounts = accounts
        .get(5..)
        .ok_or(SquadsZoneError::InvalidInstructionData)?;
    let tree = tree_accounts
        .first()
        .ok_or(SquadsZoneError::InvalidInstructionData)?;
    let spp_data = build_spp_zone_merge_data(SppZoneMergeParams {
        expiry_unix_ts: ix.expiry_unix_ts,
        merge_view_tag: ix.merge_view_tag,
        private_tx_hash: ix.private_tx_hash,
        output_utxo_hash: ix.output_utxo_hash,
        spp_proof: &ix.spp_proof,
        input_contexts: &ix.input_contexts,
        encrypted_utxo: &ix.encrypted_utxo,
    })?;
    let cpi_accounts: [&AccountView; 4] = [tree, zone_auth, merge_authority, spp_program];
    spp_merge_transact(spp_program, &cpi_accounts, &spp_data, zone_auth_bump)?;

    Ok(())
}
