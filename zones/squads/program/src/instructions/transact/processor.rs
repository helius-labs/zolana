//! `transact` (tag 0): zone-proof-gated synchronous transfer/withdrawal settled
//! through the SPP in the same transaction.

use pinocchio::{
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};
use zolana_squads_interface::{
    constants::VIEWING_KEY_STATE_ACTIVE, error::SquadsZoneError,
    instruction::instruction_data::TransactIxData, ZONE_AUTH_PDA_SEED,
};

use super::account::TransactAccounts;
use crate::instructions::viewing_key_account::loader::load_viewing_key_account;
use crate::instructions::zone_config::loader::load_zone_config;
use crate::shared::{
    cpi::spp_transact,
    pda::verify_pda,
    spp_transact::{
        build_spp_zone_transfer_data, build_spp_zone_withdrawal_data, SppSettlementRail,
        SppZoneTransferParams, SppZoneWithdrawalParams,
    },
    withdrawal::{forward_zone_withdrawal, withdrawal_is_spl},
    zone_proof::{zone_recipient, ZoneProof},
};

/// `transact` (tag 0): zone-proof-gated synchronous transfer/withdrawal settled
/// through the SPP.
///
/// Accounts: `[payer (signer, writable), co_signer (signer), zone_config
/// (readonly), sender_vka (readonly), recipient_vka (readonly, transfer only),
/// zone_auth, spp_program, ..tree_accounts]`.
///
/// `public_amount` selects the operation: `Some` is a `(1, 1)` withdrawal (the
/// single output is the sender's change, no `recipient_vka`); `None` is a
/// `(2, 2)` transfer (sender change plus one recipient output, with a
/// `recipient_vka`). The zone proof is verified here, then the settlement is
/// forwarded to the SPP via the zone-auth-signed CPI.
#[inline(never)]
pub fn process_transact_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let ix =
        TransactIxData::deserialize(data).map_err(|_| SquadsZoneError::InvalidInstructionData)?;

    // A withdrawal carries `public_amount` and no recipient viewing key account;
    // a transfer carries a recipient viewing key account and no public amount.
    let is_transfer = ix.public_amount.is_none();

    // Parse the accounts; the recipient slot is consumed only for a transfer, and
    // the settlement tail is present only for a withdrawal.
    let accs = TransactAccounts::validate_and_parse(accounts, is_transfer)?;

    // Signer checks live in the processor (not nested in helpers).
    if !accs.payer.is_signer() {
        return Err(SquadsZoneError::MissingAuthoritySignature.into());
    }
    if !accs.co_signer.is_signer() {
        return Err(SquadsZoneError::MissingCoSignerSignature.into());
    }

    // Co-signer must be the configured zone co-signer.
    let zone_config = load_zone_config(accs.zone_config)?;
    if accs.co_signer.address() != &zone_config.co_signer {
        return Err(SquadsZoneError::CoSignerMismatch.into());
    }

    // Sender viewing key account must be active (a blocked account may only exit
    // via full_withdrawal).
    let sender_vka = load_viewing_key_account(accs.sender_vka)?;
    if sender_vka.state != VIEWING_KEY_STATE_ACTIVE {
        return Err(SquadsZoneError::ViewingKeyAccountBlocked.into());
    }

    // For a transfer, the recipient viewing key account must also be active.
    let recipient_vka = match accs.recipient_vka {
        Some(recipient_vka_account) => {
            let recipient_vka = load_viewing_key_account(recipient_vka_account)?;
            if recipient_vka.state != VIEWING_KEY_STATE_ACTIVE {
                return Err(SquadsZoneError::ViewingKeyAccountBlocked.into());
            }
            Some(recipient_vka)
        }
        None => None,
    };

    // Reject an expired transaction against the cluster clock.
    let now = Clock::get()?.unix_timestamp;
    if now > ix.expiry {
        return Err(SquadsZoneError::TransactionExpired.into());
    }

    // The zone-auth PDA both authorizes the SPP CPI and is verified here; the
    // returned canonical bump is the CPI signer's bump.
    let zone_auth_bump = verify_pda(accs.zone_auth.address(), &[ZONE_AUTH_PDA_SEED], &crate::ID)?;

    // Public amount as a 32-byte big-endian field element; 0 for a transfer.
    // PROVISIONAL(M5): transact zone-proof input mapping / shape selection
    // pending SDK e2e validation.
    let mut public_amount = [0u8; 32];
    if let Some(amount) = ix.public_amount {
        let amount_bytes = amount.to_be_bytes();
        let dst = public_amount
            .get_mut(24..32)
            .ok_or(SquadsZoneError::InvalidInstructionData)?;
        dst.copy_from_slice(&amount_bytes);
    }

    // The zone circuit hashes the sender and each recipient ciphertext
    // separately, so they are read as typed `EncryptedUtxos` fields (parsed
    // inline with the rest of the instruction data). The recipient half is built
    // (and shape-validated against the ciphertext count) only for a transfer.
    let encrypted_utxos = &ix.encrypted_utxos;
    let sender_ciphertext = encrypted_utxos.sender_ciphertext.as_slice();
    let recipient = zone_recipient(encrypted_utxos, recipient_vka.as_ref())?;

    // (1, 1) withdrawal vs (2, 2) transfer; `proposal_hash` is 0 for sync
    // `transact` (the owner's signature over `private_tx_hash` already covers the
    // outputs; spec Zone Proof table). NOTE: the shape is selected from the
    // operation here, while `execute_proposal` derives it from the instruction-
    // data vector lengths; `select_zone_vk` rejects any unsupported shape either
    // way. Keep these in mind if the supported shape set grows.
    let (n_inputs, n_outputs) = if is_transfer { (2u8, 2u8) } else { (1u8, 1u8) };

    ZoneProof {
        private_tx_hash: ix.private_tx_hash,
        public_amount,
        sender_owner: sender_vka.owner.to_bytes(),
        sender_commitment: sender_vka.shared_viewing_key_commitment,
        sender_nullifier_pubkey: sender_vka.nullifier_pubkey,
        sender_ciphertext,
        recipient,
        proposal_hash: [0u8; 32],
        proof: &ix.zone_proof,
        n_inputs,
        n_outputs,
    }
    .verify()?;

    // Settle via the SPP CPI, signed by the zone-auth PDA. The forwarded accounts
    // are assembled in SPP's `zone_transact` order (payer, tree, zone_config ==
    // zone_auth) -- NOT the zone's own account order. The zone-only accounts
    // (co_signer, zone_config, the viewing key accounts) are not SPP accounts and
    // are not forwarded. Only one tree is ever touched (SPP currently supports
    // exactly one tree for the whole protocol).
    let expiry_unix_ts =
        u64::try_from(ix.expiry).map_err(|_| SquadsZoneError::InvalidInstructionData)?;
    // A smart-account sender settles signatureless via the zone-authority rail; a
    // keypair/P256 sender uses the P256 rail.
    let rail = SppSettlementRail::for_owner_kind(sender_vka.owner_kind);
    if is_transfer {
        let spp_data = build_spp_zone_transfer_data(SppZoneTransferParams {
            expiry_unix_ts,
            private_tx_hash: ix.private_tx_hash,
            spp_proof: &ix.spp_proof,
            salt: ix.salt,
            output_view_tags: &ix.output_view_tags,
            output_utxo_hashes: &ix.output_utxo_hashes,
            input_contexts: &ix.input_contexts,
            encrypted_utxos: &ix.encrypted_utxos,
            rail,
        })?;
        let cpi_accounts: [&AccountView; 4] =
            [accs.payer, accs.tree, accs.zone_auth, accs.spp_program];
        return spp_transact(accs.spp_program, &cpi_accounts, &spp_data, zone_auth_bump);
    }

    // Withdrawal: the rail is fixed by the settlement account count; the amount
    // is negated into SPP's signed public-amount field by the data builder.
    let is_spl = withdrawal_is_spl(accs.settlement)?;
    let amount = ix
        .public_amount
        .ok_or(SquadsZoneError::InvalidInstructionData)?;
    let spp_data = build_spp_zone_withdrawal_data(SppZoneWithdrawalParams {
        expiry_unix_ts,
        private_tx_hash: ix.private_tx_hash,
        spp_proof: &ix.spp_proof,
        salt: ix.salt,
        output_view_tags: &ix.output_view_tags,
        output_utxo_hashes: &ix.output_utxo_hashes,
        input_contexts: &ix.input_contexts,
        encrypted_utxos: &ix.encrypted_utxos,
        amount,
        is_spl,
        rail,
    })?;
    forward_zone_withdrawal(
        accs.spp_program,
        accs.payer,
        accs.tree,
        accs.zone_auth,
        accs.settlement,
        &spp_data,
        zone_auth_bump,
    )
}
