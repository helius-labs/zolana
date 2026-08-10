//! `fold_transact` (tag 17): several transfer legs of one account settled in
//! one transaction under a single zone fold proof.
//!
//! The zone circuit has a key for `(1,1)` and `(2,2)` only, so a spend of three
//! UTXOs does not fit one leg. A fold proves every leg spends the same account
//! and pays the same recipient, so the run is one operation. Each leg still
//! settles through its own SPP `ring_transact`.

use pinocchio::{
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};
use zolana_squads_interface::{
    constants::VIEWING_KEY_STATE_ACTIVE, error::SquadsZoneError,
    instruction::instruction_data::FoldTransactIxData, state::viewing_key_account::OwnerKind,
    RING_AUTH_PDA_SEED,
};

use crate::instructions::transact::account::TransactAccounts;
use crate::instructions::viewing_key_account::loader::load_viewing_key_account;
use crate::instructions::zone_config::loader::load_zone_config;
use crate::shared::{
    cpi::spp_transact,
    owner::verify_owner_identity,
    pda::verify_pda,
    shapes::{operation_shape, ZONE_FOLD_SUPPORTED_LEGS, ZONE_FOLD_SUPPORTED_SHAPES},
    spp_transact::{build_spp_zone_transfer_data, SppSettlementRail, SppZoneTransferParams},
    zone_proof::{ZoneFoldLeg, ZoneFoldProof},
};

/// The only leg shape a fold covers. A withdrawal already spends the whole
/// balance, so only the transfer shape has a fold key.
const FOLD_LEG_SHAPE: (u8, u8) = ZONE_FOLD_SUPPORTED_SHAPES[0];

/// Accounts: `[payer (signer, writable), co_signer (signer), zone_config
/// (readonly), sender_vka (readonly), recipient_vka (readonly), ring_auth,
/// spp_program, tree]`.
///
/// The account list is the `transact` transfer list unchanged. Every leg spends
/// the same sender and pays the same recipient, and SPP holds one tree, so a
/// leg needs no accounts of its own.
#[inline(never)]
pub fn process_fold_transact_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let ix = FoldTransactIxData::deserialize(data)
        .map_err(|_| SquadsZoneError::InvalidInstructionData)?;

    let legs = u8::try_from(ix.legs.len()).map_err(|_| SquadsZoneError::InvalidInstructionData)?;
    if !ZONE_FOLD_SUPPORTED_LEGS.contains(&legs) {
        return Err(SquadsZoneError::InvalidInstructionData.into());
    }

    let accs = TransactAccounts::validate_and_parse(accounts, true)?;

    if !accs.payer.is_signer() {
        return Err(SquadsZoneError::MissingAuthoritySignature.into());
    }
    if !accs.co_signer.is_signer() {
        return Err(SquadsZoneError::MissingCoSignerSignature.into());
    }

    let zone_config = load_zone_config(accs.zone_config)?;
    if accs.co_signer.address() != &zone_config.co_signer {
        return Err(SquadsZoneError::CoSignerMismatch.into());
    }

    let sender_vka = load_viewing_key_account(accs.sender_vka)?;
    if sender_vka.state != VIEWING_KEY_STATE_ACTIVE {
        return Err(SquadsZoneError::ViewingKeyAccountBlocked.into());
    }
    // Folded transfers settle over the same signatureless smart-account rail as
    // `transact`. Require the vault itself to be the signed payer so a relayer
    // holding auditor-recovered proof secrets cannot bypass threshold approval.
    let owner_kind = sender_vka.kind()?;
    if owner_kind == OwnerKind::SmartAccount {
        verify_owner_identity(accs.payer, sender_vka.owner.to_bytes())?;
    }
    let recipient_account = accs
        .recipient_vka
        .ok_or(SquadsZoneError::InvalidInstructionData)?;
    let recipient_vka = load_viewing_key_account(recipient_account)?;
    if recipient_vka.state != VIEWING_KEY_STATE_ACTIVE {
        return Err(SquadsZoneError::ViewingKeyAccountBlocked.into());
    }

    let now = Clock::get()?.unix_timestamp;
    if now > ix.expiry {
        return Err(SquadsZoneError::TransactionExpired.into());
    }

    let ring_auth_bump = verify_pda(accs.ring_auth.address(), &[RING_AUTH_PDA_SEED], &crate::ID)?;

    // Every leg is a transfer, so it carries exactly one recipient ciphertext.
    let mut fold_legs = Vec::with_capacity(ix.legs.len());
    for leg in &ix.legs {
        // The fold key proves one leg shape. A leg whose forwarded vectors name
        // a different SPP circuit would settle a spend the fold never proved.
        if operation_shape(true, leg.input_contexts.len(), leg.output_utxo_hashes.len())?
            != FOLD_LEG_SHAPE
        {
            return Err(SquadsZoneError::ProofShapeMismatch.into());
        }
        let [recipient_ciphertext] = leg.encrypted_utxos.recipient_ciphertexts.as_slice() else {
            return Err(SquadsZoneError::InvalidInstructionData.into());
        };
        fold_legs.push(ZoneFoldLeg {
            private_tx_hash: leg.private_tx_hash,
            sender_ciphertext: leg.encrypted_utxos.sender_ciphertext.as_slice(),
            tx_viewing_pk: &leg.encrypted_utxos.tx_viewing_pk,
            recipient_ciphertext: recipient_ciphertext.as_slice(),
        });
    }

    ZoneFoldProof {
        sender_owner: sender_vka.owner.to_bytes(),
        sender_commitment: sender_vka.shared_viewing_key_commitment,
        sender_nullifier_pubkey: sender_vka.nullifier_pubkey,
        recipient_owner: recipient_vka.owner.to_bytes(),
        recipient_viewing_pk: &recipient_vka.shared_viewing_key,
        recipient_nullifier_pubkey: recipient_vka.nullifier_pubkey,
        legs: &fold_legs,
        proof: &ix.zone_fold_proof,
        n_inputs: FOLD_LEG_SHAPE.0,
        n_outputs: FOLD_LEG_SHAPE.1,
    }
    .verify()?;

    // The fold chains the legs in order, so the per-leg SPP CPIs must run in
    // that same order.
    let expiry_unix_ts =
        u64::try_from(ix.expiry).map_err(|_| SquadsZoneError::InvalidInstructionData)?;
    let rail = SppSettlementRail::for_owner_kind(owner_kind);
    let cpi_accounts: [&AccountView; 4] = [accs.payer, accs.tree, accs.ring_auth, accs.spp_program];
    for leg in &ix.legs {
        let spp_data = build_spp_zone_transfer_data(SppZoneTransferParams {
            expiry_unix_ts,
            private_tx_hash: leg.private_tx_hash,
            spp_proof: &leg.spp_proof,
            salt: leg.salt,
            output_view_tags: &leg.output_view_tags,
            output_utxo_hashes: &leg.output_utxo_hashes,
            input_contexts: &leg.input_contexts,
            encrypted_utxos: &leg.encrypted_utxos,
            rail,
        })?;
        spp_transact(accs.spp_program, &cpi_accounts, &spp_data, ring_auth_bump)?;
    }
    Ok(())
}
