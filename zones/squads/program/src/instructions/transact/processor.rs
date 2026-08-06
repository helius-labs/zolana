use pinocchio::{
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};
use zolana_squads_interface::{
    constants::VIEWING_KEY_STATE_ACTIVE, error::SquadsZoneError,
    instruction::instruction_data::TransactIxData, state::viewing_key_account::OwnerKind,
    RING_AUTH_PDA_SEED,
};

use super::account::TransactAccounts;
use crate::instructions::viewing_key_account::loader::load_viewing_key_account;
use crate::instructions::zone_config::loader::load_zone_config;
use crate::shared::{
    cpi::spp_transact,
    owner::verify_owner_identity,
    pda::verify_pda,
    shapes::operation_shape,
    spp_transact::{
        build_spp_zone_transfer_data, build_spp_zone_withdrawal_data, SppSettlementRail,
        SppZoneTransferParams, SppZoneWithdrawalParams,
    },
    withdrawal::{forward_zone_withdrawal, withdrawal_settlement},
    zone_proof::{public_amount_fe, zone_recipient, ZoneProof},
};

/// `transact` (tag 0): zone-proof-gated synchronous transfer/withdrawal settled
/// through the SPP.
///
/// Accounts: `[payer (signer, writable), co_signer (signer), zone_config
/// (readonly), sender_vka (readonly), recipient_vka (readonly, transfer only),
/// ring_auth, spp_program, ..tree_accounts]`.
/// For a smart-account sender, `payer` must be the sender vault, invoked with
/// signer privilege by the smart-account program after threshold approval. For
/// a P256 sender, the payer may be the relayer because the owner authorization is
/// carried by the SPP proof.
///
/// `public_amount` selects the operation. `Some` is a `(1, 1)` withdrawal (the
/// single output is the sender's change, no `recipient_vka`). `None` is a
/// `(2, 2)` transfer (sender change plus one recipient output, with a
/// `recipient_vka`). The zone proof is verified here, then the settlement is
/// forwarded to the SPP via the zone-auth-signed CPI.
#[inline(never)]
pub fn process_transact_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let ix =
        TransactIxData::deserialize(data).map_err(|_| SquadsZoneError::InvalidInstructionData)?;

    let is_transfer = ix.public_amount.is_none();

    let accs = TransactAccounts::validate_and_parse(accounts, is_transfer)?;

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

    // A blocked account may only exit via `full_withdrawal`.
    let sender_vka = load_viewing_key_account(accs.sender_vka)?;
    if sender_vka.state != VIEWING_KEY_STATE_ACTIVE {
        return Err(SquadsZoneError::ViewingKeyAccountBlocked.into());
    }

    // The smart-account SPP rail does not carry an owner signature inside the
    // proof, so its direct path must be authorized by the Squads vault itself.
    // `payer` is already a required signer and is forwarded as SPP's payer. When
    // this instruction is wrapped by the smart-account program, only the vault
    // PDA receives signer privilege after the configured threshold approves the
    // synchronous execution. A relayer/co-signer therefore cannot spend a smart
    // account by submitting `transact` directly.
    let owner_kind = sender_vka.kind()?;
    if owner_kind == OwnerKind::SmartAccount {
        verify_owner_identity(accs.payer, sender_vka.owner.to_bytes())?;
    }

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

    let now = Clock::get()?.unix_timestamp;
    if now > ix.expiry {
        return Err(SquadsZoneError::TransactionExpired.into());
    }

    let ring_auth_bump = verify_pda(accs.ring_auth.address(), &[RING_AUTH_PDA_SEED], &crate::ID)?;

    let public_amount = public_amount_fe(ix.public_amount);

    let encrypted_utxos = &ix.encrypted_utxos;
    let sender_ciphertext = encrypted_utxos.sender_ciphertext.as_slice();
    let recipient = zone_recipient(encrypted_utxos, recipient_vka.as_ref())?;

    let (n_inputs, n_outputs) = operation_shape(
        is_transfer,
        ix.input_contexts.len(),
        ix.output_utxo_hashes.len(),
    )?;

    // `proposal_hash` is 0 for sync `transact`. The owner's signature over
    // `private_tx_hash` already covers the outputs (spec Zone Proof table).
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

    let expiry_unix_ts =
        u64::try_from(ix.expiry).map_err(|_| SquadsZoneError::InvalidInstructionData)?;
    let rail = SppSettlementRail::for_owner_kind(owner_kind);
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
            [accs.payer, accs.tree, accs.ring_auth, accs.spp_program];
        return spp_transact(accs.spp_program, &cpi_accounts, &spp_data, ring_auth_bump);
    }

    let settlement = withdrawal_settlement(accs.settlement, ix.spl_interface_bump)?;
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
        settlement,
        rail,
    })?;
    forward_zone_withdrawal(
        accs.spp_program,
        accs.payer,
        accs.tree,
        accs.ring_auth,
        accs.settlement,
        &spp_data,
        ring_auth_bump,
    )
}
