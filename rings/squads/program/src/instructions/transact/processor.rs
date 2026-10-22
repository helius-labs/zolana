//! `transact` (tag 0): ring-proof-gated synchronous transfer/withdrawal settled
//! through the SPP in the same transaction.

use pinocchio::{AccountView, ProgramResult};
use zolana_squads_interface::{
    constants::VIEWING_KEY_STATE_ACTIVE, error::SquadsRingError,
    instruction::instruction_data::TransactIxData,
};

use super::account::TransactAccounts;
use crate::instructions::ring_config::loader::load_ring_config;
use crate::instructions::viewing_key_account::loader::load_viewing_key_account;
use crate::shared::{
    cpi::forward_to_spp,
    ring_proof::{ring_recipient, RingProof},
    spp_transact::{external_data_hash, forwarded_spp_data, SppSettlementRail, SppTransact},
};

/// `transact` (tag 0): ring-proof-gated synchronous transfer/withdrawal settled
/// through the SPP.
///
/// Accounts: `[payer (signer, writable), co_signer (signer), ring_config
/// (readonly), sender_vka (readonly), recipient_vka (readonly, transfer only),
/// ..spp_accounts]`.
///
/// The forwarded SPP payload selects the operation: a `(1, 1)` withdrawal with
/// one withdrawal leg (the single output is the sender's change, no
/// `recipient_vka`), or a `(2, 2)` transfer with no public leg (sender change
/// plus one recipient output). The ring proof is verified against the SPP
/// payload's `private_tx_hash`, ciphertexts and public amount, then the payload is
/// forwarded to SPP unchanged via the `ring_auth`-signed CPI.
#[inline(never)]
pub fn process_transact_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let ix = decode(data)?;
    let spp = SppTransact::parse(&ix.spp)?;

    let accs = TransactAccounts::validate_and_parse(accounts, spp.is_transfer())?;

    if !accs.payer.is_signer() {
        return Err(SquadsRingError::MissingAuthoritySignature.into());
    }
    if !accs.co_signer.is_signer() {
        return Err(SquadsRingError::MissingCoSignerSignature.into());
    }

    let ring_config = load_ring_config(accs.ring_config)?;
    if accs.co_signer.address() != &ring_config.co_signer {
        return Err(SquadsRingError::CoSignerMismatch.into());
    }

    // A blocked sender may only exit via full_withdrawal.
    let sender_vka = load_viewing_key_account(accs.sender_vka)?;
    if sender_vka.state != VIEWING_KEY_STATE_ACTIVE {
        return Err(SquadsRingError::ViewingKeyAccountBlocked.into());
    }
    let recipient_vka = match accs.recipient_vka {
        Some(recipient_vka_account) => {
            let recipient_vka = load_viewing_key_account(recipient_vka_account)?;
            if recipient_vka.state != VIEWING_KEY_STATE_ACTIVE {
                return Err(SquadsRingError::ViewingKeyAccountBlocked.into());
            }
            Some(recipient_vka)
        }
        None => None,
    };

    // A smart-account sender settles signatureless via ring_authority_transact;
    // a keypair/Ed25519 sender via the Ed25519 ring_transact rail.
    let rail = SppSettlementRail::for_owner_kind(sender_vka.owner_kind);
    rail.check_circuit(&ix.spp.circuit)?;

    let recipient = ring_recipient(
        &ix.spp.tx_viewing_pk,
        spp.recipient_ciphertext()?,
        recipient_vka.as_ref(),
    )?;
    let (n_inputs, n_outputs) = spp.shape();
    // `proposal_hash` is 0 for sync `transact`: the owner's authorization over
    // `private_tx_hash` already covers the outputs.
    RingProof {
        private_tx_hash: ix.spp.private_tx_hash,
        external_data_hash: external_data_hash(rail, data, accs.spp_accounts)?,
        public_amount: spp.public_amount_field(),
        sender_owner: sender_vka.owner.to_bytes(),
        sender_commitment: sender_vka.shared_viewing_key_commitment,
        sender_nullifier_pubkey: sender_vka.nullifier_pubkey,
        sender_ciphertext: spp.sender_ciphertext()?,
        recipient,
        proposal_hash: [0u8; 32],
        proof: &ix.ring_proof,
        n_inputs,
        n_outputs,
    }
    .verify()?;

    forward_to_spp(accs.spp_accounts, &forwarded_spp_data(rail, data)?)
}

#[inline(never)]
fn decode(data: &[u8]) -> Result<Box<TransactIxData>, SquadsRingError> {
    TransactIxData::deserialize(data)
        .map(Box::new)
        .map_err(|_| SquadsRingError::InvalidInstructionData)
}
