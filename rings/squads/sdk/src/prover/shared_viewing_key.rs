//! Host side of the squads key-encryption verifiable-encryption scheme.
//!
//! Thin wrappers over [`crate::crypto`] that map [`crate::crypto::CryptoError`] to
//! [`SquadsProverError`].
//!
//! See [`crate::crypto`] for the byte-for-byte circuit correspondence.

use p256::SecretKey;

use crate::{crypto, prover::error::SquadsProverError};

pub(crate) const NONCE_LEN: usize = crypto::NONCE_LEN;

pub(crate) use crypto::pack33;

pub(crate) fn ciphertext_hash(ciphertext: &[u8]) -> Result<[u8; 32], SquadsProverError> {
    Ok(crypto::ciphertext_hash(ciphertext)?)
}

pub(crate) fn hash_field(value: &[u8; 32]) -> Result<[u8; 32], SquadsProverError> {
    Ok(crypto::hash_field(value)?)
}

pub(crate) fn hash_chain(items: &[[u8; 32]]) -> Result<[u8; 32], SquadsProverError> {
    Ok(crypto::hash_chain(items)?)
}

pub(crate) fn ecdh_encrypt(
    dh: &[u8; 32],
    eph_pk_comp: &[u8; 33],
    recipient_pk_comp: &[u8; 33],
    plaintext: &[u8],
) -> Result<Vec<u8>, SquadsProverError> {
    Ok(crypto::ecdh_encrypt(
        dh,
        eph_pk_comp,
        recipient_pk_comp,
        plaintext,
    )?)
}

pub(crate) fn secret_key_from_be(scalar_be: &[u8; 32]) -> Result<SecretKey, SquadsProverError> {
    Ok(crypto::secret_key_from_be(scalar_be)?)
}

pub(crate) fn key_schedule_pub(
    shared_secret: &[u8; 32],
) -> Result<([u8; 32], [u8; NONCE_LEN]), SquadsProverError> {
    Ok(crypto::key_schedule(shared_secret)?)
}

pub(crate) fn derive_shared_secret_pub(
    dh: &[u8; 32],
    eph_comp: &[u8; 33],
    rpk_comp: &[u8; 33],
) -> Result<[u8; 32], SquadsProverError> {
    Ok(crypto::derive_shared_secret(dh, eph_comp, rpk_comp)?)
}

pub(crate) fn ctr_apply_pub(key: &[u8; 32], nonce: &[u8; NONCE_LEN], buf: &mut [u8]) {
    crypto::ctr_apply(key, nonce, buf)
}

/// The settlement transfer a ring withdrawal folds into its external data. SPP
/// recomputes the same value, so the rail selection and every address here must
/// match the accounts the ring forwards.
/// The public destination a ring withdrawal pays. The variant selects both the
/// settlement rail and the asset field the circuit's balance check binds, so the
/// addresses that mean nothing on the other rail cannot be supplied at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WithdrawalDestination {
    /// Native SOL leaves the pool to a system account.
    Sol {
        user_sol_account: zolana_transaction::Address,
    },
    /// An SPL asset leaves the pool to a token account through the pool's
    /// per-mint vault.
    Spl {
        user_spl_token: zolana_transaction::Address,
        spl_token_interface: zolana_transaction::Address,
    },
}

pub(crate) fn withdrawal_transfer(
    destination: WithdrawalDestination,
    amount: u64,
    mint: zolana_transaction::Address,
) -> zolana_transaction::instructions::transact::SettlementTransfer {
    use zolana_transaction::instructions::transact::SettlementTransfer;
    match destination {
        WithdrawalDestination::Sol { user_sol_account } => SettlementTransfer::Sol {
            is_deposit: false,
            amount,
            user_sol_account,
        },
        WithdrawalDestination::Spl {
            user_spl_token,
            spl_token_interface,
        } => SettlementTransfer::Spl {
            mint,
            is_deposit: false,
            amount,
            user_spl_token,
            spl_token_interface,
        },
    }
}

/// The public-transfer slots a ring withdrawal proves. One asset moves, so slot
/// zero carries it. The amount is negative because a withdrawal leaves the pool,
/// which the circuit's balance check binds.
pub(crate) fn withdrawal_public_transfers(
    destination: WithdrawalDestination,
    withdrawn: u64,
    asset_fe: [u8; 32],
) -> Result<zolana_client::PublicTransfers, SquadsProverError> {
    let mut transfers = zolana_client::PublicTransfers::default();
    let asset_slot = transfers
        .assets
        .first_mut()
        .ok_or(SquadsProverError::MissingSlot)?;
    *asset_slot = match destination {
        WithdrawalDestination::Sol { .. } => zolana_interface::SOL_ASSET_FIELD,
        WithdrawalDestination::Spl { .. } => asset_fe,
    };
    let amount_slot = transfers
        .amounts
        .first_mut()
        .ok_or(SquadsProverError::MissingSlot)?;
    *amount_slot =
        zolana_transaction::instructions::transact::signed_magnitude_to_field(false, withdrawn);
    Ok(transfers)
}
