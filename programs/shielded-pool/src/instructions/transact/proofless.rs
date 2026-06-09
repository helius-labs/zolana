use light_hasher::{Hasher, Poseidon};
use pinocchio::{AccountView, Address, ProgramResult};
use zolana_interface::instruction::{ProoflessShieldData, TransactData, PUBLIC_AMOUNT_DEPOSIT};

use super::proof::solana_pk_hash;
use super::settlement::{settle_public_amounts, spl_asset_pubkey};
use super::verify::load_transact_accounts;
use crate::{
    error::ShieldedPoolError,
    instructions::{
        create_pool_tree::init::append_state_leaves as append_to_pool, hash::field_from_u64,
    },
    log::log,
};

/// Domain separator for UTXO commitments (mirrors protocol::UtxoDomain).
const UTXO_DOMAIN: u64 = 2;

/// Public deposit without a proof (spec: `proofless_shield`, tag 1).
///
/// The deposited amount is settled into the pool exactly like a transact
/// deposit, the recipient UTXO is hashed from the public fields plus the settled
/// amount/asset, appended to the UTXO tree, and the recipient bootstrap view tag
/// is inserted into the queue for discovery. No proof: every field of the
/// commitment is public, and the amount is taken from the actual deposit so a
/// depositor cannot mint a UTXO worth more than they paid in.
pub fn process_proofless_shield(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: ProoflessShieldData,
) -> ProgramResult {
    let sol = data.public_sol_amount.unwrap_or(0);
    let spl = data.public_spl_amount.unwrap_or(0);
    // Exactly one asset, non-zero: a single-asset public deposit.
    if (sol == 0) == (spl == 0) {
        return Err(ShieldedPoolError::InvalidTransactShape.into());
    }
    // Default-zone deposit: only bare UTXOs. Program/zone-owned UTXOs require the
    // zone authorization path (spec: Program ownership), so reject program/policy
    // data and a zone program id here — matching the transact circuit.
    if data.data_hash != [0u8; 32]
        || data.zone_data_hash != [0u8; 32]
        || data.zone_program_id != [0u8; 32]
    {
        return Err(ShieldedPoolError::InvalidTransactShape.into());
    }
    let needs_sol = sol != 0;
    let needs_spl = spl != 0;

    // A TransactData view of the deposit drives the shared account-loading and
    // settlement paths (mode = DEPOSIT, no proof / nullifiers / outputs).
    let tx = deposit_view(&data);
    let verified = load_transact_accounts(program_id, accounts, &tx, needs_sol, needs_spl)?;

    // Asset field and amount come from the actual deposit; the UTXO hash uses
    // the same encoding as the circuit so the deposit is spendable by a proof.
    // owner_utxo_hash = Poseidon(owner, blinding) is supplied opaquely, hiding
    // the recipient (the circuit never checks an output UTXO's owner).
    let (asset, amount) = if needs_spl {
        let mint = spl_asset_pubkey(&verified.settlement)?;
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(mint.as_ref());
        (solana_pk_hash(&bytes)?, spl)
    } else {
        (solana_pk_hash(&[0u8; 32])?, sol)
    };

    let utxo_hash = Poseidon::hashv(&[
        field_from_u64(UTXO_DOMAIN).as_slice(),
        asset.as_slice(),
        field_from_u64(amount).as_slice(),
        data.data_hash.as_slice(),
        data.zone_data_hash.as_slice(),
        data.zone_program_id.as_slice(),
        data.owner_utxo_hash.as_slice(),
    ])
    .map_err(|_| ShieldedPoolError::TransactProofVerificationFailed)?;

    settle_public_amounts(program_id, &verified.settlement, &tx)?;

    // Do NOT insert bootstrap_view_tag into the nullifier queue. Only
    // sender_view_tag / merge_view_tag are single-use and belong in the
    // nullifier tree (spec "View tags"); bootstrap_view_tag is the recipient's
    // viewing_pk — constant per recipient and reused on every first-contact
    // deposit — so queueing it would make the bloom dedup reject the recipient's
    // second proofless shield forever. The indexer discovers proofless shields
    // by scanning instruction data (bootstrap_view_tag + cleartext_utxo), which
    // is the documented handling for reusable tags.
    //
    // SAFETY: `tree` is the writable account passed by the caller and is not
    // aliased with the settlement accounts borrowed above.
    let bytes = unsafe { verified.tree.borrow_unchecked_mut() };
    if append_to_pool(bytes, &[utxo_hash]).is_err() {
        log("proofless_shield: state sub-tree append failed");
        return Err(ShieldedPoolError::StateAppendFailed.into());
    }
    Ok(())
}

fn deposit_view(data: &ProoflessShieldData) -> TransactData {
    TransactData {
        expiry_unix_ts: 0,
        sender_view_tag: [0u8; 32],
        proof: [0u8; 192],
        relayer_fee: 0,
        public_amount_mode: PUBLIC_AMOUNT_DEPOSIT,
        nullifiers: Vec::new(),
        output_utxo_hashes: Vec::new(),
        utxo_tree_root_index: Vec::new(),
        nullifier_tree_root_index: Vec::new(),
        private_tx_hash: [0u8; 32],
        public_sol_amount: data.public_sol_amount,
        public_spl_amount: data.public_spl_amount,
        cpi_signer: None,
        in_utxo_signer_indices: None,
        encrypted_utxos: Vec::new(),
        // Proofless deposits verify no proof; the rail is irrelevant here (this
        // view only drives settlement account loading).
        requires_p256: false,
    }
}
