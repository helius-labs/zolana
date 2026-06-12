use borsh::BorshSerialize;
use light_hasher::{Hasher, Poseidon};
use pinocchio::{
    cpi::invoke, error::ProgramError, instruction::InstructionView, AccountView, Address,
    ProgramResult,
};
use zolana_interface::instruction::{
    tag, ProoflessShieldIxData, ProoflessShieldEvent, TransactIxData, PUBLIC_AMOUNT_DEPOSIT,
};

use crate::instructions::{
    accounts::load_transact_accounts,
    hash::{field_from_u64, solana_pk_hash},
    settlement::{settle_public_amounts, spl_asset_pubkey},
};
use crate::{
    error::ShieldedPoolError,
    instructions::{create_tree::init::append_state_leaves as append_to_pool, loader},
    log::log,
};

/// Domain separator for UTXO commitments (mirrors protocol::UtxoDomain).
const UTXO_DOMAIN: u64 = 2;

/// Public deposit without a proof (spec: `proofless_shield`, tag 1).
///
/// The deposited amount is settled into the pool exactly like a transact
/// deposit, the recipient UTXO is hashed from the public fields plus the
/// settled amount/asset and appended to the UTXO tree, and a
/// `ProoflessShieldEvent` is emitted via `emit_event` self-CPI for the
/// indexer (the utxo hash and the mint address do not exist in the
/// instruction data). No proof: the amount is taken from the actual deposit
/// so a depositor cannot mint a UTXO worth more than they paid in.
///
/// Accounts: the transact settlement layout, then the shielded-pool program
/// account itself (callee of the self-CPI) last.
pub fn process_proofless_shield(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: ProoflessShieldIxData,
) -> ProgramResult {
    let sol = data.public_sol_amount.unwrap_or(0);
    let spl = data.public_spl_amount.unwrap_or(0);
    // Exactly one asset, non-zero: a single-asset public deposit.
    if (sol == 0) == (spl == 0) {
        return Err(ShieldedPoolError::InvalidTransactShape.into());
    }
    // Zone-bearing deposits require cpi_signer (spec check 3); the zone path
    // is not wired into this dispatcher, so reject both the signer and any
    // zone/program data outright.
    if data.cpi_signer.is_some()
        || data.policy_data_hash.is_some()
        || data.zone_data.is_some()
        || data.program_data_hash.is_some()
        || data.program_data.is_some()
    {
        return Err(ShieldedPoolError::InvalidTransactShape.into());
    }
    let needs_sol = sol != 0;
    let needs_spl = spl != 0;

    // The trailing account is the shielded-pool program itself, the callee of
    // the emit_event self-CPI.
    if accounts.len() < 2 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let (head, program_slice) = accounts.split_at_mut(accounts.len() - 1);
    if program_slice[0].address() != program_id {
        return Err(ShieldedPoolError::InvalidSettlementAccounts.into());
    }

    // A TransactIxData view of the deposit drives the shared account-loading and
    // settlement paths (mode = DEPOSIT, no proof / nullifiers / outputs).
    let tx = deposit_view(&data);
    let verified = load_transact_accounts(program_id, head, &tx, needs_sol, needs_spl)?;

    // Asset field and amount come from the actual deposit; the UTXO hash uses
    // the same encoding as the circuit so the deposit is spendable by a proof.
    // owner_utxo_hash = Poseidon(owner, blinding) is supplied opaquely, hiding
    // the recipient (the circuit never checks an output UTXO's owner).
    let (asset, asset_field, amount) = if needs_spl {
        let mint = spl_asset_pubkey(&verified.settlement)?;
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(mint.as_ref());
        (bytes, solana_pk_hash(&bytes)?, spl)
    } else {
        ([0u8; 32], solana_pk_hash(&[0u8; 32])?, sol)
    };

    let zero = [0u8; 32];
    let utxo_hash = Poseidon::hashv(&[
        field_from_u64(UTXO_DOMAIN).as_slice(),
        asset_field.as_slice(),
        field_from_u64(amount).as_slice(),
        zero.as_slice(),
        zero.as_slice(),
        zero.as_slice(),
        data.owner_utxo_hash.as_slice(),
    ])
    .map_err(|_| ShieldedPoolError::TransactProofVerificationFailed)?;

    settle_public_amounts(program_id, &verified.settlement, &tx)?;

    let bytes = loader::account_data_mut(verified.tree);
    if append_to_pool(bytes, &[utxo_hash]).is_err() {
        log("proofless_shield: state sub-tree append failed");
        return Err(ShieldedPoolError::StateAppendFailed.into());
    }

    let event = ProoflessShieldEvent {
        view_tag: data.view_tag,
        utxo_hash,
        asset,
        amount,
        zone_program_id: None,
        policy_data_hash: None,
        owner_utxo_hash: data.owner_utxo_hash,
        salt: data.salt,
        program_data_hash: None,
        program_data: None,
        zone_data: None,
    };
    emit_event(program_id, &event)
}

/// Self-CPI carrying the event bytes; the no-op `emit_event` handler accepts
/// them and indexers read them from the inner instruction.
fn emit_event(program_id: &Address, event: &ProoflessShieldEvent) -> ProgramResult {
    let mut data = vec![tag::EMIT_EVENT];
    event
        .serialize(&mut data)
        .map_err(|_| ProgramError::from(ShieldedPoolError::InvalidInstructionData))?;
    let instruction = InstructionView {
        program_id,
        accounts: &[],
        data: &data,
    };
    let no_accounts: &[&AccountView; 0] = &[];
    invoke(&instruction, no_accounts)
}

fn deposit_view(data: &ProoflessShieldIxData) -> TransactIxData {
    TransactIxData {
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
