use borsh::BorshSerialize;
use light_hasher::{Hasher, Poseidon};
use pinocchio::{
    cpi::invoke, error::ProgramError, instruction::InstructionView, AccountView, Address,
    ProgramResult,
};
use zolana_interface::instruction::{
    tag, CpiSignerData, ProoflessShieldEvent, ProoflessShieldIxData, TransactIxData,
    ZoneProoflessShieldIxData, PUBLIC_AMOUNT_DEPOSIT,
};

use crate::instructions::{
    accounts::{load_transact_accounts, CPI_SIGNER_SEED, ZONE_AUTH_SEED},
    hash::{field_from_u64, solana_pk_hash},
    settlement::{settle_public_amounts, spl_asset_pubkey},
};
use crate::{
    error::ShieldedPoolError,
    instructions::{create_tree::init::append_state_leaves as append_to_pool, loader},
    log::log,
};

/// Domain separator for UTXO commitments (mirrors protocol::UtxoDomain).
const UTXO_DOMAIN: u64 = 1;

/// Resolved fields shared by `proofless_shield` and `zone_proofless_shield`.
/// The two differ only in the CPI-signer seed (general program vs policy zone)
/// and whether policy/zone data is carried.
struct Deposit {
    view_tag: [u8; 32],
    owner_utxo_hash: [u8; 32],
    salt: [u8; 16],
    public_sol_amount: Option<u64>,
    public_spl_amount: Option<u64>,
    cpi_signer: Option<CpiSignerData>,
    cpi_signer_seed: &'static [u8],
    /// UTXO `DataHash` slot.
    program_data_hash: Option<[u8; 32]>,
    program_data: Option<Vec<u8>>,
    /// UTXO `ZoneDataHash` slot; `None` (→ 0) for default-zone deposits.
    policy_data_hash: Option<[u8; 32]>,
    zone_data: Option<Vec<u8>>,
}

/// Public deposit without a proof (spec: `proofless_shield`, tag 1).
///
/// The deposited amount is settled into the pool exactly like a transact
/// deposit, the recipient UTXO is hashed from the public fields plus the
/// settled amount/asset and appended to the UTXO tree, and a
/// `ProoflessShieldEvent` is emitted via `emit_event` self-CPI for the
/// indexer. No proof: the amount is taken from the actual deposit so a
/// depositor cannot mint a UTXO worth more than they paid in. An optional
/// `cpi_signer` (general program owner, seed `auth`) makes the deposit
/// program-owned and may carry `program_data`.
pub fn process_proofless_shield(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: ProoflessShieldIxData,
) -> ProgramResult {
    // Program data only on a program-owned deposit (spec check 3).
    if (data.program_data_hash.is_some() || data.program_data.is_some())
        && data.cpi_signer.is_none()
    {
        return Err(ShieldedPoolError::InvalidTransactShape.into());
    }
    process_deposit(
        program_id,
        accounts,
        Deposit {
            view_tag: data.view_tag,
            owner_utxo_hash: data.owner_utxo_hash,
            salt: data.salt,
            public_sol_amount: data.public_sol_amount,
            public_spl_amount: data.public_spl_amount,
            cpi_signer: data.cpi_signer,
            cpi_signer_seed: CPI_SIGNER_SEED,
            program_data_hash: data.program_data_hash,
            program_data: data.program_data,
            policy_data_hash: None,
            zone_data: None,
        },
    )
}

/// Policy-zone analog (spec: `zone_proofless_shield`, tag 15). The calling
/// zone program signs with its `zone_auth` PDA (seed `zone_auth`); the UTXO is
/// owned by the zone and additionally carries the zone's `policy_data`.
pub fn process_zone_proofless_shield(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: ZoneProoflessShieldIxData,
) -> ProgramResult {
    process_deposit(
        program_id,
        accounts,
        Deposit {
            view_tag: data.view_tag,
            owner_utxo_hash: data.owner_utxo_hash,
            salt: data.salt,
            public_sol_amount: data.public_sol_amount,
            public_spl_amount: data.public_spl_amount,
            cpi_signer: Some(data.cpi_signer),
            cpi_signer_seed: ZONE_AUTH_SEED,
            program_data_hash: data.program_data_hash,
            program_data: data.program_data,
            policy_data_hash: data.policy_data_hash,
            zone_data: data.zone_data,
        },
    )
}

/// Settle the deposit, hash + append the recipient UTXO, and emit the event.
/// Accounts: the transact settlement layout (with the `cpi_signer` PDA at
/// index 2 when present), then the shielded-pool program account itself
/// (callee of the self-CPI) last.
fn process_deposit(
    program_id: &Address,
    accounts: &mut [AccountView],
    d: Deposit,
) -> ProgramResult {
    let sol = d.public_sol_amount.unwrap_or(0);
    let spl = d.public_spl_amount.unwrap_or(0);
    // Exactly one asset, non-zero: a single-asset public deposit.
    if (sol == 0) == (spl == 0) {
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

    // A TransactIxData view of the deposit drives the shared account-loading
    // and settlement paths (mode = DEPOSIT, no proof / nullifiers / outputs).
    // The cpi_signer seed selects the general-program vs policy-zone PDA.
    let tx = deposit_view(&d);
    let verified = load_transact_accounts(
        program_id,
        head,
        &tx,
        needs_sol,
        needs_spl,
        d.cpi_signer_seed,
    )?;

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
    let program_data_hash = d.program_data_hash.unwrap_or(zero);
    let policy_data_hash = d.policy_data_hash.unwrap_or(zero);
    // zone_program_id is pk_field-encoded before hashing (spec: UTXO Hash).
    let zone_program_id = match d.cpi_signer {
        Some(cpi) => solana_pk_hash(&cpi.program_id)?,
        None => zero,
    };
    let utxo_hash = Poseidon::hashv(&[
        field_from_u64(UTXO_DOMAIN).as_slice(),
        asset_field.as_slice(),
        field_from_u64(amount).as_slice(),
        program_data_hash.as_slice(),
        policy_data_hash.as_slice(),
        zone_program_id.as_slice(),
        d.owner_utxo_hash.as_slice(),
    ])
    .map_err(|_| ShieldedPoolError::TransactProofVerificationFailed)?;

    settle_public_amounts(program_id, &verified.settlement, &tx)?;

    let bytes = loader::account_data_mut(verified.tree);
    if append_to_pool(bytes, &[utxo_hash]).is_err() {
        log("proofless_shield: state sub-tree append failed");
        return Err(ShieldedPoolError::StateAppendFailed.into());
    }

    let event = ProoflessShieldEvent {
        view_tag: d.view_tag,
        utxo_hash,
        asset,
        amount,
        // Raw program id; the indexer pk_field-encodes it to recompute the hash.
        zone_program_id: d.cpi_signer.map(|cpi| cpi.program_id),
        policy_data_hash: d.policy_data_hash,
        owner_utxo_hash: d.owner_utxo_hash,
        salt: d.salt,
        program_data_hash: d.program_data_hash,
        program_data: d.program_data,
        zone_data: d.zone_data,
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

fn deposit_view(d: &Deposit) -> TransactIxData {
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
        public_sol_amount: d.public_sol_amount,
        public_spl_amount: d.public_spl_amount,
        // Drives the cpi_signer PDA check (seed per d.cpi_signer_seed) and
        // reserves account index 2 for the signer in the settlement layout.
        cpi_signer: d.cpi_signer,
        in_utxo_signer_indices: None,
        encrypted_utxos: Vec::new(),
        // Proofless deposits verify no proof; the rail is irrelevant here (this
        // view only drives settlement account loading).
        requires_p256: false,
    }
}
